// Telemetry node: buffers readings in flash, uploads signed batches over TLS, survives outages.
//
// Readings live in a fixed-size ring file, so power loss or a long WiFi outage loses nothing
// until the ring is full. A reading leaves the ring only after the server's ack passes it.
// Credentials are stored in NVS. Enable flash encryption and secure boot for production units.

#include <Arduino.h>
#include <HTTPClient.h>
#include <LittleFS.h>
#include <Preferences.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <esp_task_wdt.h>
#include <mbedtls/md.h>
#include <time.h>

#include "server_ca.h"

static const char *FW_VERSION = "1.4.2";
static const char *RING_PATH = "/ring.bin";
static const uint32_t RING_SLOTS = 8192;
static const uint32_t SAMPLE_PERIOD_MS = 60000;
static const uint32_t UPLOAD_PERIOD_MS = 300000;
static const size_t BATCH_MAX = 20;
static const uint32_t WDT_TIMEOUT_S = 60;
static const time_t MIN_VALID_EPOCH = 1577836800;  // clock is not synced before this

struct __attribute__((packed)) Record {
  uint32_t seq;
  uint32_t ts;
  float tempC;
  int8_t rssi;
  uint8_t crc;
};

struct Config {
  String ssid, pass, deviceId, secret, url;
  bool valid() const { return ssid.length() && deviceId.length() && secret.length() && url.startsWith("https://"); }
};

static Preferences prefs;
static Config cfg;
static uint32_t nextSeq = 0;     // sequence for the next new reading, survives reboots
static uint32_t ackedSeq = 0;    // every seq below this value is confirmed by the server
static uint32_t lastSample = 0, lastUpload = 0;
static bool uploadDue = true;

static uint8_t crc8(const uint8_t *data, size_t len) {
  uint8_t crc = 0;
  while (len--) {
    crc ^= *data++;
    for (int i = 0; i < 8; i++) crc = (crc & 0x80) ? (crc << 1) ^ 0x07 : crc << 1;
  }
  return crc;
}

static void loadConfig() {
  prefs.begin("cfg", true);
  cfg.ssid = prefs.getString("ssid", "");
  cfg.pass = prefs.getString("pass", "");
  cfg.deviceId = prefs.getString("id", "");
  cfg.secret = prefs.getString("secret", "");
  cfg.url = prefs.getString("url", "");
  prefs.end();
}

static void loadCounters() {
  prefs.begin("state", true);
  nextSeq = prefs.getUInt("next", 0);
  ackedSeq = prefs.getUInt("acked", 0);
  prefs.end();
}

static void saveCounter(const char *key, uint32_t value) {
  prefs.begin("state", false);
  prefs.putUInt(key, value);
  prefs.end();
}

static bool ringOpen() {
  if (LittleFS.exists(RING_PATH)) return true;
  File f = LittleFS.open(RING_PATH, "w");
  if (!f) return false;
  Record blank = {};
  for (uint32_t i = 0; i < RING_SLOTS; i++) f.write(reinterpret_cast<uint8_t *>(&blank), sizeof(blank));
  f.close();
  return true;
}

static bool ringWrite(const Record &rec) {
  File f = LittleFS.open(RING_PATH, "r+");
  if (!f) return false;
  f.seek((rec.seq % RING_SLOTS) * sizeof(Record));
  size_t written = f.write(reinterpret_cast<const uint8_t *>(&rec), sizeof(rec));
  f.close();
  return written == sizeof(rec);
}

static bool ringRead(uint32_t seq, Record &rec) {
  File f = LittleFS.open(RING_PATH, "r");
  if (!f) return false;
  f.seek((seq % RING_SLOTS) * sizeof(Record));
  size_t got = f.read(reinterpret_cast<uint8_t *>(&rec), sizeof(rec));
  f.close();
  if (got != sizeof(rec) || rec.seq != seq) return false;
  return crc8(reinterpret_cast<const uint8_t *>(&rec), offsetof(Record, crc)) == rec.crc;
}

static void takeSample() {
  time_t now = time(nullptr);
  if (now < MIN_VALID_EPOCH) return;  // a reading with a wrong timestamp is worse than none
  Record rec = {};
  rec.seq = nextSeq;
  rec.ts = static_cast<uint32_t>(now);
  rec.tempC = temperatureRead();
  rec.rssi = WiFi.status() == WL_CONNECTED ? static_cast<int8_t>(WiFi.RSSI()) : -120;
  rec.crc = crc8(reinterpret_cast<const uint8_t *>(&rec), offsetof(Record, crc));
  if (!ringWrite(rec)) return;
  nextSeq++;
  saveCounter("next", nextSeq);
  // When the ring is full the oldest unsent readings are overwritten, so stop waiting for them.
  if (nextSeq - ackedSeq > RING_SLOTS) {
    ackedSeq = nextSeq - RING_SLOTS;
    saveCounter("acked", ackedSeq);
  }
}

static String hmacHex(const String &key, const String &message) {
  uint8_t digest[32];
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_hmac(info, reinterpret_cast<const uint8_t *>(key.c_str()), key.length(),
                  reinterpret_cast<const uint8_t *>(message.c_str()), message.length(), digest);
  char hex[65];
  for (int i = 0; i < 32; i++) sprintf(hex + i * 2, "%02x", digest[i]);
  hex[64] = 0;
  return String(hex);
}

static String sha256Hex(const String &data) {
  uint8_t digest[32];
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md(info, reinterpret_cast<const uint8_t *>(data.c_str()), data.length(), digest);
  char hex[65];
  for (int i = 0; i < 32; i++) sprintf(hex + i * 2, "%02x", digest[i]);
  hex[64] = 0;
  return String(hex);
}

static String buildBatch(size_t &count) {
  String body;
  body.reserve(96 * BATCH_MAX);
  body += "{\"firmware\":\"";
  body += FW_VERSION;
  body += "\",\"readings\":[";
  count = 0;
  for (uint32_t seq = ackedSeq; seq < nextSeq && count < BATCH_MAX; seq++) {
    Record rec;
    if (!ringRead(seq, rec)) continue;  // a damaged slot must not block everything after it
    if (count) body += ',';
    body += "{\"seq\":" + String(rec.seq) + ",\"ts\":" + String(rec.ts) + ",\"temp_c\":" + String(rec.tempC, 2) +
            ",\"rssi\":" + String(rec.rssi) + "}";
    count++;
  }
  body += "]}";
  return body;
}

// Returns the ack sequence from {"accepted":n,"duplicates":n,"ack_seq":n}, or -1 if not present.
static long parseAck(const String &response) {
  int at = response.indexOf("\"ack_seq\":");
  return at < 0 ? -1 : response.substring(at + 10).toInt();
}

static bool uploadBatch() {
  size_t count = 0;
  String body = buildBatch(count);
  if (!count) return true;

  WiFiClientSecure tls;
  tls.setCACert(SERVER_CA_PEM);  // an untrusted certificate stops the upload, the data stays in flash
  HTTPClient http;
  if (!http.begin(tls, cfg.url)) return false;
  http.setTimeout(15000);

  String timestamp = String(static_cast<uint32_t>(time(nullptr)));
  String signature = hmacHex(cfg.secret, cfg.deviceId + "." + timestamp + "." + sha256Hex(body));
  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-Device-Id", cfg.deviceId);
  http.addHeader("X-Timestamp", timestamp);
  http.addHeader("X-Signature", signature);

  int status = http.POST(body);
  bool ok = false;
  if (status == 200) {
    long ack = parseAck(http.getString());
    if (ack >= 0 && static_cast<uint32_t>(ack) + 1 > ackedSeq) {
      ackedSeq = static_cast<uint32_t>(ack) + 1;
      saveCounter("acked", ackedSeq);
      ok = true;
    }
  } else if (status == 403) {
    Serial.println("Device revoked by the server. Holding data.");
  } else {
    Serial.printf("Upload failed: %d\n", status);
  }
  http.end();
  return ok;
}

static void handleProvisioning() {
  // Factory line, sent over USB: PROV <ssid> <pass> <device-id> <secret> <https-url>
  if (!Serial.available()) return;
  String line = Serial.readStringUntil('\n');
  line.trim();
  if (!line.startsWith("PROV ")) return;
  String part[5];
  int from = 5;
  for (int i = 0; i < 5; i++) {
    int to = i < 4 ? line.indexOf(' ', from) : line.length();
    if (to < 0) {
      Serial.println("PROV expects 5 values");
      return;
    }
    part[i] = line.substring(from, to);
    from = to + 1;
  }
  prefs.begin("cfg", false);
  prefs.putString("ssid", part[0]);
  prefs.putString("pass", part[1]);
  prefs.putString("id", part[2]);
  prefs.putString("secret", part[3]);
  prefs.putString("url", part[4]);
  prefs.end();
  Serial.println("Stored. Rebooting.");
  delay(200);
  ESP.restart();
}

static void initWatchdog() {
#if defined(ESP_ARDUINO_VERSION_MAJOR) && ESP_ARDUINO_VERSION_MAJOR >= 3
  esp_task_wdt_config_t wdt = {};
  wdt.timeout_ms = WDT_TIMEOUT_S * 1000;
  wdt.trigger_panic = true;
  esp_task_wdt_reconfigure(&wdt);
#else
  esp_task_wdt_init(WDT_TIMEOUT_S, true);
#endif
  esp_task_wdt_add(nullptr);
}

void setup() {
  Serial.begin(115200);
  Serial.setTimeout(200);
  initWatchdog();
  if (!LittleFS.begin(true) || !ringOpen()) {
    Serial.println("Flash storage failed");
  }
  loadConfig();
  loadCounters();
  if (!cfg.valid()) {
    Serial.println("Not provisioned. Waiting for a PROV line.");
    return;
  }
  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(true);
  WiFi.begin(cfg.ssid.c_str(), cfg.pass.c_str());
  configTime(0, 0, "pool.ntp.org", "time.google.com");
}

void loop() {
  esp_task_wdt_reset();
  handleProvisioning();
  if (!cfg.valid()) {
    delay(100);
    return;
  }

  uint32_t now = millis();
  if (now - lastSample >= SAMPLE_PERIOD_MS || lastSample == 0) {
    lastSample = now == 0 ? 1 : now;
    takeSample();
  }
  if (now - lastUpload >= UPLOAD_PERIOD_MS) {
    lastUpload = now;
    uploadDue = true;
  }
  if (uploadDue && WiFi.status() == WL_CONNECTED && time(nullptr) >= MIN_VALID_EPOCH) {
    // Keep going until the backlog is gone, so a long outage clears quickly once WiFi is back.
    bool sent = uploadBatch();
    esp_task_wdt_reset();
    uploadDue = sent && ackedSeq < nextSeq;
  }
  delay(50);
}
