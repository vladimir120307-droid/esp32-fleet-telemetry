#pragma once

// Root certificate of the ingest server. Replace with the real CA before building for production.
// Keep a second CA in the list ahead of any rotation, or units in the field stop uploading.
static const char SERVER_CA_PEM[] = R"PEM(-----BEGIN CERTIFICATE-----
REPLACE_WITH_YOUR_ROOT_CA
-----END CERTIFICATE-----
)PEM";
