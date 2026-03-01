/*
 * WiFi Cyber Attack Monitor — ESP8266 Sensor Node v2
 * ====================================================
 * Fungsi utama:
 *   - Scan jaringan WiFi di sekitar (SSID, RSSI, channel, enkripsi)
 *   - Deteksi deauth frame via promiscuous mode
 *   - Kirim laporan ke server Flask via HTTP POST (/api/esp/report)
 *   - Web server mini di ESP untuk terima perintah dari dashboard:
 *       GET  /status   → status koneksi ESP saat ini
 *       GET  /scan     → scan WiFi sekitar, kirim hasil JSON
 *       POST /connect  → konek ke WiFi baru (body: ssid=...&password=...)
 *
 * Board: NodeMCU v1/v2/v3, Wemos D1 Mini
 * Library: ESP8266WiFi, ESP8266HTTPClient, ESP8266WebServer, ArduinoJson
 */

#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <ESP8266WebServer.h>
#include <WiFiClient.h>
#include <ArduinoJson.h>

// ─── Konfigurasi — WAJIB diubah ──────────────────────────────────────────────
const char* WIFI_SSID     = "NamaWiFiKamu";
const char* WIFI_PASSWORD = "PasswordWiFiKamu";
const char* SERVER_IP     = "192.168.100.66";  // IP laptop yang jalanin Flask
const int   SERVER_PORT   = 9001;
const char* ESP_ID        = "esp-sensor-01";
const int   ESP_WEB_PORT  = 80;                // Port web server di ESP

// ─── Interval ─────────────────────────────────────────────────────────────────
const unsigned long REPORT_INTERVAL = 10000;   // Kirim laporan tiap 10 detik
const unsigned long SCAN_INTERVAL   = 30000;   // Scan WiFi sekitar tiap 30 detik

// ─── Threshold ────────────────────────────────────────────────────────────────
const int DEAUTH_THRESHOLD = 5;

// ─── Web server di ESP ────────────────────────────────────────────────────────
ESP8266WebServer webServer(ESP_WEB_PORT);

// ─── State ────────────────────────────────────────────────────────────────────
unsigned long lastReport = 0;
unsigned long lastScan   = 0;
unsigned long bootTime   = 0;

struct DeauthEvent {
  char src_mac[18];
  int  count;
  int  channel;
};
DeauthEvent deauthEvents[10];
int deauthCount = 0;

struct WifiNetwork {
  char ssid[33];
  int  rssi;
  int  channel;
  char encryption[10];
  bool open;
};
WifiNetwork wifiNetworks[20];
int wifiNetworkCount = 0;

// Flag: sedang dalam proses ganti WiFi
bool connectingToNew = false;
char pendingSsid[33]     = "";
char pendingPassword[65] = "";


// ─── Promiscuous callback ─────────────────────────────────────────────────────
struct RxControl {
  signed   rssi:8;
  unsigned rate:4;
  unsigned is_group:1;
  unsigned:1;
  unsigned sig_mode:2;
  unsigned legacy_length:12;
  unsigned damatch0:1;
  unsigned damatch1:1;
  unsigned bssidmatch0:1;
  unsigned bssidmatch1:1;
  unsigned MCS:7;
  unsigned CWB:1;
  unsigned HT_length:16;
  unsigned Smoothing:1;
  unsigned Not_Sounding:1;
  unsigned:1;
  unsigned Aggregation:1;
  unsigned STBC:2;
  unsigned FEC_CODING:1;
  unsigned SGI:1;
  unsigned rxend_state:8;
  unsigned ampdu_cnt:8;
  unsigned channel:4;
  unsigned:12;
};

struct SnifferPacket {
  struct RxControl rx_ctrl;
  uint8_t  data[112];
  uint16_t cnt;
  uint16_t len;
};

void ICACHE_RAM_ATTR promisc_callback(uint8_t *buf, uint16_t len) {
  if (len < 28) return;
  struct SnifferPacket *pkt = (struct SnifferPacket*) buf;
  uint8_t ft  = (pkt->data[0] & 0x0C) >> 2;
  uint8_t fst = (pkt->data[0] & 0xF0) >> 4;

  if (ft == 0x00 && (fst == 0x0C || fst == 0x0A)) {
    char src[18];
    snprintf(src, sizeof(src), "%02x:%02x:%02x:%02x:%02x:%02x",
      pkt->data[10], pkt->data[11], pkt->data[12],
      pkt->data[13], pkt->data[14], pkt->data[15]);

    bool found = false;
    for (int i = 0; i < deauthCount; i++) {
      if (strcmp(deauthEvents[i].src_mac, src) == 0) {
        deauthEvents[i].count++;
        found = true;
        break;
      }
    }
    if (!found && deauthCount < 10) {
      strncpy(deauthEvents[deauthCount].src_mac, src, 17);
      deauthEvents[deauthCount].src_mac[17] = '\0';
      deauthEvents[deauthCount].count   = 1;
      deauthEvents[deauthCount].channel = pkt->rx_ctrl.channel;
      deauthCount++;
    }
  }
}


// ─── Web Server Handlers ──────────────────────────────────────────────────────

/*
 * GET /status
 * Kembalikan status ESP saat ini dalam JSON.
 * Dipakai dashboard untuk cek apakah ESP masih hidup dan terhubung ke WiFi mana.
 */
void handleStatus() {
  StaticJsonDocument<256> doc;
  doc["esp_id"]   = ESP_ID;
  doc["status"]   = (WiFi.status() == WL_CONNECTED) ? "connected" : "disconnected";
  doc["ssid"]     = WiFi.SSID();
  doc["ip"]       = WiFi.localIP().toString();
  doc["rssi"]     = WiFi.RSSI();
  doc["uptime"]   = (millis() - bootTime) / 1000;
  doc["firmware"] = "2.0.0";

  String out;
  serializeJson(doc, out);
  webServer.sendHeader("Access-Control-Allow-Origin", "*");
  webServer.send(200, "application/json", out);
}

/*
 * GET /scan
 * Scan semua WiFi di sekitar ESP dan kembalikan hasilnya sebagai JSON array.
 * Dashboard akan tampilkan daftar ini agar user bisa pilih mana yang mau dikonek.
 */
void handleScan() {
  Serial.println("[WebServer] Scan request diterima, scanning...");

  int found = WiFi.scanNetworks(false, true);
  wifiNetworkCount = 0;

  StaticJsonDocument<2048> doc;
  JsonArray networks = doc.createNestedArray("networks");

  if (found > 0) {
    int limit = min(found, 20);
    for (int i = 0; i < limit; i++) {
      JsonObject net = networks.createNestedObject();
      net["ssid"]    = WiFi.SSID(i);
      net["rssi"]    = WiFi.RSSI(i);
      net["channel"] = WiFi.channel(i);
      net["open"]    = (WiFi.encryptionType(i) == ENC_TYPE_NONE);

      String enc;
      switch (WiFi.encryptionType(i)) {
        case ENC_TYPE_WEP:  enc = "WEP";  break;
        case ENC_TYPE_TKIP: enc = "WPA";  break;
        case ENC_TYPE_CCMP: enc = "WPA2"; break;
        case ENC_TYPE_NONE: enc = "OPEN"; break;
        default:            enc = "AUTO"; break;
      }
      net["encryption"] = enc;

      // Simpan juga ke array lokal untuk laporan berikutnya
      if (wifiNetworkCount < 20) {
        strncpy(wifiNetworks[wifiNetworkCount].ssid, WiFi.SSID(i).c_str(), 32);
        wifiNetworks[wifiNetworkCount].rssi    = WiFi.RSSI(i);
        wifiNetworks[wifiNetworkCount].channel = WiFi.channel(i);
        strncpy(wifiNetworks[wifiNetworkCount].encryption, enc.c_str(), 9);
        wifiNetworks[wifiNetworkCount].open    = (WiFi.encryptionType(i) == ENC_TYPE_NONE);
        wifiNetworkCount++;
      }
    }
    WiFi.scanDelete();
  }

  doc["count"]  = networks.size();
  doc["esp_id"] = ESP_ID;

  String out;
  serializeJson(doc, out);
  webServer.sendHeader("Access-Control-Allow-Origin", "*");
  webServer.send(200, "application/json", out);

  Serial.printf("[WebServer] Scan selesai: %d jaringan\n", networks.size());
}

/*
 * POST /connect
 * Terima SSID dan password dari dashboard, lalu konek ke WiFi tersebut.
 * Body: ssid=NamaWiFi&password=PasswordWiFi
 *
 * ESP akan:
 * 1. Putus dari WiFi lama
 * 2. Konek ke WiFi baru
 * 3. Kirim laporan ke server Flask dengan status koneksi baru
 */
void handleConnect() {
  if (!webServer.hasArg("ssid")) {
    webServer.send(400, "application/json", "{\"error\":\"ssid required\"}");
    return;
  }

  String ssid     = webServer.arg("ssid");
  String password = webServer.arg("password");

  Serial.printf("[WebServer] Connect request: SSID=%s\n", ssid.c_str());

  // Simpan ke pending — koneksi dilakukan di loop() agar tidak blocking handler
  strncpy(pendingSsid,     ssid.c_str(),     32);
  strncpy(pendingPassword, password.c_str(), 64);
  connectingToNew = true;

  StaticJsonDocument<128> doc;
  doc["status"]  = "connecting";
  doc["ssid"]    = ssid;
  doc["message"] = "ESP sedang mencoba konek, cek status dalam 10 detik";

  String out;
  serializeJson(doc, out);
  webServer.sendHeader("Access-Control-Allow-Origin", "*");
  webServer.send(200, "application/json", out);
}

// Handle CORS preflight untuk request dari browser
void handleOptions() {
  webServer.sendHeader("Access-Control-Allow-Origin", "*");
  webServer.sendHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  webServer.sendHeader("Access-Control-Allow-Headers", "Content-Type");
  webServer.send(204);
}


// ─── Setup ────────────────────────────────────────────────────────────────────
void setup() {
  Serial.begin(115200);
  delay(100);

  Serial.println("\n\n=== WiFi Monitor ESP8266 Sensor v2 ===");
  Serial.printf("ESP ID   : %s\n", ESP_ID);
  Serial.printf("Server   : %s:%d\n", SERVER_IP, SERVER_PORT);

  bootTime = millis();

  connectWiFi(WIFI_SSID, WIFI_PASSWORD);

  // Daftarkan endpoint web server
  webServer.on("/status",  HTTP_GET,     handleStatus);
  webServer.on("/scan",    HTTP_GET,     handleScan);
  webServer.on("/connect", HTTP_POST,    handleConnect);
  webServer.on("/connect", HTTP_OPTIONS, handleOptions);
  webServer.on("/scan",    HTTP_OPTIONS, handleOptions);
  webServer.begin();

  Serial.printf("[WebServer] Jalan di http://%s:%d\n",
    WiFi.localIP().toString().c_str(), ESP_WEB_PORT);
  Serial.println("[ESP] Sensor siap!");
}


// ─── Loop ─────────────────────────────────────────────────────────────────────
void loop() {
  // Tangani request web server
  webServer.handleClient();

  unsigned long now = millis();

  // Proses koneksi WiFi baru kalau ada pending request
  if (connectingToNew) {
    connectingToNew = false;
    Serial.printf("[WiFi] Ganti ke SSID: %s\n", pendingSsid);
    connectWiFi(pendingSsid, pendingPassword);

    // Update SERVER_IP kalau perlu — kirim laporan dengan status baru
    sendReport();
    return;
  }

  // Reconnect kalau putus
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("[WiFi] Putus, reconnecting...");
    connectWiFi(WIFI_SSID, WIFI_PASSWORD);
    return;
  }

  // Scan WiFi sekitar secara berkala
  if (now - lastScan >= SCAN_INTERVAL) {
    scanWifiNetworks();
    lastScan = now;
  }

  // Tangkap deauth frame sebentar
  captureDeauthFrames(1500);

  // Kirim laporan ke server
  if (now - lastReport >= REPORT_INTERVAL) {
    sendReport();
    lastReport = now;
  }

  delay(50);
}


// ─── Fungsi koneksi WiFi ──────────────────────────────────────────────────────
void connectWiFi(const char* ssid, const char* pass) {
  Serial.printf("[WiFi] Connecting to: %s\n", ssid);

  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, pass);

  int tries = 0;
  while (WiFi.status() != WL_CONNECTED && tries < 20) {
    delay(500);
    Serial.print(".");
    tries++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("\n[WiFi] Connected! IP: %s | RSSI: %d dBm\n",
      WiFi.localIP().toString().c_str(), WiFi.RSSI());
  } else {
    Serial.println("\n[WiFi] Gagal connect.");
  }
}


// ─── Scan WiFi sekitar ────────────────────────────────────────────────────────
void scanWifiNetworks() {
  int found = WiFi.scanNetworks(false, true);
  wifiNetworkCount = 0;

  if (found <= 0) return;

  int limit = min(found, 20);
  for (int i = 0; i < limit; i++) {
    strncpy(wifiNetworks[i].ssid, WiFi.SSID(i).c_str(), 32);
    wifiNetworks[i].ssid[32]  = '\0';
    wifiNetworks[i].rssi      = WiFi.RSSI(i);
    wifiNetworks[i].channel   = WiFi.channel(i);
    wifiNetworks[i].open      = (WiFi.encryptionType(i) == ENC_TYPE_NONE);

    switch (WiFi.encryptionType(i)) {
      case ENC_TYPE_WEP:  strncpy(wifiNetworks[i].encryption, "WEP",  9); break;
      case ENC_TYPE_TKIP: strncpy(wifiNetworks[i].encryption, "WPA",  9); break;
      case ENC_TYPE_CCMP: strncpy(wifiNetworks[i].encryption, "WPA2", 9); break;
      case ENC_TYPE_NONE: strncpy(wifiNetworks[i].encryption, "OPEN", 9); break;
      default:            strncpy(wifiNetworks[i].encryption, "AUTO", 9); break;
    }
    wifiNetworks[i].encryption[9] = '\0';
    wifiNetworkCount++;
  }

  WiFi.scanDelete();
  Serial.printf("[Scan] %d jaringan ditemukan\n", wifiNetworkCount);
}


// ─── Tangkap deauth frame ─────────────────────────────────────────────────────
void captureDeauthFrames(unsigned long ms) {
  WiFi.disconnect();
  delay(30);

  wifi_set_opmode(STATION_MODE);
  wifi_promiscuous_enable(0);
  wifi_set_promiscuous_rx_cb(promisc_callback);
  wifi_promiscuous_enable(1);

  for (int ch = 1; ch <= 13; ch++) {
    wifi_set_channel(ch);
    delay(ms / 13);
  }

  wifi_promiscuous_enable(0);
  delay(30);
  connectWiFi(WiFi.SSID().c_str(), WiFi.psk().c_str());
}


// ─── Kirim laporan ke Flask ───────────────────────────────────────────────────
void sendReport() {
  if (WiFi.status() != WL_CONNECTED) return;

  StaticJsonDocument<2048> doc;
  doc["esp_id"]        = ESP_ID;
  doc["firmware"]      = "2.0.0";
  doc["uptime"]        = (millis() - bootTime) / 1000;
  doc["rssi"]          = WiFi.RSSI();
  doc["connected_ssid"] = WiFi.SSID();
  doc["esp_ip"]        = WiFi.localIP().toString();
  doc["esp_web_port"]  = ESP_WEB_PORT;

  // Deauth events
  JsonArray deauthArr = doc.createNestedArray("deauth_events");
  for (int i = 0; i < deauthCount; i++) {
    if (deauthEvents[i].count >= DEAUTH_THRESHOLD) {
      JsonObject ev = deauthArr.createNestedObject();
      ev["src_mac"] = deauthEvents[i].src_mac;
      ev["count"]   = deauthEvents[i].count;
      ev["channel"] = deauthEvents[i].channel;
    }
  }

  // WiFi scan results
  JsonArray scanArr = doc.createNestedArray("wifi_scan");
  for (int i = 0; i < wifiNetworkCount; i++) {
    JsonObject net = scanArr.createNestedObject();
    net["ssid"]       = wifiNetworks[i].ssid;
    net["rssi"]       = wifiNetworks[i].rssi;
    net["channel"]    = wifiNetworks[i].channel;
    net["encryption"] = wifiNetworks[i].encryption;
    net["open"]       = wifiNetworks[i].open;
  }

  String payload;
  serializeJson(doc, payload);

  String url = "http://" + String(SERVER_IP) + ":" + String(SERVER_PORT) + "/api/esp/report";

  WiFiClient client;
  HTTPClient http;
  http.begin(client, url);
  http.addHeader("Content-Type", "application/json");
  http.setTimeout(5000);

  int code = http.POST(payload);
  if (code == 200) {
    Serial.printf("[HTTP] Laporan OK | deauth=%d scan=%d\n",
      deauthArr.size(), scanArr.size());
  } else {
    Serial.printf("[HTTP] Gagal: %d\n", code);
  }

  http.end();
  deauthCount = 0;
}
