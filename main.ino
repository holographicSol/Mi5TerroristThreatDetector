/*
    Terrorism Threat Levels System - Written By Benjamin Jack Cullen.


    There are 5 categories at which the threat levels could be set: 


        LOW - an attack is highly unlikely
        MODERATE - an attack is possible, but not likely
        SUBSTANTIAL - an attack is likely
        SEVERE - an attack is highly likely
        CRITICAL - an attack is highly likely in the near future


    Members of the public should always remain alert to the danger of terrorism and report any suspicious activity to the police on 999 or the anti-terrorist hotline: 0800 789 321.
    If your information does not relate to an imminent threat, you can also contact Mi5: https://www.mi5.gov.uk/contact-us

*/


#include <Arduino.h>
#include <WiFi.h>
#include <WiFiMulti.h>
#include <HTTPClient.h>

#include <Wire.h>
#include <U8g2lib.h>

WiFiMulti WiFiMulti;
HTTPClient http;

// 128×64 SSD1309 I²C; 0x3C (or 0x3D) on hardware I²C
U8G2_SSD1309_128X64_NONAME2_F_HW_I2C u8g2(U8G2_R0, /* reset=*/ U8X8_PIN_NONE);

char *WIFI_SSID = "your_ssid";
char *WIFI_PASS = "your_password";

char *threat_level_url = "https://www.mi5.gov.uk/UKThreatLevel/UKThreatLevel.xml";
int   threat_level_int     = 0;
String threat_level_str    = "pending";
String threat_level_desc   = "pending";

int   http_code_int = -1;
String http_code_str = "Unknown";

static void drawHeader() {
    u8g2.setFont(u8g2_font_7x13B_tr);
    u8g2.setDrawColor(1);
    u8g2.drawBox(0, 0, 128, 15);
    u8g2.setDrawColor(0);
    u8g2.drawStr(4, 12, "Mi5 THREAT LEVEL");
    u8g2.setDrawColor(1);
}

void updateOLED(int http_code,
                const String& http_desc,
                const String& level_str,
                int level_int,
                const String& level_desc) {
  u8g2.firstPage();
  do {
    u8g2.setDrawColor(1);

    // Header
    drawHeader();

    // Level
    u8g2.setFont(u8g2_font_5x8_tf);
    String line1 = "LEVEL: " + level_str + " (" + String(level_int) + "/5)";
    u8g2.drawStr(0, 40, String(line1).c_str());

    // HTTP Code
    u8g2.setFont(u8g2_font_5x8_tf);
    String line0 = "HTTP: " + String(http_code) + " (" + http_desc + ")";
    u8g2.drawStr(0, 64, String(line0).c_str());

  } while (u8g2.nextPage());
}

void setup() {
  Serial.begin(115200);
  delay(3000);

  // Initialize OLED (U8g2)
  Wire.begin(7, 8);  // SDA=GPIO7, SCL=GPIO8 FOR ESP32-P4-WiFi6-M Waveshare
  u8g2.begin();
  u8g2.setFont(u8g2_font_5x8_tf);
  u8g2.firstPage();
  do {
    drawHeader();
  } while (u8g2.nextPage());
  Serial.println("OLED (U8g2): Initialized");
  delay(1000);


  // Startup header
  Serial.println();
  Serial.println();
  Serial.println("[ Mi5 TERRORIST THREAT LEVEL SYSTEM ]");


  // Add access point
  Serial.println();
  Serial.println("Adding access point (SSID): " + String(WIFI_SSID));
  WiFiMulti.addAP((const char*)WIFI_SSID, (const char*)WIFI_PASS);


  // Wait infinitely to connect
  Serial.print("Waiting for WiFi... ");
  while (WiFiMulti.run() != WL_CONNECTED) {
    Serial.print(".");
    delay(500);
  }
  Serial.println();
  Serial.println("WiFi connected");
  Serial.println("IP address: " + String(WiFi.localIP()));
}

String httpCodeToDesc(int code) {
  if (code == 200)      return "OK";
  if (code == 204)      return "No Content";
  if (code == 301)      return "Moved Permanently";
  if (code == 302)      return "Found (Redirect)";
  if (code == 400)      return "Bad Request";
  if (code == 401)      return "Unauthorized";
  if (code == 403)      return "Forbidden";
  if (code == 404)      return "Not Found";
  if (code == 500)      return "Server Error";
  if (code == 502)      return "Bad Gateway";
  if (code == 503)      return "Service Unavailable";
  if (code == 504)      return "Gateway Timeout";

  if (code == -1)       return "Connection Failed";
  if (code == -2)       return "Connection Refused";
  if (code == -3)       return "Send Failed";
  if (code == -4)       return "Read Timeout";

  return "Unknown HTTP Code";
}

bool reconnect_to_wifi() {
  if (WiFi.status() == WL_CONNECTED) return true;

  Serial.println("WiFi disconnected; trying to reconnect...");
  while (WiFi.status() != WL_CONNECTED) {
    if (WiFiMulti.run() == WL_CONNECTED) {
      Serial.println();
      Serial.println("WiFi reconnected");
      Serial.println("IP address: " + String(WiFi.localIP()));
      return true;
    }
    Serial.print(".");
    delay(500);
  }
  return false;
}

void loop() {

  // Reconnect WiFi if needed
  if (!reconnect_to_wifi()) {
    Serial.println("WiFi reconnection failed; retrying HTTP skipped.");
    delay(5000);
    return;
  }


  // Initialize
  http.begin(threat_level_url);

  // Get request
  http_code_int = http.GET();
  http_code_str = httpCodeToDesc(http_code_int);


  // Get Success
  if (http_code_int > 0) {

    // Get payload as String type
    String payload = http.getString();

    // There are 2 title and 2 description tags, we are interested in child tags of item
    int itemStart = payload.indexOf("<item>");
    int itemEnd   = payload.indexOf("</item>", itemStart);
    if (itemStart != -1 && itemEnd != -1 && itemEnd > itemStart) {
      String item = payload.substring(itemStart, itemEnd);

      // Title: Threat Level
      int titleStart = item.indexOf("<title>");
      int titleEnd   = item.indexOf("</title>", titleStart);
      if (titleStart != -1 && titleEnd != -1 && titleEnd > titleStart) {
        threat_level_str = item.substring(titleStart + 7, titleEnd);
        threat_level_str.trim();

        // Extract level
        int colon = threat_level_str.indexOf("Current threat level: ");
        if (colon != -1) {
          threat_level_str = threat_level_str.substring(colon + 22);  // 22 = len "Current threat level: "
          threat_level_str.trim();
        }

        // Map level string to int
        if      (threat_level_str == "LOW")       threat_level_int = 1;
        else if (threat_level_str == "MODERATE")  threat_level_int = 2;
        else if (threat_level_str == "SUBSTANTIAL") threat_level_int = 3;
        else if (threat_level_str == "SEVERE")    threat_level_int = 4;
        else if (threat_level_str == "CRITICAL")  threat_level_int = 5;
      }

      // Description: Threat Level description
      int descStart = item.indexOf("<description>");
      int descEnd   = item.indexOf("</description>", descStart);
      if (descStart != -1 && descEnd != -1 && descEnd > descStart) {
        threat_level_desc = item.substring(descStart + 13, descEnd);
        threat_level_desc.trim();
      }
    }
  }

  // Get Failed
  else {
    Serial.printf("GET failed, error: %s\n", http.errorToString(http_code_int).c_str());
  }


  // Print status
  Serial.println("---------------------------------------------------------------------------------------------------------------------------------------------------------------------");
  Serial.println("HTTP Code: " + String(http_code_int) + " (" + http_code_str + ")");
  Serial.println("Current UK threat level: " + String(threat_level_str) + " (" + String(threat_level_int) + "/5)");
  Serial.println("Threat level description: " + String(threat_level_desc));


  // Update OLED display
  updateOLED(http_code_int, http_code_str, threat_level_str, threat_level_int, threat_level_desc);

  // End
  http.end();
  delay(10000);
}
