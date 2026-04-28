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

// ###################################################################################################
// DISPLAY
// ###################################################################################################
U8G2_SSD1309_128X64_NONAME2_F_HW_I2C display_0(U8G2_R0, /* reset=*/ U8X8_PIN_NONE);

// ###################################################################################################
// WIFI
// ###################################################################################################
WiFiMulti  wifimulti;
HTTPClient httpclient;

char *WIFI_SSID = "your_ssid";
char *WIFI_PASS = "your_password";

// ###################################################################################################
// GLOBAL STATS
// ###################################################################################################

// Connectivity
bool online_bool = false;

// HTTP Code
int    http_code_int = -1;
String http_code_str = "Unknown";

// Threat level
char *threat_level_url     = "https://www.mi5.gov.uk/UKThreatLevel/UKThreatLevel.xml";
int   threat_level_int     = 0;
String threat_level_str    = "pending";
String threat_level_desc   = "pending";

// Display Header
String display_header = "Mi5 THREAT LEVEL";

// Serial Header
String serial_header = "[ Mi5 TERRORIST THREAT LEVEL SYSTEM ]";

// ###################################################################################################
// DRAW HEADER
// ###################################################################################################
static void drawHeader() {
    display_0.setFont(u8g2_font_7x13B_tr);
    // Header background
    display_0.setDrawColor(1);
    display_0.drawBox(0, 0, 128, 15);
    // Header text
    display_0.setDrawColor(0);
    display_0.drawStr(64 - (display_0.getStrWidth(display_header.c_str()) / 2), 12, display_header.c_str());
    display_0.setDrawColor(1);
}

// ###################################################################################################
// UPDATE DISPLAY
// ###################################################################################################
void updateDisplay(int http_code,
                const String& http_desc,
                const String& level_str,
                int level_int,
                const String& level_desc) {
  display_0.firstPage();
  do {
    // Header (large font, black on white)
    drawHeader();

    // Level int (6x10 font, white on black)
    display_0.setFont(u8g2_font_6x10_tf);
    display_0.setDrawColor(1);
    String line2 = "(" + String(level_int) + "/5)";
    display_0.drawStr(64 - (display_0.getStrWidth(line2.c_str()) / 2), 32, line2.c_str());

    // Level str (6x10 font, white on black)
    display_0.setFont(u8g2_font_6x10_tf);
    display_0.setDrawColor(1);
    String line1 = level_str;
    display_0.drawStr(64 - (display_0.getStrWidth(line1.c_str()) / 2), 44, line1.c_str());

    // HTTP Code (bottom of screen)
    // if (http_code_int!=200) {
        display_0.setFont(u8g2_font_6x10_tf);
        display_0.setDrawColor(1);
        display_0.drawBox(0, 55, 128, 12);
        display_0.setDrawColor(0);
        String line0 = String(http_code) + " " + http_desc + "";
        display_0.drawStr(64 - (display_0.getStrWidth(line0.c_str()) / 2), 63, line0.c_str());
        display_0.setDrawColor(1);
    // }

  } while (display_0.nextPage());
}

// ###################################################################################################
// HTTP CODE TO DESCRIPTION
// ###################################################################################################
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
  return "Unknown";
}

// ###################################################################################################
// RECONNECT TO WIFI
// ###################################################################################################
bool reconnect_to_wifi() {
  if (WiFi.status() == WL_CONNECTED) {
    return true;
  }
  Serial.println("WiFi disconnected; trying to reconnect...");
  while (WiFi.status() != WL_CONNECTED) {
    if (wifimulti.run() == WL_CONNECTED) {
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

// ###################################################################################################
// SETUP
// ###################################################################################################
void setup() {
  // ------------------------------------------------------------------------------------------------
  // Stabalize
  // ------------------------------------------------------------------------------------------------
  delay(3000);
  
  // ------------------------------------------------------------------------------------------------
  // Serial
  // ------------------------------------------------------------------------------------------------
  Serial.begin(115200);

  // Startup header
  Serial.println();
  Serial.println();
  Serial.println(serial_header);
  Serial.println();

  // ------------------------------------------------------------------------------------------------
  // Display
  // ------------------------------------------------------------------------------------------------

  // Initialize display
  Wire.begin(7, 8);  // SDA=GPIO7, SCL=GPIO8 FOR ESP32-P4-WiFi6-M Waveshare
  Serial.println("[Display] Initializing");
  display_0.begin();
  display_0.setFont(u8g2_font_5x8_tf);
  display_0.firstPage();
  do {
    drawHeader();
  } while (display_0.nextPage());
  Serial.println("[Display] Initialized");
  delay(1000);

  // ------------------------------------------------------------------------------------------------
  // WiFi
  // ------------------------------------------------------------------------------------------------

  // Add access point
  Serial.println("[WiFi] Adding access point (SSID): " + String(WIFI_SSID));
  wifimulti.addAP((const char*)WIFI_SSID, (const char*)WIFI_PASS);

  // Wait infinitely to connect
  Serial.print("[WiFi] Waiting for WiFi... ");
  while (wifimulti.run() != WL_CONNECTED) {
    online_bool = false;
    Serial.print(".");
    delay(500);
  }
  online_bool = true;
  Serial.println();
  Serial.println("[WiFi] connected");
  Serial.println("[WiFi] IP address: " + String(WiFi.localIP()));
}

// ###################################################################################################
// MAIN LOOP
// ###################################################################################################
void loop() {

  // ------------------------------------------------------------------------------------------------
  // WiFi
  // ------------------------------------------------------------------------------------------------

  // Reconnect WiFi if needed
  if (!reconnect_to_wifi()) {
    online_bool = false;
    Serial.println("WiFi reconnection failed");
    delay(5000);
  }
  else {online_bool = true;}

  if (online_bool==true) {

    // ------------------------------------------------------------------------------------------------
    // Read RSS Feed
    // ------------------------------------------------------------------------------------------------

    // Initialize
    httpclient.begin(threat_level_url);

    // Get request
    http_code_int = httpclient.GET();
    http_code_str = httpCodeToDesc(http_code_int);


    // Get Success
    if (http_code_int > 0) {

        // Get payload as String type
        String payload = httpclient.getString();

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
    else {Serial.printf("GET failed, error: %s\n", httpclient.errorToString(http_code_int).c_str());}

    // End
    httpclient.end();
  }

  // ------------------------------------------------------------------------------------------------
  // Update Stats
  // ------------------------------------------------------------------------------------------------

  // Update Serial
  Serial.println("---------------------------------------------------------------------------------------------------------------------------------------------------------------------");
  Serial.println("Online                   : " + String(online_bool ? "true" : "false"));
  Serial.println("HTTP Code                : " + String(http_code_int) + " (" + http_code_str + ")");
  Serial.println("Current UK threat level  : " + String(threat_level_str) + " (" + String(threat_level_int) + "/5)");
  Serial.println("Threat level description : " + String(threat_level_desc));

  // Update Display
  updateDisplay(http_code_int, http_code_str, threat_level_str, threat_level_int, threat_level_desc);

  // ------------------------------------------------------------------------------------------------
  // Delay next iteration
  // ------------------------------------------------------------------------------------------------
  delay(10000);
}
