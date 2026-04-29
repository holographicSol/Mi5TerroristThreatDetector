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

int    wifi_signal_dBm_raw  = 0;
String wifi_signal_dBm_name = "pending";
int    wifi_signal_dBm_bars    = 0;

// ###################################################################################################
// Get WIFI Signal (dBm)
// ###################################################################################################
int32_t getRSSIRaw() {
  return WiFi.RSSI();
}

// ###################################################################################################
// Get WIFI Signal Strength As String (dBm)
// ###################################################################################################
String getRSSIName() {
  int32_t rssi = WiFi.RSSI();
  
  if (rssi >= -50) {
    return "Excellent";
  } else if (rssi >= -60) {
    return "Good";
  } else if (rssi >= -70) {
    return "Fair";
  } else if (rssi >= -80) {
    return "Weak";
  } else {
    return "Very Weak";
  }
}

// ###################################################################################################
// WIFI Signal Bars (dBm)
// ###################################################################################################
int getRSSIBars(int max_bars) {
  int32_t rssi = WiFi.RSSI();
  int bars = 0;
  
  if (rssi >= -50) bars = max_bars;
  else if (rssi >= -60) bars = max_bars - 1;
  else if (rssi >= -70) bars = max_bars - 2;
  else if (rssi >= -80) bars = max_bars - 3;
  else if (rssi > -100) bars = 1;
  else bars = 0;
  
  return bars;
}

// ###################################################################################################
// GLOBAL STATS
// ###################################################################################################

// Connectivity
bool online_bool = false;

// HTTP Code
int    http_code_int = -1;
String http_code_str = "Unknown";

// Threat level
char *threat_level_url   = "https://www.mi5.gov.uk/UKThreatLevel/UKThreatLevel.xml";
int   threat_level_int   = 0;
String threat_level_str  = "pending";
String threat_level_desc = "pending";

// Display Header
String display_header = "Mi5 THREAT LEVEL";

// Serial Header
String serial_header = "[ Mi5 TERRORIST THREAT LEVEL SYSTEM ]";


// ###################################################################################################
// DRAW HEADER
// ###################################################################################################
static void drawHeader() {
    display_0.setFont(u8g2_font_6x10_tf);
    // Header background
    display_0.setDrawColor(1);
    display_0.drawBox(0, 0, 128, 11);
    // Header text
    display_0.setDrawColor(0);
    display_0.drawStr(64 - (display_0.getStrWidth(display_header.c_str()) / 2), 9, display_header.c_str());
    display_0.setDrawColor(1);
}

// ###################################################################################################
// UPDATE DISPLAY
// ###################################################################################################
void updateDisplay() {
  display_0.firstPage();
  do {
    display_0.setFont(u8g2_font_6x10_tf);

    // Header (inverted, y=0-10)
    drawHeader();

    // Level str (centered, y=24)
    display_0.setDrawColor(1);
    display_0.drawStr(64 - (display_0.getStrWidth(threat_level_str.c_str()) / 2), 24, threat_level_str.c_str());

    // Level int "(N/5)" (centered, y=36)
    String lineInt = "(" + String(threat_level_int) + "/5)";
    display_0.drawStr(64 - (display_0.getStrWidth(lineInt.c_str()) / 2), 36, lineInt.c_str());

    // Draw Bottom info bar (inverted, y=53-63)
    display_0.setDrawColor(1);
    display_0.drawBox(0, 53, 128, 11);
    display_0.setDrawColor(0);

    // WiFi symbol: rising bars, left-aligned, bottom at y=62
    // 4 bars each 2px wide with 1px gap; filled up to wifi_signal_dBm_bars, outline only beyond
    {
        const int barW        = 2;
        const int barGap      = 1;
        const int barBase     = 62;
        const int barHeights[4] = {3, 5, 7, 9};
        for (int i = 0; i < wifi_signal_dBm_bars; i++) {
            int bx = 2 + i * (barW + barGap);
            int bh = barHeights[i];
            int by = barBase - bh + 1;
            if (online_bool && i < wifi_signal_dBm_bars) {
                display_0.drawBox(bx, by, barW, bh);
            } else {
                display_0.drawFrame(bx, by, barW, bh);
            }
        }
    }

    // HTTP code: right-aligned (no description)
    String httpStr = String(http_code_int);
    display_0.drawStr(128 - display_0.getStrWidth(httpStr.c_str()) - 6, 62, httpStr.c_str());


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

  // Get raw RSSI (dBm)
  wifi_signal_dBm_raw = WiFi.RSSI();  // Range: -30 to -100 dBm

  // Get wifi_signal_dBm_name description
  wifi_signal_dBm_name = getRSSIName();

  // Get bar count (0-4)
  wifi_signal_dBm_bars = getRSSIBars(4);

  // ------------------------------------------------------------------------------------------------
  // WiFi
  // ------------------------------------------------------------------------------------------------

  // Show activity indicator while connecting / crawling
  updateDisplay();

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
  Serial.println("Wifi                     : " + String(online_bool ? "true" : "false"));
  Serial.println("WiFi Signal (dBm)        : " + String(wifi_signal_dBm_raw));
  Serial.println("WiFi Signal              : " + wifi_signal_dBm_name);
  Serial.println("WiFi Signal (bars)       : " + String(wifi_signal_dBm_bars) + "/4");
  Serial.println("HTTP Code                : " + String(http_code_int) + " (" + http_code_str + ")");
  Serial.println("Current UK threat level  : " + String(threat_level_str) + " (" + String(threat_level_int) + "/5)");
  Serial.println("Threat level description : " + String(threat_level_desc));

  // Update Display (activity off)
  updateDisplay();

  // ------------------------------------------------------------------------------------------------
  // Delay next iteration
  // ------------------------------------------------------------------------------------------------
  delay(3000);
}
