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
#include "arg_parser.h"
#include "strval.h"
#include "hextodig.h"
#include <FS.h>
#include <SPIFFS.h>
#include <ArduinoJson.h>

// ###################################################################################################
// TASKS
// ###################################################################################################

TaskHandle_t DisplayTask;
TaskHandle_t ConnectionTask;
TaskHandle_t SerialTask;

// ###################################################################################################
// FILE
// ###################################################################################################

#define JSON_CONFIG_FILE "/config.json"

// ###################################################################################################
// SERIAL
// ###################################################################################################

bool debug=false;

ArgParser      parser;
PlainArgParser plainparser;

struct Serial0Data{
  int  nbytes;
  int  iter_token;
  char BUFFER[256];
  int  token;
  char checksum[1];
  int  checksum_of_buffer;
  int  checksum_in_buffer;
  char gotSum[2];
  int  i_XOR;
  int  XOR;
  char c_XOR;
} serial0Data;

String serial_header  = "[ Mi5 TERRORIST THREAT LEVEL SYSTEM ]";

// ###################################################################################################
// DISPLAY
// ###################################################################################################

U8G2_SSD1309_128X64_NONAME2_F_HW_I2C display_0(U8G2_R0, /* reset=*/ U8X8_PIN_NONE);

String display_header = "Mi5 THREAT LEVEL";

// ###################################################################################################
// WIFI
// ###################################################################################################

WiFiMulti  wifimulti;
HTTPClient httpclient;

char WIFI_SSID[32];
char WIFI_PASS[64];

int    wifi_signal_dBm_raw  = 0;
String wifi_signal_dBm_name = "pending";
int    wifi_signal_dBm_bars = 0;

// Connectivity
bool ap_connected = false;

// HTTP Code
int    http_code_int = -1;
String http_code_str = "Unknown";

// Threat level
char*  threat_level_url  = "https://www.mi5.gov.uk/UKThreatLevel/UKThreatLevel.xml";
int    threat_level_int  = 0;
String threat_level_str  = "pending";
String threat_level_desc = "pending";
const char* threat_level_names[6] = {"LOW", "MODERATE", "SUBSTANTIAL", "SEVERE", "CRITICAL", "UNKNOWN"};

// ###################################################################################################
// GET CHECKSUM SERIAL0
// ###################################################################################################
int getCheckSumSerial0(char * string) {
  for (serial0Data.XOR=0, serial0Data.i_XOR=0; serial0Data.i_XOR < strlen(string); serial0Data.i_XOR++)
  {
    serial0Data.c_XOR=(unsigned char)string[serial0Data.i_XOR];
    if (serial0Data.c_XOR=='*') break;
    if (serial0Data.c_XOR != '$') serial0Data.XOR ^= serial0Data.c_XOR;
  }
  return serial0Data.XOR;
}

// ###################################################################################################
// VALIDATE CHECKSUM SERIAL0
// ###################################################################################################
bool validateChecksumSerial0(char * buffer) {
  memset(serial0Data.gotSum, 0, sizeof(serial0Data.gotSum));
  serial0Data.gotSum[0]=buffer[strlen(buffer) - 3];
  serial0Data.gotSum[1]=buffer[strlen(buffer) - 2];
  serial0Data.checksum_of_buffer= getCheckSumSerial0(buffer);
  serial0Data.checksum_in_buffer=h2d2(serial0Data.gotSum[0], serial0Data.gotSum[1]);
  if (serial0Data.checksum_in_buffer==serial0Data.checksum_of_buffer) {return true;}
  return false;
}

// ###################################################################################################
// CREATE CHECKSUM SERIAL0
// ###################################################################################################
void createChecksumSerial0(char * buffer) {
  serial0Data.checksum_of_buffer=getCheckSumSerial0(buffer);
  sprintf(serial0Data.checksum,"%X",serial0Data.checksum_of_buffer);
}

// ###################################################################################################
// VALIDATE SSID
// ###################################################################################################
bool validate_ssid(const char* ssid) {
  size_t len = strlen(ssid);
  return len > 0 && len <= sizeof(WIFI_SSID) - 1;
}

// ###################################################################################################
// VALIDATE PASSWORD
// ###################################################################################################
bool validate_password(const char* password) {
  size_t len = strlen(password);
  return len >= 8 && len <= sizeof(WIFI_PASS) - 1;
}

// ###################################################################################################
// SAVE CONFIG FILE
// ###################################################################################################
void saveConfigFile() {

  Serial.println(F("[saveConfigFile] Saving configuration..."));
  
  // Create a JSON document
  JsonDocument json;
  json["WIFI_SSID"] = WIFI_SSID;
  json["WIFI_PASS"] = WIFI_PASS;
 
  // Open config file
  File configFile = SPIFFS.open(JSON_CONFIG_FILE, "w");
  if (!configFile) {Serial.println("[saveConfigFile] Failed to open config file for writing");}
 
  // Serialize JSON data to write to file
  serializeJsonPretty(json, Serial);
  if (serializeJson(json, configFile) == 0) {Serial.println("[saveConfigFile] Failed to write to file");}

  // Close file
  configFile.close();
}

// ###################################################################################################
// LOAD CONFIG FILE
// ###################################################################################################
bool loadConfigFile()
// Load existing configuration file
{
  // Uncomment if we need to format filesystem
  // SPIFFS.format();
 
  // Read configuration from FS json
  Serial.println("[loadConfigFile] Mounting File System...");
 
  // May need to make it begin(true) first time you are using SPIFFS
  if (SPIFFS.begin(false) || SPIFFS.begin(true))
  {
    Serial.println("[loadConfigFile] Mounted file system");
    if (SPIFFS.exists(JSON_CONFIG_FILE))
    {
      // The file exists, reading and loading
      Serial.println("[loadConfigFile] Reading config file");
      File configFile = SPIFFS.open(JSON_CONFIG_FILE, "r");
      if (configFile)
      {
        Serial.println("[loadConfigFile] Opened configuration file");
        JsonDocument json;
        DeserializationError error = deserializeJson(json, configFile);
        serializeJsonPretty(json, Serial);
        if (!error)
        {
          Serial.println("[loadConfigFile] Parsing JSON");

          memset(WIFI_SSID, 0, sizeof(WIFI_SSID));
          memset(WIFI_PASS, 0, sizeof(WIFI_PASS));
          strcpy(WIFI_SSID, json["WIFI_SSID"]);
          strcpy(WIFI_PASS, json["WIFI_PASS"]);
 
          return true;
        }
        else {Serial.println("[loadConfigFile] Failed to load json config");}
      }
    }
  }
  else
  {
    // Error mounting file system
    Serial.println("[loadConfigFile] Failed to mount FS");
  }
 
  return false;
}

// ###################################################################################################
// SET ACCESS POINT
// ###################################################################################################
bool set_ap(const char* ssid, const char* password) {
  
  // Clear existing APs to avoid conflicts
  wifimulti.APlistClean();

  // Update existing credentials
  memset(WIFI_SSID, 0, sizeof(WIFI_SSID));
  memset(WIFI_PASS, 0, sizeof(WIFI_PASS));
  strncpy(WIFI_SSID, ssid, sizeof(WIFI_SSID) - 1);
  strncpy(WIFI_PASS, password, sizeof(WIFI_PASS) - 1);

  // Save to file system
  saveConfigFile();

  // Add new AP to WiFiMulti
  bool result = wifimulti.addAP(WIFI_SSID, WIFI_PASS);
  if (result) {Serial.println("[WiFi] Access point updated successfully: " + String(WIFI_SSID));}
  else {Serial.println("[WiFi] Failed to update access point: " + String(WIFI_SSID));}
  return result;
}

// ###################################################################################################
// Get WIFI Signal (dBm)
// ###################################################################################################
int32_t getRSSIRaw() {return WiFi.RSSI();}

// ###################################################################################################
// Get WIFI Signal Strength As String (dBm)
// ###################################################################################################
String getRSSIName() {
  int32_t rssi = WiFi.RSSI();
  if      (!ap_connected) {return "Offline";}
  else if (rssi >= -50)   {return "Excellent";}
  else if (rssi >= -60)   {return "Good";}
  else if (rssi >= -70)   {return "Fair";}
  else if (rssi >= -80)   {return "Weak";}
  else                    {return "Very Weak";}
}

// ###################################################################################################
// WIFI Signal Bars (dBm)
// ###################################################################################################
int getRSSIBars(int max_bars) {
  int32_t rssi = WiFi.RSSI();
  int bars = 0;
  if      (rssi >= -50) {bars = max_bars;}
  else if (rssi >= -60) {bars = max_bars - 1;}
  else if (rssi >= -70) {bars = max_bars - 2;}
  else if (rssi >= -80) {bars = max_bars - 3;}
  else if (rssi > -100) {bars = 1;}
  else                  {bars = 0;}
  return bars;
}

// ###################################################################################################
// HTTP CODE TO DESCRIPTION
// ###################################################################################################
String httpCodeToDesc(int code) {
  if (code == 200) return "OK";
  if (code == 204) return "No Content";
  if (code == 301) return "Moved Permanently";
  if (code == 302) return "Found (Redirect)";
  if (code == 400) return "Bad Request";
  if (code == 401) return "Unauthorized";
  if (code == 403) return "Forbidden";
  if (code == 404) return "Not Found";
  if (code == 500) return "Server Error";
  if (code == 502) return "Bad Gateway";
  if (code == 503) return "Service Unavailable";
  if (code == 504) return "Gateway Timeout";
  if (code == -1)  return "Connection Failed";
  if (code == -2)  return "Connection Refused";
  if (code == -3)  return "Send Failed";
  if (code == -4)  return "Read Timeout";
  return "Unknown";
}

// ###################################################################################################
// UPDATE DISPLAY TASK
// ###################################################################################################
void updateDisplayTask(void * pvParameters) {
  while (1) {

    // -----------------------------------------------------------------------------------------------
    // Update Display
    // -----------------------------------------------------------------------------------------------
    display_0.firstPage();
    do {
      display_0.setFont(u8g2_font_6x10_tf);

      // Header
      display_0.setDrawColor(1);
      display_0.drawBox(0, 0, 128, 11);
      display_0.setDrawColor(0);
      display_0.drawStr(64 - (display_0.getStrWidth(display_header.c_str()) / 2), 9, display_header.c_str());
      display_0.setDrawColor(1);

      // Level str (centered, y=29)
      display_0.setDrawColor(1);
      display_0.drawStr(64 - (display_0.getStrWidth(threat_level_str.c_str()) / 2), 29, threat_level_str.c_str());

      // Level int "(N/5)" (centered, y=41)
      String lineInt = "(" + String(threat_level_int) + "/5)";
      display_0.drawStr(64 - (display_0.getStrWidth(lineInt.c_str()) / 2), 41, lineInt.c_str());

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
          if (ap_connected) {
            for (int i = 0; i < wifi_signal_dBm_bars; i++) {
                int bx = 2 + i * (barW + barGap);
                int bh = barHeights[i];
                int by = barBase - bh + 1;
                display_0.drawBox(bx, by, barW, bh);
            }
          }
          else {
            int bx = 2 + 0 * (barW + barGap);
            int bh = barHeights[0];
            int by = barBase - bh + 1;
            display_0.drawBox(bx, by, barW, bh);
            display_0.drawStr(2 + barW + 2, 63, "x");
          }
      }

      // HTTP code: right-aligned (no description)
      String httpStr = String(http_code_int);
      display_0.drawStr(128 - display_0.getStrWidth(httpStr.c_str()) - 6, 62, httpStr.c_str());


    } while (display_0.nextPage());

    // -----------------------------------------------------------------------------------------------
    // End
    // -----------------------------------------------------------------------------------------------
    vTaskDelay(1000 / portTICK_PERIOD_MS);
  }
}

// ###################################################################################################
// GET ONLINE TASK
// ###################################################################################################
void connectionTask(void * pvParameters) {
  while (1) {
    // -----------------------------------------------------------------------------------------------
    // Update Signal
    // -----------------------------------------------------------------------------------------------

    // Get raw RSSI (dBm)
    wifi_signal_dBm_raw = WiFi.RSSI();  // Range: -30 to -100 dBm

    // Get wifi_signal_dBm_name description
    wifi_signal_dBm_name = getRSSIName();

    // Get bar count (0-4)
    wifi_signal_dBm_bars = getRSSIBars(4);

    // -----------------------------------------------------------------------------------------------
    // Connect WiFi if needed
    // -----------------------------------------------------------------------------------------------

    // Connected
    if (WiFi.status() == WL_CONNECTED) {ap_connected = true;}

    // Connect
    else {
      ap_connected = false;
      Serial.println("[WiFi] trying to connect...");

      for (int i=0; i<10; i++) {
        Serial.println("[WiFi] Connection attempt: " + String(i+1) + "/10");
        if (wifimulti.run() == WL_CONNECTED) {
          ap_connected = true;
          Serial.println();
          Serial.println("[WiFi] connected");
          Serial.println("[WiFi] IP address: " + WiFi.localIP().toString());
          break;
        }
        Serial.print(".");
        delay(500);
      }
    }

    // -----------------------------------------------------------------------------------------------
    // End
    // -----------------------------------------------------------------------------------------------
    vTaskDelay(1000 / portTICK_PERIOD_MS);
  }
}

// ###################################################################################################
// PRINT HELP
// ###################################################################################################
static void PrintHelp(void) {
  Serial.println(
    R"(

    -----------------------------------------------------------------------------

    [Help]

    help or h displays this help message.

    [Connect to Access Point]

    connect --ssid <SSID> -p <PASSWORD>

    Access point will be stored automatically.

    [Debug]

    debug --enable
    debug -e
    debug --disable
    debug -d

    If enabled, system information will be printed to serial, periodically.

    -----------------------------------------------------------------------------

    )"
  );
}

// ###################################################################################################
// DEBUG ARG PARSE
// ###################################################################################################
/*
  Debug ArgParse.
  Expected behaviour:
  command: foo -a -b -c
  flags:   a b c
  command: foo -a 1 -b 2 -c 3
  flags:   a="1" b="2" c="3"
  Note:
    - For best practice only use ArgParser if flags are required, else use PlainArgParser for simple tokenization.
    - Use PlainArgParser if processing negative numbers.
    - short flags: 1-3 alphanumeric chars. example: -a, -a1, -a12, -abc.
    - long flags: 4-256 alphanumeric chars. example: --foobar, --foo-bar, --foobar123.
    - see ArgParser for more details.
*/
size_t pos_count;
const char** pos;
bool verbose;
bool verbose_1;
bool enable;

void printArgParse() {
  Serial.println("-------------------------------------------");
  Serial.print("[debug] First command: ");
  if (pos_count > 0) {Serial.println(pos[0]);}
  else {Serial.println("none");}
  Serial.print("[debug] Positionals (");
  Serial.print(pos_count);
  Serial.print("): ");
  for (size_t j = 0; j < pos_count; ++j)
    {Serial.print(pos[j]); if (j < pos_count - 1) Serial.print(" ");}
  Serial.println();
  Serial.println("----");
  Serial.print("[debug] Flag count: ");
  Serial.println(parser.flag_count);
  Serial.print("[debug] Flags: ");
  for (size_t k = 0; k < parser.flag_count; ++k)
    {Serial.print(parser.flags[k]); const char* val = parser.values[k];
      if (val[0] != '\0') {Serial.print("=\""); Serial.print(val); Serial.print("\"");}
      if (k < parser.flag_count - 1) Serial.print(" ");
  }
  Serial.println();
  Serial.println("-------------------------------------------");
}

// ###################################################################################################
// SERIAL TASK
// ###################################################################################################
void serialTask(void * pvParameters) {
  while (1) {
    // -----------------------------------------------------------------------------------------------
    // Get Serial Commands
    // -----------------------------------------------------------------------------------------------
    memset(serial0Data.BUFFER, 0, sizeof(serial0Data.BUFFER));
    while (Serial.available())
      {Serial.readBytesUntil('\n', serial0Data.BUFFER, sizeof(serial0Data.BUFFER)-1);}
    if (strlen(serial0Data.BUFFER)>=2) {

      // Debug Serial Buffer.
      Serial.println("[cmd] " + String(serial0Data.BUFFER));

      // Initialize argparse.
      argparser_reset(&parser);
      if (!argparser_init_from_buffer(&parser, serial0Data.BUFFER))
        {fprintf(stderr, "[cmd] Failed to initialize parser from buffer\n"); return;}
      pos_count=0; pos={}; pos = argparser_get_positionals(&parser, &pos_count);

      // Verbosity.
      verbose=false; verbose_1=false;
      verbose = argparser_get_bool(&parser, "v") || argparser_get_bool(&parser, "verbose");
      verbose_1 = argparser_get_bool(&parser, "vv") || argparser_get_bool(&parser, "verbose1");
      if (verbose_1) {verbose=true;}
      if (verbose==false) {verbose_1=false;}
      Serial.println("[cmd] verbose: " + String(verbose));
      Serial.println("[cmd] verbose1: " + String(verbose_1));

      // Enable/Disable
      enable=false;
      if (argparser_has_flag(&parser, "disable") || argparser_has_flag(&parser, "d")) {enable=false;}
      else if (argparser_has_flag(&parser, "enable") || argparser_has_flag(&parser, "e")) {enable=true;}

      // Debug Arg Parse.
      printArgParse();

      // Commands.
      if (strcmp(pos[0], "help")==0 || strcmp(pos[0], "h")==0) {PrintHelp();}

      // Debug
      else if (strcmp(pos[0], "debug")==0) {
        if (enable) {Serial.println("[cmd] Debug enabled"); debug=true;}
        else {Serial.println("[cmd] Debug disabled");debug=false;}
      }

      // Connect
      else if (strcmp(pos[0], "connect")==0) {
        const char* ssid = "";
        const char* password = "";
        if (argparser_has_flag(&parser, "ssid")) {ssid = argparser_get_string(&parser, "ssid", "");}
        if (argparser_has_flag(&parser, "p")) {password = argparser_get_string(&parser, "p", "");}
        if (validate_ssid(ssid) && validate_password(password)) {
          
          // Suspend connection task to avoid conflicts during manual connect
          vTaskSuspend(ConnectionTask);
          ap_connected = false;

          delay(100);

          // Add new AP
          if (set_ap(ssid, password)) {

            // Reconnect WiFi (force a disconnect and allow connection task to handle further connection attempts)
            Serial.println("[cmd] Reconnecting to: " + String(ssid));
            WiFi.reconnect();
          }
          else {
            Serial.println("[cmd] Failed to set access point. Please check the credentials and try again.");
          }

          // Resume connection task
          vTaskResume(ConnectionTask);
        }
        else {
          Serial.println("[cmd] Invalid SSID or password. SSID must be 1-32 chars. Password must be 8-63 chars.");
        }
      }
    }

    // -----------------------------------------------------------------------------------------------
    // Update Serial
    // -----------------------------------------------------------------------------------------------
    if (debug) {
      Serial.println("---------------------------------------------------------------------------------------------------------------------------------------------------------------------");
      Serial.println("Wifi                     : " + String(ap_connected ? "true" : "false"));
      Serial.println("WiFi Signal (dBm)        : " + String(wifi_signal_dBm_raw));
      Serial.println("WiFi Signal              : " + wifi_signal_dBm_name);
      Serial.println("WiFi Signal (bars)       : " + String(wifi_signal_dBm_bars) + "/4");
      Serial.println("HTTP Code                : " + String(http_code_int) + " (" + http_code_str + ")");
      Serial.println("Current UK threat level  : " + String(threat_level_str) + " (" + String(threat_level_int) + "/5)");
      Serial.println("Threat level description : " + String(threat_level_desc));
    }

    // -----------------------------------------------------------------------------------------------
    // End
    // -----------------------------------------------------------------------------------------------
    vTaskDelay(1000 / portTICK_PERIOD_MS);
  }
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
  // WiFi
  // ------------------------------------------------------------------------------------------------

  // Add access point
  // Serial.println("[WiFi] Adding access point (SSID): " + String(WIFI_SSID));
  bool res = loadConfigFile();
  Serial.println("[WiFi] Loaded config from file: " + String(res ? "true" : "false"));
  wifimulti.addAP((const char*)WIFI_SSID, (const char*)WIFI_PASS);

  // ------------------------------------------------------------------------------------------------
  // Display
  // ------------------------------------------------------------------------------------------------

  // Initialize display
  Wire.begin(7, 8);  // SDA=GPIO7, SCL=GPIO8 FOR ESP32-P4-WiFi6-M Waveshare
  Serial.println("[Display] Initializing");
  display_0.begin();
  display_0.setFont(u8g2_font_5x8_tf);

  // ------------------------------------------------------------------------------------------------
  // Tasks
  // ------------------------------------------------------------------------------------------------

  // Start display task
  xTaskCreatePinnedToCore(
    updateDisplayTask,
    "UpdateDisplayTask",
    4096,
    NULL,
    0,
    &DisplayTask,
    0
  );

  // Start signal update task
  xTaskCreatePinnedToCore(
    connectionTask,
    "ConnectionTask",
    4096,
    NULL,
    0,
    &ConnectionTask,
    0
  );

  // Start serial task
  xTaskCreatePinnedToCore(
    serialTask,
    "SerialTask",
    4096,
    NULL,
    0,
    &SerialTask,
    0
  );
}

// ###################################################################################################
// MAIN LOOP
// ###################################################################################################
void loop() {

  if (ap_connected==true) {

    // ------------------------------------------------------------------------------------------------
    // Read RSS Feed
    // ------------------------------------------------------------------------------------------------

    // Initialize
    httpclient.begin(threat_level_url);

    // Get request
    http_code_int = httpclient.GET();
    http_code_str = httpCodeToDesc(http_code_int);


    // Scrape data if successful
    if (http_code_int == 200) {

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

            // Extract level by word (upper/lower case)
            {
              String upper = threat_level_str;
              upper.toUpperCase();
              threat_level_str = "";
              for (int i = 0; i < 5; i++) {
                  if (upper.indexOf(threat_level_names[i]) != -1) {
                  threat_level_str = String(threat_level_names[i]);
                  break;
                  }
              }
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
  else {
    http_code_int = -1;
    http_code_str = "Offline";
    // threat_level_str = "pending";
    // threat_level_int = 0;
    // threat_level_desc = "pending";
  }

  // ------------------------------------------------------------------------------------------------
  // Delay next iteration
  // ------------------------------------------------------------------------------------------------
  delay(5000);
}
