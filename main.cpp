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

String serial_header  = "[ MI5 TERRORIST THREAT LEVEL SYSTEM ]";

// ###################################################################################################
// DISPLAY
// ###################################################################################################

U8G2_SSD1309_128X64_NONAME2_F_HW_I2C display_0(U8G2_R0, /* reset=*/ U8X8_PIN_NONE);

String display_header = "MI5 THREAT";

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
String threat_level_str  = "PENDING";
String threat_level_desc = "PENDING";
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

/*
  Fontname: Cobalt_Alien_Condensed_10
  Copyright: 
  Glyphs: 224/256
  BBX Build Mode: 0
*/
const uint8_t cobalt_alien_cond_10[2148] U8G2_FONT_SECTION("cobalt_alien_cond_10") = 
  "\340\0\3\4\4\4\2\4\5\14\14\0\375\7\376\10\377\1D\2\212\10G \5\0\342\4!\6r\42"
  "\205\3\42\10\65r\205\10\25\1#\17wc\216$\21\221\23)'\222DD\0$\17\224\237\215\220H"
  "I\10IH\211\220\10\0%\26\232\37\7\61\221\20\211\30\211\70\200\70\200\10\231\10\221\20\61\1&\12"
  "v#F\211\214HD\10'\6\62\63\205\1(\10\224\237\205\221|\42)\10\224\237\5\221|\62*\7"
  "\62\67\315H\0+\12CgM\310HP\10\0,\6\62\37\205\1-\6\23o\305\0.\6B#\5"
  "\2/\14v#\246\230\240\230\240\230D\0\60\11v#\6\312C\12\2\61\7sc\305\210|\62\12v"
  "#\206\241\30\233\240\1\63\12u\343E\231\330\231\330\1\64\12v#N\211,%\210\22\65\12v#\6"
  "\342\230\331 \2\66\12v#\6\242 \22\21\2\67\12u\343E\231\220\232\64\0\70\12v#\6\22\221"
  "\22\21\2\71\12v#\6\22\21\242 \2:\7b#\5!\1;\10r\37\5\241H\4<\14t\243"
  "\225\210\220\210\230\220\230\0=\7\64\253\5!\1>\14t\243\305\220\230\220\24\221\21\0\77\13u\343E"
  "\231\320\261\230\30\0@\25\233_G;\0\71\0I\11\211\24\22)$\42\347@*\0A\13v#\6"
  "\242\20\221\22\221\0B\12v#\206!\221\22\21\2C\10u\343\305\231\334\12D\11v#\206!\21M"
  "\10E\12u\343\305\231\330\231X\1F\12u\343\305\231\330\231\64\0G\11v#\6\242$J\10H\12"
  "v#\206\20%%J\2I\6r#\205\3J\7t\243\225<\31K\15v#\206H\211\10\21%\21"
  ")\3L\10t\243\205\220<\21M\17y\343\206h\331\11\212\311\10Q\20\251\0N\14wc\206X\221"
  "\311\212Q\231\0O\10v#\6\22\235\20P\13v#\206!\21\221\242 \0Q\12\206#\6\22\235J"
  "\4\5R\13v#\206!\21\221\212$\1S\12v#\6\342\230\331 \2T\11v#\206\221\240<\1"
  "U\10v#\206\20=!V\14v#\306\210<\205\10\215M\1W\26z#\307\220\210\224\21\241\220\21"
  "\241\220\262\221\261\221\261\221\21\0X\16v#\306\210\10\331\230\340\20\311\210\0Y\14v#\206\220\10\21"
  "\231\240L\0Z\12v#\206\241\30\233\240\1[\10\224\237\205\221|\42\134\14v#\306\240\250\240\250\240"
  "\250\0]\10\224\237\5\221|\62^\13v#\206!\21\221\22\221\0_\6\25\343E\1`\6\22;\205"
  "\0a\11f#\6\22M%\2b\12v#\206 \22%A\4c\10e#\306\231l\5d\10v#"
  "\246\22\215\6e\12f#\6\22\245\20A\3f\12u\333\305\231\330\231\64\0g\13\206\33\6\22M%"
  "\202B\4h\11v#\206 \22\235\4i\6b#\5\3j\11\243W\215\240\210\274\24k\15v#\206"
  "\240\10\12\21\221\210\224\1l\6r#\205\3m\14i\343\206h\331\311S\20\251\0n\13gc\306\220"
  "\311\303\210\231\0o\10f#\6\22M\10p\12v\37\206!\21%E\0q\12v\37\6\22M%\202"
  "\2r\10d\243\205\221\234\0s\12f#\316aQ\341\11\0t\11t\243\205\220\221L\4u\10f#"
  "\206\20\235\20v\15f\342\305\210L!BDc#\0w\24i\242\206\220\210H\310\210H\211HI\320"
  "\310\230\310\10\0x\15f#\306\210\10\231\240\30\311\210\0y\13\206\33\206\20\235J\4\205\10z\12f"
  "#\206\241\210\212\240\1{\11f\242\5\22M%\2|\7\222\336\304\303\0}\10f\242\5\22\215\6~"
  "\12v\242\5\242\224\42\42\4\177\5\0\242\4\200\5\0\42\4\201\5\0\42\4\202\5\0\42\4\203\5\0"
  "\42\4\204\5\0\42\4\205\5\0\42\4\206\5\0\42\4\207\5\0\42\4\210\5\0\42\4\211\5\0\42\4"
  "\212\5\0\42\4\213\5\0\42\4\214\5\0\42\4\215\5\0\42\4\216\5\0\42\4\217\5\0\42\4\220\5"
  "\0\42\4\221\5\0\42\4\222\5\0\42\4\223\5\0\42\4\224\5\0\42\4\225\5\0\42\4\226\5\0\42"
  "\4\227\5\0\42\4\230\5\0\42\4\231\5\0\42\4\232\5\0\42\4\233\5\0\42\4\234\5\0\42\4\235"
  "\5\0\42\4\236\5\0\42\4\237\5\0\42\4\240\5\0\342\4\241\7r\342\4\21\2\242\21\225\236]`"
  "\310I\210H\210HHY`\10\0\243\14v\342\315\230\240X\221\240\230\1\244\10u\343\205\210\27\1\245"
  "\15v\342\205\220\10\21\65\61\62!\0\246\7\222\336\4\22\2\247\15v\242\245\10Q\211\224\22\222\61\0"
  "\250\7\23;EH\0\251\7\62\366\314H\0\252\13v\342\325\330\264\20\271\224\10\253\20x\42\226\24!"
  "YF\304\204\304\202\304\204\4\254\7\64f\5Y\4\255\6\22\356\204\0\256\7\62\366\314H\0\257\6\25"
  "zE\1\260\6\21\273D\0\261\12d\42UX\320P(\1\262\7D\62\5\21\5\263\11f\242\5\22"
  "\225B\3\264\6\22\372\204\0\265\11v\236\205\20\235\24\1\266\12\226\232E\332H\25\371\7\267\6\42\352"
  "\4\1\270\6!\232\204\0\271\6B\362\4\2\272\7Dr\305C\0\273\22x\42\306\210\230\220\230\210\230"
  "\220\24!)#B\0\274\24|\42\337H\250X\210P\70P\10\213\260X\250h!\0\275\26\231^\206"
  "\70\200\220\230\220\230\210\360\260\10\211\240\210\220P \1\276\21z#WH\304#\225\21\22\245\243\220\20"
  "\61\0\277\11u\242\235\344#\261\2\300\15\226\242\225\70\10\242\20\221\22\221\0\301\15\226\242\225\70\10\242"
  "\20\221\22\221\0\302\16\226\242\225XP\10\242\20\221\22\221\0\303\16\226\242\215H`\20\242\20\221\22\221"
  "\0\304\16\226\342MP\70\0\242\20\221\22\221\0\305\15\226\342]\70\10\242\20\221\22\221\0\306\17y\242"
  "\306\222\230\220\230\320\232\220\230P\1\307\14\226\232E\211\240\34\315\2\205\0\310\14\225\242Uh\310\231\330"
  "\231X\1\311\13\225\242\225\360\231\330\231X\1\312\13\225\242\315\360\231\330\231X\1\313\14\225\242MP\350"
  "\231\330\231X\1\314\7\222\342\204\220\3\315\7\222\342\204\220\3\316\11\223\342\204\330\210|\1\317\7\221b"
  "D\310\1\320\16w\342\215\251\210\220\211$\21!\21\3\321\16\227\342M\71\210X\221\311\212Q\231\0\322"
  "\12\226\242\225\70\10\22\235\20\323\12\226\242\225\70\10\22\235\20\324\13\226\242\225XP\10\22\235\20\325\13"
  "\226\242\215H`\20\22\235\20\326\13\226\342MP\70\0\22\235\20\327\11D&\215\10\211\10\1\330\11v"
  "\242\5\312C\12\2\331\12\226\242\225\70\210\20=!\332\12\226\242\225\70\210\20=!\333\13\226\242\225X"
  "P\210\20=!\334\13\226\342MP\70\200\20=!\335\16\226\342\225\70\210\220\10\21\231\240L\0\336\13"
  "v\242\205\240!\21\221\42\0\337\12v\242\5\22\225\42*\3\340\12v\242\225\20\22M%\2\341\12v"
  "\242\225\20\22M%\2\342\12v\242\225\20\22M%\2\343\13v\242\215H\10\22M%\2\344\13v\342"
  "MP\10\22M%\2\345\12v\342]\20\22M%\2\346\20j\342\6\223\20\221\20\221P\210\220\340\210"
  "\1\347\14\206\232E\211\240\214f\201B\0\350\13v\242\225\20\22\245\20A\3\351\13v\242\225\20\22\245"
  "\20A\3\352\13v\242\225\20\22\245\20A\3\353\14v\342MP\10\22\245\20A\3\354\6r\342\204\3"
  "\355\6r\342\204\3\356\11s\342\204H\211\134\0\357\6qb\304\1\360\14\206\342U\230Q\210\240\22\21"
  "\2\361\14w\342MQX\221\311\212\231\0\362\11v\242\225\20\22M\10\363\11v\242\225\20\22M\10\364"
  "\11v\242\225\20\22M\10\365\12v\242\215H\10\22M\10\366\12v\342MP\10\22M\10\367\11Df"
  "U\10q\10\0\370\11f\242\5\312\303\10\2\371\12v\242\225\70\210\20M\10\372\12v\242\225\70\210\20"
  "M\10\373\13v\242\225XP\210\20M\10\374\13v\342MP\70\200\20M\10\375\14\226\232\225\60\21M"
  "%\202B\4\376\13\206\236\205\240 \22%E\0\377\15\226\332MP(\21M%\202B\4\0\0\0\4"
  "\377\377\0";


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
      // u8g2_font_6x10_tf
      // u8g2_font_7x13B_tf
      // u8g2_font_t0_11b_tf
      // u8g2_font_profont11_tf

      display_0.setFont(cobalt_alien_cond_10);

      // Header
      // display_0.setFont(u8g2_font_profont11_tf);
      display_0.setDrawColor(1);
      display_0.drawBox(0, 0, 128, 11);
      display_0.setDrawColor(0);
      display_0.drawStr(64 - (display_0.getStrWidth(display_header.c_str()) / 2), 9, display_header.c_str());
      display_0.setDrawColor(1);

      // Level str
      // display_0.setFont(u8g2_font_7x13B_tf);
      display_0.setDrawColor(1);
      display_0.drawStr(64 - (display_0.getStrWidth(threat_level_str.c_str()) / 2), 27, threat_level_str.c_str());

      // Level int - 5 numbered boxes, current level emphasized
      // display_0.setFont(u8g2_font_profont11_tf);
      {
        const int boxW   = 17;
        const int boxH   = 13;
        const int boxGap = 4;
        const int totalW = 5 * boxW + 4 * boxGap;
        const int startX = (128 - totalW) / 2;
        const int boxY   = 33;
        const int textY  = boxY + 10;  // baseline: centers digit vertically in box
        for (int i = 1; i <= 5; i++) {
          int bx = startX + (i - 1) * (boxW + boxGap);
          char digit[2] = { (char)('0' + i), '\0' };
          int textX = bx + (boxW - display_0.getStrWidth(digit)) / 2;
          if (i == threat_level_int) {
            display_0.setDrawColor(1);
            display_0.drawBox(bx, boxY, boxW, boxH);
            display_0.setDrawColor(0);
            display_0.drawStr(textX, textY, digit);
            display_0.setDrawColor(1);
          } else {
            display_0.setDrawColor(1);
            display_0.drawFrame(bx, boxY, boxW, boxH);
            display_0.drawStr(textX, textY, digit);
          }
        }
      }

      // Draw Bottom info bar
      display_0.setDrawColor(1);
      display_0.drawBox(0, 53, 128, 11);
      display_0.setDrawColor(0);
      
      // WiFi signal: rising bars
      // display_0.setFont(u8g2_font_profont11_tf);
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
      // display_0.setFont(u8g2_font_profont11_tf);
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
