/*

	settings.h : This file holds static values important for other functions called in the program.

*/

#pragma once

using namespace PcapDotNet::Core;

ref class settings_values {
	public:
		static bool captureInfo = false; // do not capture extensive packet data by default
		static System::String^ selectedIP = ""; // IP for pinging function - default is lo
		static PacketDevice^ selectedIface; // selected interface for sniffing functions
		static System::String^ startPort = "1"; // start at port 1 for scanning by default
		static System::String^ endPort = "1024"; // end at port 1024 for scanning by default
		static System::String^ icmpCount = "256"; // ping a destination 256 times by default
		static bool tcpEnabled = false; // used to check for capture of TCP instead of UDP
		static bool udpEnabled = true; // used to check for capture of UDP instead of TCP - default
};