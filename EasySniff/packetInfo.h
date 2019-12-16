/*

	packetInfo.h : This header file handles the retrieval of packets, outlining the [IP, srcPort, and dstPort]
				   Other info such as the ISP and IP Geolocation are handled in the related API header.

				   This header also contains the class definition that holds all packet info, specifically in
				   its data struct. This struct contains all info outlined in the GUI for rows. The class
				   <packetInfo> will be inherited by the class outlined in the API header in order to
				   store API-oriented info in the <data> struct, specifically <isp> and <location>.
*/

#pragma once

#include "settings.h"

using namespace System::Windows::Forms;
using namespace System::Collections::Generic;
using namespace System::Net::NetworkInformation;
using namespace System::Threading;
using namespace System::Net;
using namespace System::Net::Sockets;
using namespace PcapDotNet;
using namespace PcapDotNet::Packets;
using namespace PcapDotNet::Base;
using namespace PcapDotNet::Core;

ref class packetInfo {
	public: // data
		System::String^ ipAddress = "";
		System::String^ srcPort = "";
		System::String^ dstPort = "";
		System::String^ isp = "";
		System::String^ location = "";
		System::String^ protection = "";
		System::String^ extended_Source = "";
		System::String^ extended_Checksum = "";
		System::String^ extended_fragOptions = "";
		System::String^ extended_Payload = "";
	public: List<System::String^>^ ipList = gcnew List<System::String^>;
	public: void getPacketData(); // returns ipAddress, srcPort, and dstPort
	public: System::String^ sendICMPEcho();
	public: System::String^ portScan(unsigned int port);
	public: array<System::String^>^ getExtendedInfo(); // returns extended packet data
	public: array<System::String^>^ getInfo(); // returns a row of data located in <data>
	public: void getInterface(ComboBox^ comboBox);
};
