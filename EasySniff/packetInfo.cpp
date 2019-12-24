#include "packetInfo.h"

void packetInfo::getInterface(ComboBox^ comboBox) {
	try {
		IList<LivePacketDevice^>^ deviceList = LivePacketDevice::AllLocalMachine;
		LivePacketDevice^ chosenInterface;
		for each (auto device in deviceList) {
			if (device->Description + " | " + device->Name == comboBox->Text) { // check device desc + name to prevent duplicate adapter bias
				chosenInterface = device;
			}
		}
		settings_values::selectedIface = chosenInterface;
	}
	catch (...) {
		// do nothing
	}
}

// This is the function that actually sets the values for the class member variables.
// Those variables being ipAddress, srcPort, and dstPort. the other two will be returned 
// by the respective API header function. 
// This function should be called first in a sniffing loop.
void packetInfo::getPacketData() { // comboBox used for selecting interface
	try {
		PacketDevice^ selectedInterface = settings_values::selectedIface;
		PacketCommunicator^ communicator = selectedInterface->Open();
		Packet^ packet;
		PacketCommunicatorReceiveResult packetResults = communicator->ReceivePacket(packet);
		switch (packetResults) {
			case PacketCommunicatorReceiveResult::Ok: {
				if (!packet->Ethernet->IpV4->Source.ToString()->StartsWith("10.") &&
					!packet->Ethernet->IpV4->Source.ToString()->StartsWith("192.168.") &&
					!packet->Ethernet->IpV4->Source.ToString()->StartsWith("0.")) {
					if (settings_values::udpEnabled == true) {
						if (!settings_values::captureInfo) {
							if (packet->Ethernet->IpV4->Source.ToString() != ""
								&& packet->Ethernet->IpV4->Udp->SourcePort.ToString() != ""
								&& packet->Ethernet->IpV4->Udp->DestinationPort.ToString() != "") {
								this->ipAddress = packet->Ethernet->IpV4->Source.ToString();
								this->srcPort = packet->Ethernet->IpV4->Udp->SourcePort.ToString();
								this->dstPort = packet->Ethernet->IpV4->Udp->DestinationPort.ToString();
								break;
							}
						}
						else if (settings_values::captureInfo) {
							if (packet->Ethernet->IpV4->Source.ToString() != ""
								&& packet->Ethernet->IpV4->Udp->SourcePort.ToString() != ""
								&& packet->Ethernet->IpV4->Udp->DestinationPort.ToString() != "") {
								this->ipAddress = packet->Ethernet->IpV4->Source.ToString();
								this->srcPort = packet->Ethernet->IpV4->Udp->SourcePort.ToString();
								this->dstPort = packet->Ethernet->IpV4->Udp->DestinationPort.ToString();
								this->extended_Source = packet->Ethernet->IpV4->Source.ToString()
									+ ":" + packet->Ethernet->IpV4->Udp->SourcePort.ToString()
									+ " -> " + packet->Ethernet->IpV4->Destination.ToString()
									+ ":" + packet->Ethernet->IpV4->Udp->DestinationPort.ToString();
								if (packet->Ethernet->IpV4->Protocol == IpV4::IpV4Protocol::Udp) {
									this->extended_Proto = "UDP";
								}
								else if (packet->Ethernet->IpV4->Protocol == IpV4::IpV4Protocol::Tcp) {
									this->extended_Proto = "TCP";
								}
								this->extended_Checksum = packet->IpV4->HeaderChecksum.ToString();
								this->extended_fragOptions = packet->IpV4->Fragmentation.Options.ToString();
								this->extended_Payload = "Len. " + packet->Ethernet->IpV4->Udp->Payload->Length + ": " + packet->Ethernet->IpV4->Udp->Payload->ToHexadecimalString();
								break;
							}
						}
					}
					else if (settings_values::tcpEnabled == true) {
						if (!settings_values::captureInfo) {
							if (packet->Ethernet->IpV4->Source.ToString() != ""
								&& packet->Ethernet->IpV4->Tcp->SourcePort.ToString() != ""
								&& packet->Ethernet->IpV4->Tcp->DestinationPort.ToString() != "") {
								this->ipAddress = packet->Ethernet->IpV4->Source.ToString();
								this->srcPort = packet->Ethernet->IpV4->Tcp->SourcePort.ToString();
								this->dstPort = packet->Ethernet->IpV4->Tcp->DestinationPort.ToString();
								break;
							}
						}
						else if (settings_values::captureInfo) {
							if (packet->Ethernet->IpV4->Source.ToString() != ""
								&& packet->Ethernet->IpV4->Tcp->SourcePort.ToString() != ""
								&& packet->Ethernet->IpV4->Tcp->DestinationPort.ToString() != "") {
								this->ipAddress = packet->Ethernet->IpV4->Source.ToString();
								this->srcPort = packet->Ethernet->IpV4->Tcp->SourcePort.ToString();
								this->dstPort = packet->Ethernet->IpV4->Tcp->DestinationPort.ToString();
								this->extended_Source = packet->Ethernet->IpV4->Source.ToString()
									+ ":" + packet->Ethernet->IpV4->Tcp->SourcePort.ToString()
									+ " -> " + packet->Ethernet->IpV4->Destination.ToString()
									+ ":" + packet->Ethernet->IpV4->Tcp->DestinationPort.ToString();
								if (packet->Ethernet->IpV4->Protocol == IpV4::IpV4Protocol::Udp) {
									this->extended_Proto = "UDP";
								}
								else if (packet->Ethernet->IpV4->Protocol == IpV4::IpV4Protocol::Tcp) {
									this->extended_Proto = "TCP";
								}
								this->extended_Checksum = packet->IpV4->HeaderChecksum.ToString();
								this->extended_fragOptions = packet->IpV4->Fragmentation.Options.ToString();
								this->extended_Payload = "Len. " + packet->Ethernet->IpV4->Tcp->Payload->Length + ": " + packet->Ethernet->IpV4->Tcp->Payload->ToHexadecimalString();
								break;
							}
						}
					}
				}
			}
		}
	}
	catch (System::NullReferenceException^ e) {
		// do nothing
	}
}

System::String^ packetInfo::sendICMPEcho() {
	PingReply^ pr;
	Ping^ pingObj = gcnew Ping();
	IPAddress^ ip = IPAddress::Parse(settings_values::selectedIP);
	pr = pingObj->Send(ip, 1000);
	switch (pr->Status) {
		case IPStatus::TimedOut: {
			return settings_values::selectedIP + " status: request timed out.\n";
		}
		case IPStatus::Success: {
			return settings_values::selectedIP + " status: replied [" + pr->Buffer->Length + " Bytes, " + pr->RoundtripTime.ToString() + " ms]\n";
		}
		default: {
			return settings_values::selectedIP + " status: " + pr->Status.ToString() + "\n";
		}
	}
}

System::String^ packetInfo::portScan(unsigned int port) { // this function is annoying
	try {
		TcpClient^ tcpSocket = gcnew TcpClient();
		IPAddress^ ip = IPAddress::Parse(settings_values::selectedIP);
		ip = ip->Parse(settings_values::selectedIP);
		System::IAsyncResult^ result = tcpSocket->BeginConnect(ip, port, nullptr, tcpSocket);
		if (result->AsyncWaitHandle->WaitOne(300, false)) {
			try {
				tcpSocket->EndConnect(result);
				return settings_values::selectedIP + ":" + port + " status: [open]\n";
			}
			catch (...) {
				return settings_values::selectedIP + ":" + port + " status: [closed - rejected]\n";
			}
		}
		else {
			return settings_values::selectedIP + ":" + port + " status: [closed - timeout]\n";
		}
	}
	catch (...) {
		// do nothing
	}
}

// Call when creating a new array as array<System::String^>^ being a param.
// This is the last data function that should be called in a sniffing loop
// and will populate an entire row if successful.
array<System::String^>^ packetInfo::getInfo() {
	array<System::String^>^ packetData = gcnew array<System::String^>(6); // alloc size of five as there are only five params in <data>
	packetData[0] = this->ipAddress;
	packetData[1] = this->srcPort;
	packetData[2] = this->dstPort;
	packetData[3] = this->isp;
	packetData[4] = this->location;
	packetData[5] = this->protection;
	return packetData;
}

array<System::String^>^ packetInfo::getExtendedInfo() {
	array<System::String^>^ packetData = gcnew array<System::String^>(5);
	packetData[0] = this->extended_Source;
	packetData[1] = this->extended_Proto;
	packetData[2] = this->extended_Checksum;
	packetData[3] = this->extended_fragOptions;
	packetData[4] = this->extended_Payload;
	return packetData;
}