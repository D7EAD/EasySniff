/*

	devices.h : Handles the fetching and indexing of network interfaces in the interfaceList for
				interface selection.

*/

using namespace System;
using namespace System::Windows::Forms;
using namespace System::Collections::Generic;
using namespace PcapDotNet::Core;

void getDevices(ComboBox^ %comboBox) {
	IList<LivePacketDevice^>^ deviceList = LivePacketDevice::AllLocalMachine;
	if (deviceList->Count == 0) {
		MessageBox::Show("No interfaces found! Sniffing disabled!", "Error");
	}
	else {
		int i = 0;
		array<System::Object^>^ objects = gcnew array<System::Object^>(deviceList->Count);
		for each (auto device in deviceList) {
			objects[i] = device->Description + " | " + device->Name;
			i = i + 1;
		}
		comboBox->Items->AddRange(objects);
	}
}