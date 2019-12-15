/*

	informationHandler.h : This file is used for retrieving the Location and ISP of a captured IP address.
						   It will set the respective values in the packetInfo class of packetInfo.h.

*/

#pragma once

#define ROOT "http://ip-api.com/json/" // super cool api key-free geoipdb :)

using namespace System::Net;
using namespace System::IO;
using namespace Newtonsoft::Json::Linq;

void getISP(System::String^% ispContainer, System::String^% protectedContainer, System::String^ ip) {
	HttpWebRequest^ request = dynamic_cast<HttpWebRequest^>(WebRequest::Create(ROOT + ip));
	request->Method = "GET";
	request->ContentType = "application/json";

	HttpWebResponse^ response = dynamic_cast<HttpWebResponse^>(request->GetResponse());
	Stream^ stream = response->GetResponseStream();
	StreamReader^ reader = gcnew StreamReader(stream);
	System::String^ result = reader->ReadToEnd();
	JObject^ obj = JObject::Parse(result);

	System::String^ isp = obj["isp"]->ToString();
	if (isp->Contains("OVH")) {
		protectedContainer = "Yes : 4Tb/s";
	}
	else if (isp->Contains("Nuclearfallout")) {
		protectedContainer = "Yes : 10-250Gb/s+";
	}
	else if (isp->Contains("Cloudflare")) {
		protectedContainer = "Yes : 30Tb/s";
	}
	else if (isp->Contains("ServerMania")) {
		protectedContainer = "Yes : 1-40Gb/s";
	}
	else if (isp->Contains("Sharktech")) {
		protectedContainer = "Yes : 40-100Gb/s";
	}
	else if (isp->Contains("Interserver")) {
		protectedContainer = "Yes : 20Gb/s";
	}
	else if (isp->Contains("Incapsula")) {
		protectedContainer = "Yes : 6Tb/s";
	}
	else if (isp->Contains("Imperva")) {
		protectedContainer = "Yes : 6Tb/s";
	}
	else {
		protectedContainer = "No";
	}
	ispContainer = isp;
}

void getLocation(System::String^ %locationContainer, System::String^ ip) {
	HttpWebRequest^ request = dynamic_cast<HttpWebRequest^>(WebRequest::Create(ROOT + ip));
	request->Method = "GET";
	request->ContentType = "application/json";

	HttpWebResponse^ response = dynamic_cast<HttpWebResponse^>(request->GetResponse());
	Stream^ stream = response->GetResponseStream();
	StreamReader^ reader = gcnew StreamReader(stream);
	System::String^ result = reader->ReadToEnd();
	JObject^ obj = JObject::Parse(result);

	System::String^ location = obj["countryCode"]->ToString() + ", " + obj["regionName"]->ToString() + ", " + obj["city"]->ToString();
	locationContainer = location;
}

void lookupAddress(RichTextBox^ %textBoxContainer, System::String^ ip) {
	textBoxContainer->Clear();
	HttpWebRequest^ request = dynamic_cast<HttpWebRequest^>(WebRequest::Create(ROOT + ip));
	request->Method = "GET";
	request->ContentType = "application/json";

	HttpWebResponse^ response = dynamic_cast<HttpWebResponse^>(request->GetResponse());
	Stream^ stream = response->GetResponseStream();
	StreamReader^ reader = gcnew StreamReader(stream);
	System::String^ result = reader->ReadToEnd();
	JObject^ obj = JObject::Parse(result);
	if (obj["status"]->ToString() == "fail") {
		textBoxContainer->AppendText("Status: " + obj["status"]->ToString() + "\n");
		textBoxContainer->AppendText("Message: " + obj["message"]->ToString() + "\n");
	}
	else if (obj["status"]->ToString() == "success") {
		textBoxContainer->AppendText("Status: " + obj["status"]->ToString() + "\n");
		textBoxContainer->AppendText("Country: " + obj["country"]->ToString() + "\n");
		textBoxContainer->AppendText("Country Code: " + obj["countryCode"]->ToString() + "\n");
		textBoxContainer->AppendText("Region: " + obj["regionName"]->ToString() + "\n");
		textBoxContainer->AppendText("City: " + obj["city"]->ToString() + "\n");
		textBoxContainer->AppendText("ZIP: " + obj["zip"]->ToString() + "\n");
		textBoxContainer->AppendText("Latitude: " + obj["lat"]->ToString() + "\n");
		textBoxContainer->AppendText("Longitude: " + obj["lon"]->ToString() + "\n");
		textBoxContainer->AppendText("Time Zone: " + obj["timezone"]->ToString() + "\n");
		textBoxContainer->AppendText("ISP: " + obj["isp"]->ToString() + "\n");
		if (obj["org"]->ToString() != "") {
			textBoxContainer->AppendText("ORG: " + obj["org"]->ToString() + "\n");
		}
		textBoxContainer->AppendText("AS: " + obj["as"]->ToString() + "\n");
	}
}