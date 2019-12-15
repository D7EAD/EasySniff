#pragma once

#include "packetInfo.h"

namespace EasySniff {
	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;
	using namespace System::Threading;

	public ref class portScanHandler : public System::Windows::Forms::Form {
		private: System::Windows::Forms::RichTextBox^ scanResultOutputField;
		private: System::ComponentModel::IContainer^ components;
		private: packetInfo^ packetInf = gcnew packetInfo();
		private: unsigned int port = 1;
		private: Thread^ t1 = gcnew Thread(gcnew ThreadStart(this, &portScanHandler::asyncPortScan));

		public: portScanHandler(void) {
			InitializeComponent();
			this->t1->IsBackground = true;
		}
			
		protected: ~portScanHandler() {
			if (components) {
				delete components;
			}
		}

		private: void asyncPortScan() {
			try {
				for (this->port = Convert::ToUInt16(settings_values::startPort); this->port <= Convert::ToUInt16(settings_values::endPort); this->port++) {
					this->scanResultOutputField->AppendText(this->packetInf->portScan(this->port));
					this->scanResultOutputField->ScrollToCaret();
				}
				this->scanResultOutputField->AppendText("[Status: finished]");
			}
			catch (...) {
				// do nothing
			}
		}

		void InitializeComponent(void) {
			this->scanResultOutputField = (gcnew System::Windows::Forms::RichTextBox());
			this->SuspendLayout();
			// 
			// scanResultOutputField
			// 
			this->scanResultOutputField->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(51)));
			this->scanResultOutputField->BorderStyle = System::Windows::Forms::BorderStyle::None;
			this->scanResultOutputField->Font = (gcnew System::Drawing::Font(L"Consolas", 10));
			this->scanResultOutputField->ForeColor = System::Drawing::Color::White;
			this->scanResultOutputField->Location = System::Drawing::Point(0, 0);
			this->scanResultOutputField->Margin = System::Windows::Forms::Padding(2, 2, 2, 2);
			this->scanResultOutputField->Name = L"scanResultOutputField";
			this->scanResultOutputField->ReadOnly = true;
			this->scanResultOutputField->ScrollBars = System::Windows::Forms::RichTextBoxScrollBars::None;
			this->scanResultOutputField->Size = System::Drawing::Size(368, 336);
			this->scanResultOutputField->TabIndex = 0;
			this->scanResultOutputField->Text = L"Close the window to stop the process.\nPort statuses are shown below:\n\n";
			// 
			// portScanHandler
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(6, 13);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(51)));
			this->ClientSize = System::Drawing::Size(368, 332);
			this->Controls->Add(this->scanResultOutputField);
			this->ForeColor = System::Drawing::Color::White;
			this->FormBorderStyle = System::Windows::Forms::FormBorderStyle::FixedToolWindow;
			this->Margin = System::Windows::Forms::Padding(2, 2, 2, 2);
			this->MaximizeBox = false;
			this->Name = L"portScanHandler";
			this->Text = L"EasySniff | Scanner";
			this->FormClosing += gcnew System::Windows::Forms::FormClosingEventHandler(this, &portScanHandler::portScanHandler_FormClosing);
			this->Load += gcnew System::EventHandler(this, &portScanHandler::portScanHandler_Load);
			this->ResumeLayout(false);

		}
		private: System::Void portScanHandler_Load(System::Object^ sender, System::EventArgs^ e) {
			this->t1->Start();
		}
		private: System::Void portScanHandler_FormClosing(System::Object^ sender, System::Windows::Forms::FormClosingEventArgs^ e) {
			try {
				this->t1->Abort(); // to prevent it complaining about CreateHandle() and blah blah blah
			}
			catch (...) {
				// do nothing
			}
		}
	};
}