#include "packetInfo.h"

namespace EasySniff {
	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;
	using namespace System::Threading;

	public ref class pingAddressForm : public System::Windows::Forms::Form {
		private: System::Windows::Forms::RichTextBox^ icmpOutputField;
		private: System::ComponentModel::IContainer^ components;
		private: packetInfo^ packetInf = gcnew packetInfo();
		private: System::Windows::Forms::Timer^ pingTimer;
		private: Thread^ t1 = gcnew Thread(gcnew ThreadStart(this, &pingAddressForm::asyncPing));

		public: pingAddressForm(void) {
			InitializeComponent();
			this->t1->IsBackground = true;
		}

		protected: ~pingAddressForm() {
			if (components) {
				delete components;
			}
		}

		private: void asyncPing() {
			try {
				for (int i = 0; i < Convert::ToUInt16(settings_values::icmpCount); i++) { // max 65535 pings, basically infinite - shouldn't need more
					this->icmpOutputField->AppendText("[Echo " + (i + 1) + "] : " + this->packetInf->sendICMPEcho());
					this->icmpOutputField->ScrollToCaret();
				}
				this->icmpOutputField->AppendText("[Status: finished]");
			}
			catch (...) {
				// do nothing
			}
		}

		void InitializeComponent(void) {
			this->components = (gcnew System::ComponentModel::Container());
			this->icmpOutputField = (gcnew System::Windows::Forms::RichTextBox());
			this->pingTimer = (gcnew System::Windows::Forms::Timer(this->components));
			this->SuspendLayout();
			// 
			// icmpOutputField
			// 
			this->icmpOutputField->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(51)));
			this->icmpOutputField->BorderStyle = System::Windows::Forms::BorderStyle::None;
			this->icmpOutputField->Font = (gcnew System::Drawing::Font(L"Consolas", 10));
			this->icmpOutputField->ForeColor = System::Drawing::Color::White;
			this->icmpOutputField->Location = System::Drawing::Point(1, 2);
			this->icmpOutputField->Name = L"icmpOutputField";
			this->icmpOutputField->ReadOnly = true;
			this->icmpOutputField->ScrollBars = System::Windows::Forms::RichTextBoxScrollBars::None;
			this->icmpOutputField->Size = System::Drawing::Size(473, 383);
			this->icmpOutputField->TabIndex = 0;
			this->icmpOutputField->Text = L"Close the window to stop the process.\nEcho statuses are shown below:\n\n";
			// 
			// pingAddressForm
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(6, 13);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(51)));
			this->ClientSize = System::Drawing::Size(471, 384);
			this->Controls->Add(this->icmpOutputField);
			this->FormBorderStyle = System::Windows::Forms::FormBorderStyle::FixedToolWindow;
			this->MaximizeBox = false;
			this->Name = L"pingAddressForm";
			this->Text = L"EasySniff | ICMP Manager";
			this->FormClosing += gcnew System::Windows::Forms::FormClosingEventHandler(this, &pingAddressForm::pingAddressForm_FormClosing);
			this->Load += gcnew System::EventHandler(this, &pingAddressForm::PingAddressForm_Load);
			this->ResumeLayout(false);

		}
		private: System::Void PingAddressForm_Load(System::Object^ sender, System::EventArgs^ e) {
			this->t1->Start();
		}
		private: System::Void pingAddressForm_FormClosing(System::Object^ sender, System::Windows::Forms::FormClosingEventArgs^ e) {
			try {
				this->t1->Abort();
			}
			catch (...) {
				// do nothing
			}
		}
	};
}