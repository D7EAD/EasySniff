#include "informationHandler.h"

namespace EasySniff {
	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;

	public ref class dnsInformationHandler : public System::Windows::Forms::Form {
	private: System::Windows::Forms::RichTextBox^ dnsInfoOutput;

		private: System::ComponentModel::Container^ components;
	
		public: dnsInformationHandler(void) {
			InitializeComponent();
		}

		protected: ~dnsInformationHandler() {
			if (components) {
				delete components;
			}
		}

		void InitializeComponent(void) {
			this->dnsInfoOutput = (gcnew System::Windows::Forms::RichTextBox());
			this->SuspendLayout();
			// 
			// dnsInfoOutput
			// 
			this->dnsInfoOutput->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(51)));
			this->dnsInfoOutput->BorderStyle = System::Windows::Forms::BorderStyle::None;
			this->dnsInfoOutput->Font = (gcnew System::Drawing::Font(L"Consolas", 10));
			this->dnsInfoOutput->ForeColor = System::Drawing::Color::White;
			this->dnsInfoOutput->Location = System::Drawing::Point(0, 0);
			this->dnsInfoOutput->Margin = System::Windows::Forms::Padding(2);
			this->dnsInfoOutput->Name = L"dnsInfoOutput";
			this->dnsInfoOutput->Size = System::Drawing::Size(438, 236);
			this->dnsInfoOutput->TabIndex = 0;
			this->dnsInfoOutput->Text = L"DNS info will appear below:";
			// 
			// dnsInformationHandler
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(6, 13);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(51)));
			this->ClientSize = System::Drawing::Size(440, 233);
			this->Controls->Add(this->dnsInfoOutput);
			this->FormBorderStyle = System::Windows::Forms::FormBorderStyle::FixedToolWindow;
			this->Margin = System::Windows::Forms::Padding(2);
			this->MaximizeBox = false;
			this->Name = L"dnsInformationHandler";
			this->Text = L"EasySniff | DNS Manager";
			this->Load += gcnew System::EventHandler(this, &dnsInformationHandler::dnsInformationHandler_Load);
			this->ResumeLayout(false);

		}
		private: System::Void dnsInformationHandler_Load(System::Object^ sender, System::EventArgs^ e) {
			getDNSInfo(this->dnsInfoOutput, settings_values::selectedIP);
		}
	};
}