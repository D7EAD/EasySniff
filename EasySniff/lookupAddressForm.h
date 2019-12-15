#include "informationHandler.h"

namespace EasySniff {
	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;

	public ref class lookupAddressForm : public System::Windows::Forms::Form {
		private: System::Windows::Forms::RichTextBox^ ipLookupOutputField;
		private: System::Windows::Forms::TextBox^ ipField;
		private: System::ComponentModel::Container^ components;

		public: lookupAddressForm(void) {
			InitializeComponent();
		}

		protected: ~lookupAddressForm() {
			if (components) {
				delete components;
			}
		}

		void InitializeComponent(void) {
			this->ipLookupOutputField = (gcnew System::Windows::Forms::RichTextBox());
			this->ipField = (gcnew System::Windows::Forms::TextBox());
			this->SuspendLayout();
			// 
			// ipLookupOutputField
			// 
			this->ipLookupOutputField->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(51)));
			this->ipLookupOutputField->BorderStyle = System::Windows::Forms::BorderStyle::FixedSingle;
			this->ipLookupOutputField->ForeColor = System::Drawing::Color::White;
			this->ipLookupOutputField->Location = System::Drawing::Point(-2, 24);
			this->ipLookupOutputField->Name = L"ipLookupOutputField";
			this->ipLookupOutputField->ReadOnly = true;
			this->ipLookupOutputField->Size = System::Drawing::Size(426, 203);
			this->ipLookupOutputField->TabIndex = 1;
			this->ipLookupOutputField->Text = L"";
			// 
			// ipField
			// 
			this->ipField->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(70)));
			this->ipField->BorderStyle = System::Windows::Forms::BorderStyle::None;
			this->ipField->ForeColor = System::Drawing::Color::White;
			this->ipField->Location = System::Drawing::Point(-2, 2);
			this->ipField->Name = L"ipField";
			this->ipField->Size = System::Drawing::Size(426, 16);
			this->ipField->TabIndex = 0;
			this->ipField->Text = L"Enter IP Address...";
			this->ipField->KeyPress += gcnew System::Windows::Forms::KeyPressEventHandler(this, &lookupAddressForm::IpField_KeyPress);
			// 
			// lookupAddressForm
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(7, 15);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(70)));
			this->ClientSize = System::Drawing::Size(422, 211);
			this->Controls->Add(this->ipField);
			this->Controls->Add(this->ipLookupOutputField);
			this->Font = (gcnew System::Drawing::Font(L"Consolas", 10));
			this->ForeColor = System::Drawing::Color::White;
			this->FormBorderStyle = System::Windows::Forms::FormBorderStyle::FixedToolWindow;
			this->MaximizeBox = false;
			this->Name = L"lookupAddressForm";
			this->Text = L"EasySniff | IP Lookup";
			this->ResumeLayout(false);
			this->PerformLayout();

		}
		private: System::Void IpField_KeyPress(System::Object^ sender, System::Windows::Forms::KeyPressEventArgs^ e) {
			if (e->KeyChar == static_cast<char>(Keys::Return)) {
				lookupAddress(this->ipLookupOutputField, this->ipField->Text);
			}
		}
	};
}
