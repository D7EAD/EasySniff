﻿/*

	main_form.h : The main form for EasySniff. It includes the sniffer and the entry points for other functions.
				  Functions such as ICMP Manager, IP Lookup, and Data Manager.

	TODO:
		Add key shortcuts for sniffing and clearing.
*/

#pragma once

#include "devices.h"
#include "packetInfo.h"
#include "informationHandler.h"
#include "lookupAddressForm.h"
#include "pingAddressForm.h"
#include "portScanHandler.h"

enum PAGES {
	PAGE_MAIN,
	PAGE_DATA
};

namespace EasySniff {
	using namespace System;
	using namespace System::Windows;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;
	using namespace System::Threading;

	public ref class main_form : public System::Windows::Forms::Form {
		private: System::Windows::Forms::Button^ sniffButton;
		private: System::Windows::Forms::Label^ namePanel;
		private: System::Windows::Forms::Label^ horizontalBackPanel;
		private: System::Windows::Forms::DataGridView^ dataGrid;
		private: System::ComponentModel::IContainer^ components;
		private: System::Windows::Forms::ComboBox^ interfaceList;
		private: System::Windows::Forms::Button^ clearRowsButton;
		private: packetInfo^ packetInf;
		private: System::Windows::Forms::Label^ bottomPanel;
		private: System::Windows::Forms::TextBox^ sniffStatusField;
		private: System::Windows::Forms::Button^ settingsButton;
		private: System::Windows::Forms::Button^ backToSnifferButton;
		private: System::Windows::Forms::Button^ settingsSaveButton;
		private: System::Windows::Forms::TextBox^ interfaceStatusField;
		private: System::Windows::Forms::Label^ saveResultsDialog;
		private: System::Windows::Forms::TextBox^ rowCount;
		private: System::Windows::Forms::DataGridViewTextBoxColumn^ IP;
		private: System::Windows::Forms::DataGridViewTextBoxColumn^ srcPort;
		private: System::Windows::Forms::DataGridViewTextBoxColumn^ dstPort;
		private: System::Windows::Forms::DataGridViewTextBoxColumn^ ISP;
		private: System::Windows::Forms::DataGridViewTextBoxColumn^ Location;
		private: System::Windows::Forms::DataGridViewTextBoxColumn^ Protected;
		private: System::Windows::Forms::Button^ toolsButton;
		private: System::Windows::Forms::Button^ lookupSpecificIPButton;
		private: System::Windows::Forms::Button^ exportButton;
		private: System::Windows::Forms::DataGridView^ packetInfoDataGrid;
		private: System::Windows::Forms::Button^ packetDataButton;
		private: System::Windows::Forms::CheckBox^ checkBox_ShowPacketData;
		private: System::Windows::Forms::DataGridViewTextBoxColumn^ IPandPorts;
		private: System::Windows::Forms::DataGridViewTextBoxColumn^ checksum;
		private: System::Windows::Forms::DataGridViewTextBoxColumn^ fragOptions;
		private: System::Windows::Forms::DataGridViewTextBoxColumn^ Payload;
		private: bool sniffing = false;
		private: System::Windows::Forms::Button^ exportButton_PacketData;
		private: int selectedPage = PAGE_MAIN;
		private: System::Windows::Forms::Label^ portList_Label;
		private: System::Windows::Forms::ComboBox^ portList;
		private: System::Windows::Forms::Label^ echoCount_Label;
		private: System::Windows::Forms::ComboBox^ echoCount;
		private: bool portScanKeyDown = false;
		private: bool threadStopped = false;
		private: System::Windows::Forms::TextBox^ packetDataGridRowCount;
		private: Thread^ t1 = gcnew Thread(gcnew ThreadStart(this, &main_form::asyncSniff));

		public: main_form(void) {
			InitializeComponent();
			this->packetInf = (gcnew packetInfo());
			t1->IsBackground = true;
		}

		protected: ~main_form() {
			if (components) {
				delete components;
			}
		}

		private: void asyncSniff() {
			// below are functions related to sniffing
			// timer only set off when sniffing enabled
			while (this->sniffing) {
				try {
					this->packetInf->getInterface(this->interfaceList);
					this->packetInf->getPacketData();
					if (!settings_values::captureInfo) {
						if (!this->packetInf->ipList->Contains(this->packetInf->getInfo()[0])) {
							getISP(this->packetInf->isp, this->packetInf->protection, this->packetInf->getInfo()[0]);
							if (!this->packetInf->isp->Contains("Akamai") && !this->packetInf->isp->Contains("Microsoft")
								&& !this->packetInf->isp->Contains("Amazon")) {
								getLocation(this->packetInf->location, this->packetInf->getInfo()[0]);
								this->dataGrid->Rows->Add(this->packetInf->getInfo());
								this->packetInf->ipList->Add(this->packetInf->getInfo()[0]);
							}
						}
					}
					else if (settings_values::captureInfo) {
						if (this->packetInf->getExtendedInfo()[0] != "" && this->packetInf->getExtendedInfo()[1] != ""
							&& this->packetInf->getExtendedInfo()[2] != "" && this->packetInf->getExtendedInfo()[3] != "") {
							this->packetInfoDataGrid->Rows->Add(this->packetInf->getExtendedInfo());
						}
						if (!this->packetInf->ipList->Contains(this->packetInf->getInfo()[0])) {
							getISP(this->packetInf->isp, this->packetInf->protection, this->packetInf->getInfo()[0]);
							if (!this->packetInf->isp->Contains("Akamai") && !this->packetInf->isp->Contains("Microsoft")
								&& !this->packetInf->isp->Contains("Amazon")) {
								getLocation(this->packetInf->location, this->packetInf->getInfo()[0]);
								this->dataGrid->Rows->Add(this->packetInf->getInfo());
								this->packetInf->ipList->Add(this->packetInf->getInfo()[0]);
							}
						}
					}
				}
				catch (...) {
					// do nothing
				}
				Thread::Sleep(10);
			}
		}

		void InitializeComponent(void) {
			System::Windows::Forms::DataGridViewCellStyle^ dataGridViewCellStyle1 = (gcnew System::Windows::Forms::DataGridViewCellStyle());
			System::Windows::Forms::DataGridViewCellStyle^ dataGridViewCellStyle2 = (gcnew System::Windows::Forms::DataGridViewCellStyle());
			System::Windows::Forms::DataGridViewCellStyle^ dataGridViewCellStyle3 = (gcnew System::Windows::Forms::DataGridViewCellStyle());
			System::Windows::Forms::DataGridViewCellStyle^ dataGridViewCellStyle4 = (gcnew System::Windows::Forms::DataGridViewCellStyle());
			System::Windows::Forms::DataGridViewCellStyle^ dataGridViewCellStyle5 = (gcnew System::Windows::Forms::DataGridViewCellStyle());
			System::Windows::Forms::DataGridViewCellStyle^ dataGridViewCellStyle6 = (gcnew System::Windows::Forms::DataGridViewCellStyle());
			System::ComponentModel::ComponentResourceManager^ resources = (gcnew System::ComponentModel::ComponentResourceManager(main_form::typeid));
			this->sniffButton = (gcnew System::Windows::Forms::Button());
			this->namePanel = (gcnew System::Windows::Forms::Label());
			this->horizontalBackPanel = (gcnew System::Windows::Forms::Label());
			this->dataGrid = (gcnew System::Windows::Forms::DataGridView());
			this->IP = (gcnew System::Windows::Forms::DataGridViewTextBoxColumn());
			this->srcPort = (gcnew System::Windows::Forms::DataGridViewTextBoxColumn());
			this->dstPort = (gcnew System::Windows::Forms::DataGridViewTextBoxColumn());
			this->ISP = (gcnew System::Windows::Forms::DataGridViewTextBoxColumn());
			this->Location = (gcnew System::Windows::Forms::DataGridViewTextBoxColumn());
			this->Protected = (gcnew System::Windows::Forms::DataGridViewTextBoxColumn());
			this->interfaceList = (gcnew System::Windows::Forms::ComboBox());
			this->clearRowsButton = (gcnew System::Windows::Forms::Button());
			this->bottomPanel = (gcnew System::Windows::Forms::Label());
			this->sniffStatusField = (gcnew System::Windows::Forms::TextBox());
			this->settingsButton = (gcnew System::Windows::Forms::Button());
			this->backToSnifferButton = (gcnew System::Windows::Forms::Button());
			this->settingsSaveButton = (gcnew System::Windows::Forms::Button());
			this->interfaceStatusField = (gcnew System::Windows::Forms::TextBox());
			this->saveResultsDialog = (gcnew System::Windows::Forms::Label());
			this->rowCount = (gcnew System::Windows::Forms::TextBox());
			this->toolsButton = (gcnew System::Windows::Forms::Button());
			this->lookupSpecificIPButton = (gcnew System::Windows::Forms::Button());
			this->exportButton = (gcnew System::Windows::Forms::Button());
			this->packetInfoDataGrid = (gcnew System::Windows::Forms::DataGridView());
			this->IPandPorts = (gcnew System::Windows::Forms::DataGridViewTextBoxColumn());
			this->checksum = (gcnew System::Windows::Forms::DataGridViewTextBoxColumn());
			this->fragOptions = (gcnew System::Windows::Forms::DataGridViewTextBoxColumn());
			this->Payload = (gcnew System::Windows::Forms::DataGridViewTextBoxColumn());
			this->packetDataButton = (gcnew System::Windows::Forms::Button());
			this->checkBox_ShowPacketData = (gcnew System::Windows::Forms::CheckBox());
			this->exportButton_PacketData = (gcnew System::Windows::Forms::Button());
			this->portList_Label = (gcnew System::Windows::Forms::Label());
			this->portList = (gcnew System::Windows::Forms::ComboBox());
			this->echoCount_Label = (gcnew System::Windows::Forms::Label());
			this->echoCount = (gcnew System::Windows::Forms::ComboBox());
			this->packetDataGridRowCount = (gcnew System::Windows::Forms::TextBox());
			(cli::safe_cast<System::ComponentModel::ISupportInitialize^>(this->dataGrid))->BeginInit();
			(cli::safe_cast<System::ComponentModel::ISupportInitialize^>(this->packetInfoDataGrid))->BeginInit();
			this->SuspendLayout();
			// 
			// sniffButton
			// 
			this->sniffButton->FlatStyle = System::Windows::Forms::FlatStyle::Popup;
			this->sniffButton->Font = (gcnew System::Drawing::Font(L"Consolas", 11));
			this->sniffButton->ForeColor = System::Drawing::Color::White;
			this->sniffButton->Location = System::Drawing::Point(800, 9);
			this->sniffButton->Name = L"sniffButton";
			this->sniffButton->Size = System::Drawing::Size(103, 61);
			this->sniffButton->TabIndex = 0;
			this->sniffButton->Text = L"Sniff";
			this->sniffButton->UseVisualStyleBackColor = true;
			this->sniffButton->Click += gcnew System::EventHandler(this, &main_form::sniffButton_Click);
			// 
			// namePanel
			// 
			this->namePanel->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(70)));
			this->namePanel->Font = (gcnew System::Drawing::Font(L"Consolas", 35));
			this->namePanel->ForeColor = System::Drawing::Color::Magenta;
			this->namePanel->Location = System::Drawing::Point(12, 12);
			this->namePanel->Name = L"namePanel";
			this->namePanel->Size = System::Drawing::Size(279, 61);
			this->namePanel->TabIndex = 2;
			this->namePanel->Text = L"E̵a̵s̸y̴S̸n̷i̸f̵f";
			// 
			// horizontalBackPanel
			// 
			this->horizontalBackPanel->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(70)));
			this->horizontalBackPanel->Location = System::Drawing::Point(-4, 0);
			this->horizontalBackPanel->Name = L"horizontalBackPanel";
			this->horizontalBackPanel->Size = System::Drawing::Size(1128, 90);
			this->horizontalBackPanel->TabIndex = 3;
			// 
			// dataGrid
			// 
			this->dataGrid->AllowUserToAddRows = false;
			this->dataGrid->AllowUserToDeleteRows = false;
			this->dataGrid->AllowUserToResizeColumns = false;
			this->dataGrid->AllowUserToResizeRows = false;
			this->dataGrid->BackgroundColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(51)));
			this->dataGrid->BorderStyle = System::Windows::Forms::BorderStyle::None;
			this->dataGrid->CellBorderStyle = System::Windows::Forms::DataGridViewCellBorderStyle::None;
			this->dataGrid->ClipboardCopyMode = System::Windows::Forms::DataGridViewClipboardCopyMode::EnableAlwaysIncludeHeaderText;
			dataGridViewCellStyle1->Alignment = System::Windows::Forms::DataGridViewContentAlignment::MiddleLeft;
			dataGridViewCellStyle1->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(51)));
			dataGridViewCellStyle1->Font = (gcnew System::Drawing::Font(L"Consolas", 10));
			dataGridViewCellStyle1->SelectionBackColor = System::Drawing::SystemColors::Highlight;
			dataGridViewCellStyle1->SelectionForeColor = System::Drawing::SystemColors::HighlightText;
			dataGridViewCellStyle1->WrapMode = System::Windows::Forms::DataGridViewTriState::True;
			this->dataGrid->ColumnHeadersDefaultCellStyle = dataGridViewCellStyle1;
			this->dataGrid->ColumnHeadersHeightSizeMode = System::Windows::Forms::DataGridViewColumnHeadersHeightSizeMode::AutoSize;
			this->dataGrid->Columns->AddRange(gcnew cli::array< System::Windows::Forms::DataGridViewColumn^  >(6) {
				this->IP, this->srcPort,
					this->dstPort, this->ISP, this->Location, this->Protected
			});
			dataGridViewCellStyle2->Alignment = System::Windows::Forms::DataGridViewContentAlignment::MiddleLeft;
			dataGridViewCellStyle2->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(51)));
			dataGridViewCellStyle2->Font = (gcnew System::Drawing::Font(L"Consolas", 10));
			dataGridViewCellStyle2->ForeColor = System::Drawing::Color::White;
			dataGridViewCellStyle2->SelectionBackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(51)));
			dataGridViewCellStyle2->SelectionForeColor = System::Drawing::SystemColors::HighlightText;
			dataGridViewCellStyle2->WrapMode = System::Windows::Forms::DataGridViewTriState::False;
			this->dataGrid->DefaultCellStyle = dataGridViewCellStyle2;
			this->dataGrid->EnableHeadersVisualStyles = false;
			this->dataGrid->GridColor = System::Drawing::Color::White;
			this->dataGrid->Location = System::Drawing::Point(-1, 88);
			this->dataGrid->Name = L"dataGrid";
			this->dataGrid->ReadOnly = true;
			this->dataGrid->RowHeadersBorderStyle = System::Windows::Forms::DataGridViewHeaderBorderStyle::None;
			this->dataGrid->RowHeadersVisible = false;
			this->dataGrid->RowHeadersWidth = 51;
			this->dataGrid->RowHeadersWidthSizeMode = System::Windows::Forms::DataGridViewRowHeadersWidthSizeMode::DisableResizing;
			dataGridViewCellStyle3->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(51)));
			dataGridViewCellStyle3->ForeColor = System::Drawing::Color::White;
			dataGridViewCellStyle3->SelectionBackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(51)));
			this->dataGrid->RowsDefaultCellStyle = dataGridViewCellStyle3;
			this->dataGrid->RowTemplate->Height = 24;
			this->dataGrid->ScrollBars = System::Windows::Forms::ScrollBars::None;
			this->dataGrid->ShowCellErrors = false;
			this->dataGrid->ShowCellToolTips = false;
			this->dataGrid->ShowEditingIcon = false;
			this->dataGrid->ShowRowErrors = false;
			this->dataGrid->Size = System::Drawing::Size(1121, 383);
			this->dataGrid->TabIndex = 4;
			this->dataGrid->CellMouseClick += gcnew System::Windows::Forms::DataGridViewCellMouseEventHandler(this, &main_form::copyCellContent);
			this->dataGrid->CellMouseDoubleClick += gcnew System::Windows::Forms::DataGridViewCellMouseEventHandler(this, &main_form::dataGrid_pingAddress);
			this->dataGrid->RowsAdded += gcnew System::Windows::Forms::DataGridViewRowsAddedEventHandler(this, &main_form::dataGrid_RowsAdded);
			this->dataGrid->KeyDown += gcnew System::Windows::Forms::KeyEventHandler(this, &main_form::dataGrid_KeyDown);
			// 
			// IP
			// 
			this->IP->HeaderText = L"IP:";
			this->IP->MinimumWidth = 6;
			this->IP->Name = L"IP";
			this->IP->ReadOnly = true;
			this->IP->Width = 185;
			// 
			// srcPort
			// 
			this->srcPort->HeaderText = L"Src. Port:";
			this->srcPort->MinimumWidth = 6;
			this->srcPort->Name = L"srcPort";
			this->srcPort->ReadOnly = true;
			this->srcPort->Width = 120;
			// 
			// dstPort
			// 
			this->dstPort->HeaderText = L"Dest. Port:";
			this->dstPort->MinimumWidth = 6;
			this->dstPort->Name = L"dstPort";
			this->dstPort->ReadOnly = true;
			this->dstPort->Width = 135;
			// 
			// ISP
			// 
			this->ISP->HeaderText = L"ISP:";
			this->ISP->MinimumWidth = 6;
			this->ISP->Name = L"ISP";
			this->ISP->ReadOnly = true;
			this->ISP->Width = 200;
			// 
			// Location
			// 
			this->Location->HeaderText = L"Location:";
			this->Location->MinimumWidth = 6;
			this->Location->Name = L"Location";
			this->Location->ReadOnly = true;
			this->Location->Width = 350;
			// 
			// Protected
			// 
			this->Protected->HeaderText = L"Protected:";
			this->Protected->MinimumWidth = 6;
			this->Protected->Name = L"Protected";
			this->Protected->ReadOnly = true;
			this->Protected->Width = 130;
			// 
			// interfaceList
			// 
			this->interfaceList->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(70)));
			this->interfaceList->DropDownStyle = System::Windows::Forms::ComboBoxStyle::DropDownList;
			this->interfaceList->FlatStyle = System::Windows::Forms::FlatStyle::Flat;
			this->interfaceList->ForeColor = System::Drawing::Color::White;
			this->interfaceList->FormattingEnabled = true;
			this->interfaceList->Location = System::Drawing::Point(297, 29);
			this->interfaceList->MaxDropDownItems = 25;
			this->interfaceList->Name = L"interfaceList";
			this->interfaceList->Size = System::Drawing::Size(479, 28);
			this->interfaceList->TabIndex = 0;
			this->interfaceList->SelectedValueChanged += gcnew System::EventHandler(this, &main_form::interfaceList_SelectedValueChanged);
			// 
			// clearRowsButton
			// 
			this->clearRowsButton->FlatStyle = System::Windows::Forms::FlatStyle::Popup;
			this->clearRowsButton->Font = (gcnew System::Drawing::Font(L"Consolas", 11));
			this->clearRowsButton->ForeColor = System::Drawing::Color::White;
			this->clearRowsButton->Location = System::Drawing::Point(902, 9);
			this->clearRowsButton->Name = L"clearRowsButton";
			this->clearRowsButton->Size = System::Drawing::Size(103, 61);
			this->clearRowsButton->TabIndex = 6;
			this->clearRowsButton->Text = L"Clear";
			this->clearRowsButton->UseVisualStyleBackColor = true;
			this->clearRowsButton->Click += gcnew System::EventHandler(this, &main_form::clearRowsButton_Click);
			// 
			// bottomPanel
			// 
			this->bottomPanel->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(70)));
			this->bottomPanel->Location = System::Drawing::Point(-4, 478);
			this->bottomPanel->Name = L"bottomPanel";
			this->bottomPanel->Size = System::Drawing::Size(1128, 27);
			this->bottomPanel->TabIndex = 7;
			// 
			// sniffStatusField
			// 
			this->sniffStatusField->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(70)));
			this->sniffStatusField->BorderStyle = System::Windows::Forms::BorderStyle::None;
			this->sniffStatusField->ForeColor = System::Drawing::Color::White;
			this->sniffStatusField->Location = System::Drawing::Point(12, 485);
			this->sniffStatusField->Name = L"sniffStatusField";
			this->sniffStatusField->ReadOnly = true;
			this->sniffStatusField->Size = System::Drawing::Size(135, 20);
			this->sniffStatusField->TabIndex = 8;
			this->sniffStatusField->Text = L"Sniffing: off";
			// 
			// settingsButton
			// 
			this->settingsButton->FlatStyle = System::Windows::Forms::FlatStyle::Popup;
			this->settingsButton->Font = (gcnew System::Drawing::Font(L"Consolas", 9));
			this->settingsButton->ForeColor = System::Drawing::Color::White;
			this->settingsButton->Location = System::Drawing::Point(1021, 478);
			this->settingsButton->Name = L"settingsButton";
			this->settingsButton->Size = System::Drawing::Size(103, 30);
			this->settingsButton->TabIndex = 9;
			this->settingsButton->Text = L"Settings";
			this->settingsButton->UseVisualStyleBackColor = true;
			this->settingsButton->Click += gcnew System::EventHandler(this, &main_form::settingsButton_Click);
			// 
			// backToSnifferButton
			// 
			this->backToSnifferButton->Enabled = false;
			this->backToSnifferButton->FlatStyle = System::Windows::Forms::FlatStyle::Popup;
			this->backToSnifferButton->Font = (gcnew System::Drawing::Font(L"Consolas", 9));
			this->backToSnifferButton->ForeColor = System::Drawing::Color::White;
			this->backToSnifferButton->Location = System::Drawing::Point(1021, 478);
			this->backToSnifferButton->Name = L"backToSnifferButton";
			this->backToSnifferButton->Size = System::Drawing::Size(103, 30);
			this->backToSnifferButton->TabIndex = 10;
			this->backToSnifferButton->Text = L"Sniffer";
			this->backToSnifferButton->UseVisualStyleBackColor = true;
			this->backToSnifferButton->Visible = false;
			this->backToSnifferButton->Click += gcnew System::EventHandler(this, &main_form::backToSnifferButton_Click);
			// 
			// settingsSaveButton
			// 
			this->settingsSaveButton->Enabled = false;
			this->settingsSaveButton->FlatStyle = System::Windows::Forms::FlatStyle::Popup;
			this->settingsSaveButton->Font = (gcnew System::Drawing::Font(L"Consolas", 9));
			this->settingsSaveButton->ForeColor = System::Drawing::Color::White;
			this->settingsSaveButton->Location = System::Drawing::Point(912, 478);
			this->settingsSaveButton->Name = L"settingsSaveButton";
			this->settingsSaveButton->Size = System::Drawing::Size(103, 30);
			this->settingsSaveButton->TabIndex = 11;
			this->settingsSaveButton->Text = L"Save";
			this->settingsSaveButton->UseVisualStyleBackColor = true;
			this->settingsSaveButton->Visible = false;
			this->settingsSaveButton->Click += gcnew System::EventHandler(this, &main_form::settingsSaveButton_Click);
			// 
			// interfaceStatusField
			// 
			this->interfaceStatusField->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(70)));
			this->interfaceStatusField->BorderStyle = System::Windows::Forms::BorderStyle::None;
			this->interfaceStatusField->ForeColor = System::Drawing::Color::White;
			this->interfaceStatusField->Location = System::Drawing::Point(140, 485);
			this->interfaceStatusField->Name = L"interfaceStatusField";
			this->interfaceStatusField->ReadOnly = true;
			this->interfaceStatusField->Size = System::Drawing::Size(980, 20);
			this->interfaceStatusField->TabIndex = 15;
			this->interfaceStatusField->Text = L"Interface: none";
			// 
			// saveResultsDialog
			// 
			this->saveResultsDialog->Enabled = false;
			this->saveResultsDialog->ForeColor = System::Drawing::Color::White;
			this->saveResultsDialog->Location = System::Drawing::Point(698, 107);
			this->saveResultsDialog->Name = L"saveResultsDialog";
			this->saveResultsDialog->Size = System::Drawing::Size(426, 283);
			this->saveResultsDialog->TabIndex = 16;
			this->saveResultsDialog->Visible = false;
			// 
			// rowCount
			// 
			this->rowCount->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(70)));
			this->rowCount->BorderStyle = System::Windows::Forms::BorderStyle::None;
			this->rowCount->Font = (gcnew System::Drawing::Font(L"Consolas", 11));
			this->rowCount->ForeColor = System::Drawing::Color::White;
			this->rowCount->Location = System::Drawing::Point(297, 61);
			this->rowCount->Name = L"rowCount";
			this->rowCount->ReadOnly = true;
			this->rowCount->Size = System::Drawing::Size(135, 22);
			this->rowCount->TabIndex = 17;
			this->rowCount->Text = L"Rows: 0";
			// 
			// toolsButton
			// 
			this->toolsButton->FlatStyle = System::Windows::Forms::FlatStyle::Popup;
			this->toolsButton->Font = (gcnew System::Drawing::Font(L"Consolas", 11));
			this->toolsButton->ForeColor = System::Drawing::Color::White;
			this->toolsButton->Location = System::Drawing::Point(1000, 9);
			this->toolsButton->Name = L"toolsButton";
			this->toolsButton->Size = System::Drawing::Size(103, 61);
			this->toolsButton->TabIndex = 18;
			this->toolsButton->Text = L"Tools";
			this->toolsButton->UseVisualStyleBackColor = true;
			this->toolsButton->Click += gcnew System::EventHandler(this, &main_form::ToolsButton_Click);
			// 
			// lookupSpecificIPButton
			// 
			this->lookupSpecificIPButton->Enabled = false;
			this->lookupSpecificIPButton->FlatStyle = System::Windows::Forms::FlatStyle::Popup;
			this->lookupSpecificIPButton->Font = (gcnew System::Drawing::Font(L"Consolas", 11));
			this->lookupSpecificIPButton->ForeColor = System::Drawing::Color::White;
			this->lookupSpecificIPButton->Location = System::Drawing::Point(22, 107);
			this->lookupSpecificIPButton->Name = L"lookupSpecificIPButton";
			this->lookupSpecificIPButton->Size = System::Drawing::Size(243, 37);
			this->lookupSpecificIPButton->TabIndex = 19;
			this->lookupSpecificIPButton->Text = L"Lookup a Specific IP";
			this->lookupSpecificIPButton->UseVisualStyleBackColor = true;
			this->lookupSpecificIPButton->Visible = false;
			this->lookupSpecificIPButton->Click += gcnew System::EventHandler(this, &main_form::LookupSpecificIPButton_Click);
			// 
			// exportButton
			// 
			this->exportButton->Enabled = false;
			this->exportButton->FlatStyle = System::Windows::Forms::FlatStyle::Popup;
			this->exportButton->Font = (gcnew System::Drawing::Font(L"Consolas", 11));
			this->exportButton->ForeColor = System::Drawing::Color::White;
			this->exportButton->Location = System::Drawing::Point(22, 150);
			this->exportButton->Name = L"exportButton";
			this->exportButton->Size = System::Drawing::Size(243, 37);
			this->exportButton->TabIndex = 20;
			this->exportButton->Text = L"Export Row IP Data";
			this->exportButton->UseVisualStyleBackColor = true;
			this->exportButton->Visible = false;
			this->exportButton->Click += gcnew System::EventHandler(this, &main_form::ExportButton_Click);
			// 
			// packetInfoDataGrid
			// 
			this->packetInfoDataGrid->AllowUserToAddRows = false;
			this->packetInfoDataGrid->AllowUserToDeleteRows = false;
			this->packetInfoDataGrid->AllowUserToResizeColumns = false;
			this->packetInfoDataGrid->AllowUserToResizeRows = false;
			this->packetInfoDataGrid->BackgroundColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(51)));
			this->packetInfoDataGrid->BorderStyle = System::Windows::Forms::BorderStyle::None;
			this->packetInfoDataGrid->CellBorderStyle = System::Windows::Forms::DataGridViewCellBorderStyle::None;
			this->packetInfoDataGrid->ClipboardCopyMode = System::Windows::Forms::DataGridViewClipboardCopyMode::EnableAlwaysIncludeHeaderText;
			dataGridViewCellStyle4->Alignment = System::Windows::Forms::DataGridViewContentAlignment::MiddleLeft;
			dataGridViewCellStyle4->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(51)));
			dataGridViewCellStyle4->Font = (gcnew System::Drawing::Font(L"Consolas", 8));
			dataGridViewCellStyle4->SelectionBackColor = System::Drawing::SystemColors::Highlight;
			dataGridViewCellStyle4->SelectionForeColor = System::Drawing::SystemColors::HighlightText;
			dataGridViewCellStyle4->WrapMode = System::Windows::Forms::DataGridViewTriState::True;
			this->packetInfoDataGrid->ColumnHeadersDefaultCellStyle = dataGridViewCellStyle4;
			this->packetInfoDataGrid->ColumnHeadersHeightSizeMode = System::Windows::Forms::DataGridViewColumnHeadersHeightSizeMode::AutoSize;
			this->packetInfoDataGrid->Columns->AddRange(gcnew cli::array< System::Windows::Forms::DataGridViewColumn^  >(4) {
				this->IPandPorts,
					this->checksum, this->fragOptions, this->Payload
			});
			dataGridViewCellStyle5->Alignment = System::Windows::Forms::DataGridViewContentAlignment::MiddleLeft;
			dataGridViewCellStyle5->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(51)));
			dataGridViewCellStyle5->Font = (gcnew System::Drawing::Font(L"Consolas", 8));
			dataGridViewCellStyle5->ForeColor = System::Drawing::Color::White;
			dataGridViewCellStyle5->SelectionBackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(51)));
			dataGridViewCellStyle5->SelectionForeColor = System::Drawing::SystemColors::HighlightText;
			dataGridViewCellStyle5->WrapMode = System::Windows::Forms::DataGridViewTriState::False;
			this->packetInfoDataGrid->DefaultCellStyle = dataGridViewCellStyle5;
			this->packetInfoDataGrid->Enabled = false;
			this->packetInfoDataGrid->EnableHeadersVisualStyles = false;
			this->packetInfoDataGrid->Font = (gcnew System::Drawing::Font(L"Consolas", 8));
			this->packetInfoDataGrid->GridColor = System::Drawing::Color::White;
			this->packetInfoDataGrid->Location = System::Drawing::Point(-1, 88);
			this->packetInfoDataGrid->Name = L"packetInfoDataGrid";
			this->packetInfoDataGrid->ReadOnly = true;
			this->packetInfoDataGrid->RowHeadersBorderStyle = System::Windows::Forms::DataGridViewHeaderBorderStyle::None;
			this->packetInfoDataGrid->RowHeadersVisible = false;
			this->packetInfoDataGrid->RowHeadersWidth = 51;
			this->packetInfoDataGrid->RowHeadersWidthSizeMode = System::Windows::Forms::DataGridViewRowHeadersWidthSizeMode::DisableResizing;
			dataGridViewCellStyle6->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(51)));
			dataGridViewCellStyle6->ForeColor = System::Drawing::Color::White;
			dataGridViewCellStyle6->SelectionBackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(51)));
			this->packetInfoDataGrid->RowsDefaultCellStyle = dataGridViewCellStyle6;
			this->packetInfoDataGrid->RowTemplate->Height = 24;
			this->packetInfoDataGrid->ScrollBars = System::Windows::Forms::ScrollBars::None;
			this->packetInfoDataGrid->ShowCellErrors = false;
			this->packetInfoDataGrid->ShowCellToolTips = false;
			this->packetInfoDataGrid->ShowEditingIcon = false;
			this->packetInfoDataGrid->ShowRowErrors = false;
			this->packetInfoDataGrid->Size = System::Drawing::Size(1121, 388);
			this->packetInfoDataGrid->TabIndex = 22;
			this->packetInfoDataGrid->Visible = false;
			this->packetInfoDataGrid->CellMouseClick += gcnew System::Windows::Forms::DataGridViewCellMouseEventHandler(this, &main_form::packetInfoDataGrid_CellMouseClick);
			this->packetInfoDataGrid->RowsAdded += gcnew System::Windows::Forms::DataGridViewRowsAddedEventHandler(this, &main_form::packetInfoDataGrid_RowsAdded);
			this->packetInfoDataGrid->KeyDown += gcnew System::Windows::Forms::KeyEventHandler(this, &main_form::packetInfoDataGrid_KeyDown);
			// 
			// IPandPorts
			// 
			this->IPandPorts->HeaderText = L"Source";
			this->IPandPorts->MinimumWidth = 6;
			this->IPandPorts->Name = L"IPandPorts";
			this->IPandPorts->ReadOnly = true;
			this->IPandPorts->Width = 250;
			// 
			// checksum
			// 
			this->checksum->HeaderText = L"Checksum";
			this->checksum->MinimumWidth = 6;
			this->checksum->Name = L"checksum";
			this->checksum->ReadOnly = true;
			this->checksum->Width = 110;
			// 
			// fragOptions
			// 
			this->fragOptions->HeaderText = L"Frag. Opts.";
			this->fragOptions->MinimumWidth = 6;
			this->fragOptions->Name = L"fragOptions";
			this->fragOptions->ReadOnly = true;
			this->fragOptions->Width = 200;
			// 
			// Payload
			// 
			this->Payload->HeaderText = L"Payload";
			this->Payload->MinimumWidth = 6;
			this->Payload->Name = L"Payload";
			this->Payload->ReadOnly = true;
			this->Payload->Width = 561;
			// 
			// packetDataButton
			// 
			this->packetDataButton->Enabled = false;
			this->packetDataButton->FlatStyle = System::Windows::Forms::FlatStyle::Popup;
			this->packetDataButton->Font = (gcnew System::Drawing::Font(L"Consolas", 9));
			this->packetDataButton->ForeColor = System::Drawing::Color::White;
			this->packetDataButton->Location = System::Drawing::Point(912, 478);
			this->packetDataButton->Name = L"packetDataButton";
			this->packetDataButton->Size = System::Drawing::Size(103, 30);
			this->packetDataButton->TabIndex = 23;
			this->packetDataButton->Text = L"Data";
			this->packetDataButton->UseVisualStyleBackColor = true;
			this->packetDataButton->Visible = false;
			this->packetDataButton->Click += gcnew System::EventHandler(this, &main_form::packetDataButton_Click);
			// 
			// checkBox_ShowPacketData
			// 
			this->checkBox_ShowPacketData->AutoSize = true;
			this->checkBox_ShowPacketData->Enabled = false;
			this->checkBox_ShowPacketData->ForeColor = System::Drawing::Color::White;
			this->checkBox_ShowPacketData->Location = System::Drawing::Point(24, 107);
			this->checkBox_ShowPacketData->Name = L"checkBox_ShowPacketData";
			this->checkBox_ShowPacketData->Size = System::Drawing::Size(265, 24);
			this->checkBox_ShowPacketData->TabIndex = 24;
			this->checkBox_ShowPacketData->Text = L"Show Extensive Packet Data";
			this->checkBox_ShowPacketData->UseVisualStyleBackColor = true;
			this->checkBox_ShowPacketData->Visible = false;
			// 
			// exportButton_PacketData
			// 
			this->exportButton_PacketData->Enabled = false;
			this->exportButton_PacketData->FlatStyle = System::Windows::Forms::FlatStyle::Popup;
			this->exportButton_PacketData->Font = (gcnew System::Drawing::Font(L"Consolas", 11));
			this->exportButton_PacketData->ForeColor = System::Drawing::Color::White;
			this->exportButton_PacketData->Location = System::Drawing::Point(22, 193);
			this->exportButton_PacketData->Name = L"exportButton_PacketData";
			this->exportButton_PacketData->Size = System::Drawing::Size(243, 37);
			this->exportButton_PacketData->TabIndex = 25;
			this->exportButton_PacketData->Text = L"Export Packet Data";
			this->exportButton_PacketData->UseVisualStyleBackColor = true;
			this->exportButton_PacketData->Visible = false;
			this->exportButton_PacketData->Click += gcnew System::EventHandler(this, &main_form::exportButton_PacketData_Click);
			// 
			// portList_Label
			// 
			this->portList_Label->AutoSize = true;
			this->portList_Label->Enabled = false;
			this->portList_Label->ForeColor = System::Drawing::Color::White;
			this->portList_Label->Location = System::Drawing::Point(20, 373);
			this->portList_Label->Name = L"portList_Label";
			this->portList_Label->Size = System::Drawing::Size(180, 20);
			this->portList_Label->TabIndex = 27;
			this->portList_Label->Text = L"Ports for scanning:";
			this->portList_Label->Visible = false;
			// 
			// portList
			// 
			this->portList->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(51)));
			this->portList->Enabled = false;
			this->portList->ForeColor = System::Drawing::Color::White;
			this->portList->FormattingEnabled = true;
			this->portList->Items->AddRange(gcnew cli::array< System::Object^  >(2) { L"1-1024", L"1-65535" });
			this->portList->Location = System::Drawing::Point(24, 396);
			this->portList->Name = L"portList";
			this->portList->Size = System::Drawing::Size(241, 28);
			this->portList->TabIndex = 28;
			this->portList->Text = L"1-1024";
			this->portList->Visible = false;
			// 
			// echoCount_Label
			// 
			this->echoCount_Label->AutoSize = true;
			this->echoCount_Label->Enabled = false;
			this->echoCount_Label->ForeColor = System::Drawing::Color::White;
			this->echoCount_Label->Location = System::Drawing::Point(20, 301);
			this->echoCount_Label->Name = L"echoCount_Label";
			this->echoCount_Label->Size = System::Drawing::Size(153, 20);
			this->echoCount_Label->TabIndex = 29;
			this->echoCount_Label->Text = L"ICMP Echo Count:";
			this->echoCount_Label->Visible = false;
			// 
			// echoCount
			// 
			this->echoCount->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(51)));
			this->echoCount->Enabled = false;
			this->echoCount->ForeColor = System::Drawing::Color::White;
			this->echoCount->FormattingEnabled = true;
			this->echoCount->Items->AddRange(gcnew cli::array< System::Object^  >(2) { L"1-1024", L"1-65535" });
			this->echoCount->Location = System::Drawing::Point(24, 324);
			this->echoCount->Name = L"echoCount";
			this->echoCount->Size = System::Drawing::Size(241, 28);
			this->echoCount->TabIndex = 30;
			this->echoCount->Text = L"256";
			this->echoCount->Visible = false;
			// 
			// packetDataGridRowCount
			// 
			this->packetDataGridRowCount->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(70)));
			this->packetDataGridRowCount->BorderStyle = System::Windows::Forms::BorderStyle::None;
			this->packetDataGridRowCount->Enabled = false;
			this->packetDataGridRowCount->Font = (gcnew System::Drawing::Font(L"Consolas", 11));
			this->packetDataGridRowCount->ForeColor = System::Drawing::Color::White;
			this->packetDataGridRowCount->Location = System::Drawing::Point(404, 61);
			this->packetDataGridRowCount->Name = L"packetDataGridRowCount";
			this->packetDataGridRowCount->ReadOnly = true;
			this->packetDataGridRowCount->Size = System::Drawing::Size(190, 22);
			this->packetDataGridRowCount->TabIndex = 31;
			this->packetDataGridRowCount->Text = L"Data Rows: 0";
			this->packetDataGridRowCount->Visible = false;
			// 
			// main_form
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(9, 20);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(0)), static_cast<System::Int32>(static_cast<System::Byte>(0)),
				static_cast<System::Int32>(static_cast<System::Byte>(51)));
			this->ClientSize = System::Drawing::Size(1121, 506);
			this->Controls->Add(this->exportButton);
			this->Controls->Add(this->lookupSpecificIPButton);
			this->Controls->Add(this->exportButton_PacketData);
			this->Controls->Add(this->packetDataGridRowCount);
			this->Controls->Add(this->toolsButton);
			this->Controls->Add(this->sniffButton);
			this->Controls->Add(this->clearRowsButton);
			this->Controls->Add(this->rowCount);
			this->Controls->Add(this->namePanel);
			this->Controls->Add(this->interfaceList);
			this->Controls->Add(this->horizontalBackPanel);
			this->Controls->Add(this->dataGrid);
			this->Controls->Add(this->echoCount);
			this->Controls->Add(this->echoCount_Label);
			this->Controls->Add(this->portList);
			this->Controls->Add(this->portList_Label);
			this->Controls->Add(this->checkBox_ShowPacketData);
			this->Controls->Add(this->packetDataButton);
			this->Controls->Add(this->saveResultsDialog);
			this->Controls->Add(this->settingsSaveButton);
			this->Controls->Add(this->backToSnifferButton);
			this->Controls->Add(this->settingsButton);
			this->Controls->Add(this->interfaceStatusField);
			this->Controls->Add(this->sniffStatusField);
			this->Controls->Add(this->bottomPanel);
			this->Controls->Add(this->packetInfoDataGrid);
			this->Font = (gcnew System::Drawing::Font(L"Consolas", 10));
			this->FormBorderStyle = System::Windows::Forms::FormBorderStyle::FixedSingle;
			this->Icon = (cli::safe_cast<System::Drawing::Icon^>(resources->GetObject(L"$this.Icon")));
			this->Margin = System::Windows::Forms::Padding(3, 4, 3, 4);
			this->MaximizeBox = false;
			this->Name = L"main_form";
			this->Text = L"EasySniff";
			this->Load += gcnew System::EventHandler(this, &main_form::main_form_Load);
			(cli::safe_cast<System::ComponentModel::ISupportInitialize^>(this->dataGrid))->EndInit();
			(cli::safe_cast<System::ComponentModel::ISupportInitialize^>(this->packetInfoDataGrid))->EndInit();
			this->ResumeLayout(false);
			this->PerformLayout();

		}
		private: System::Void sniffButton_Click(System::Object^  sender, System::EventArgs^  args) {
			// handles setting the sniffing value
			if (!this->interfaceList->SelectedItem) {
				MessageBox::Show("You must choose an interface before sniffing!", "Error!");
			}
			else {
				if (this->sniffing) {
					this->sniffing = false;
					this->sniffStatusField->Text = "Sniffing: off";
					this->settingsButton->Visible = true;
					this->settingsButton->Enabled = true;
					if (this->selectedPage == PAGE_MAIN && this->checkBox_ShowPacketData->Checked) {
						this->packetDataButton->Visible = true;
						this->packetDataButton->Enabled = true;
					}
					if (this->selectedPage != PAGE_MAIN) {
						this->backToSnifferButton->Visible = true;
						this->backToSnifferButton->Enabled = true;
					}
					this->interfaceStatusField->Text = "Interface: none";
					try {
						this->t1->Suspend();		// There is no reason why this should raise unless the user PURPOSELY
					}								// repeatedly sniffs on/off at a very rapid pace. So... as a result, if
					catch (...) {					// they do, I am just gonna knock them out the program. You shouldn't be
						Application::Exit();		// doing that anyway.
					}
					this->threadStopped = true;
				}
				else {
					this->sniffing = true;
					this->sniffStatusField->Text = "Sniffing: on";
					this->packetInf->ipList->Add("");
					this->settingsButton->Visible = false;
					this->settingsButton->Enabled = false;
					this->packetDataButton->Visible = false;
					this->packetDataButton->Enabled = false;
					this->backToSnifferButton->Visible = false;
					this->backToSnifferButton->Enabled = false;
					this->interfaceStatusField->Text = "Interface: " + this->interfaceList->Text;
					if (this->threadStopped) {
						this->t1->Resume();
						this->threadStopped = false;
					}
					else {
						this->t1->Start();
					}
				}
			}
		}
		private: System::Void main_form_Load(System::Object^ sender, System::EventArgs^  e) {
			getDevices(this->interfaceList); // get all interfaces on startup
			this->packetInf->ipList->Add("");
		}
		private: System::Void clearRowsButton_Click(System::Object^ sender, System::EventArgs^  e) {
			this->dataGrid->Rows->Clear();
			this->packetInf->ipList->Clear();
			this->packetInf->ipList->Add("");
			this->packetInfoDataGrid->Rows->Clear();
			this->rowCount->Text = "Rows: 0";
			this->packetDataGridRowCount->Text = "Data Rows: 0";
		}
		private: System::Void copyCellContent(System::Object^ sender, DataGridViewCellMouseEventArgs^  e) {
			try {
				if (!this->portScanKeyDown) {
					Clipboard::SetText(this->dataGrid->Rows[e->RowIndex]->Cells[e->ColumnIndex]->Value->ToString());
				}
				else if (this->portScanKeyDown) {
					this->portScanKeyDown = false;
					if (this->dataGrid->Rows[e->RowIndex]->Cells[e->ColumnIndex]->Value->ToString()->Contains(".")) {
						portScanHandler^ psh = gcnew portScanHandler();
						settings_values::selectedIP = this->dataGrid->Rows[e->RowIndex]->Cells[e->ColumnIndex]->Value->ToString();
						psh->Show();
					}
				}
			}
			catch (...) {
				// do nothing
			}
		}
		private: System::Void dataGrid_pingAddress(System::Object^ sender, DataGridViewCellMouseEventArgs^ e) {
			try {
				if (!this->portScanKeyDown) {
					if (this->dataGrid->Rows[e->RowIndex]->Cells[e->ColumnIndex]->Value->ToString()->Contains(".")) {
						pingAddressForm^ paf = gcnew pingAddressForm();
						settings_values::selectedIP = this->dataGrid->Rows[e->RowIndex]->Cells[e->ColumnIndex]->Value->ToString();
						paf->Show();
					}
				}
			}
			catch (...) {
				// do nothing
			}
		}
		private: System::Void packetInfoDataGrid_CellMouseClick(System::Object^ sender, System::Windows::Forms::DataGridViewCellMouseEventArgs^ e) {
			try {
				Clipboard::SetText(this->packetInfoDataGrid->Rows[e->RowIndex]->Cells[e->ColumnIndex]->Value->ToString());
			}
			catch (...) {
				// do nothing
			}
		}
		private: System::Void settingsButton_Click(System::Object^ sender, System::EventArgs^ e) {
			this->interfaceList->Visible = false;
			this->sniffButton->Visible = false;
			this->clearRowsButton->Visible = false;
			this->sniffStatusField->Visible = false;
			this->interfaceStatusField->Visible = false;
			this->saveResultsDialog->Text = ""; this->saveResultsDialog->Visible = true;
			this->dataGrid->Visible = false;
			this->backToSnifferButton->Visible = true;
			this->settingsSaveButton->Visible = true;
			this->rowCount->Visible = false;
			this->toolsButton->Visible = false;
			this->packetDataGridRowCount->Visible = false;
			this->checkBox_ShowPacketData->Visible = true;
			this->packetDataButton->Visible = false;
			this->portList->Visible = true;
			this->portList_Label->Visible = true;
			this->echoCount->Visible = true;
			this->echoCount_Label->Visible = true;
			this->Text = "EasySniff | Settings";

			this->interfaceList->Enabled = false;
			this->sniffButton->Enabled = false;
			this->clearRowsButton->Enabled = false;
			this->sniffStatusField->Enabled = false;
			this->interfaceStatusField->Enabled = false;
			this->saveResultsDialog->Enabled = true;
			this->dataGrid->Enabled = false;
			this->backToSnifferButton->Enabled = true;
			this->settingsSaveButton->Enabled = true;
			this->rowCount->Enabled = false;
			this->packetDataGridRowCount->Enabled = false;
			this->toolsButton->Enabled = false;
			this->checkBox_ShowPacketData->Enabled = true;
			this->packetDataButton->Enabled = false;
			this->portList->Enabled = true;
			this->portList_Label->Enabled = true;
			this->echoCount->Enabled = true;
			this->echoCount_Label->Enabled = true;
		}
 		private: System::Void ToolsButton_Click(System::Object^ sender, System::EventArgs^ e) {
			this->interfaceList->Visible = false;
			this->sniffButton->Visible = false;
			this->clearRowsButton->Visible = false;
			this->sniffStatusField->Visible = false;
			this->interfaceStatusField->Visible = false;
			this->saveResultsDialog->Text = ""; this->saveResultsDialog->Visible = true;
			this->dataGrid->Visible = false;
			this->backToSnifferButton->Visible = true;
			this->rowCount->Visible = false;
			this->lookupSpecificIPButton->Visible = true;
			this->toolsButton->Visible = false;
			this->exportButton->Visible = true;
			this->exportButton_PacketData->Visible = true;
			this->packetDataGridRowCount->Visible = false;
			this->packetDataButton->Visible = false;
			this->Text = "EasySniff | Tools";

			this->interfaceList->Enabled = false;
			this->sniffButton->Enabled = false;
			this->clearRowsButton->Enabled = false;
			this->sniffStatusField->Enabled = false;
			this->interfaceStatusField->Enabled = false;
			this->dataGrid->Enabled = false;
			this->backToSnifferButton->Enabled = true;
			this->settingsSaveButton->Enabled = true;
			this->rowCount->Enabled = false;
			this->lookupSpecificIPButton->Enabled = true;
			this->toolsButton->Enabled = false;
			this->exportButton->Enabled = true;
			this->packetDataGridRowCount->Enabled = false;
			this->exportButton_PacketData->Enabled = true;
			this->packetDataButton->Enabled = false;
		}	private: System::Void LookupSpecificIPButton_Click(System::Object^ sender, System::EventArgs^ e) {
				lookupAddressForm^ lookupIPFormObj = gcnew lookupAddressForm();
				lookupIPFormObj->Show();
			}
		private: System::Void backToSnifferButton_Click(System::Object^ sender, System::EventArgs^ e) {
			this->selectedPage = PAGE_MAIN;
			this->interfaceList->Visible = true;
			this->sniffButton->Visible = true;
			this->clearRowsButton->Visible = true;
			this->sniffStatusField->Visible = true;
			this->interfaceStatusField->Visible = true;
			this->saveResultsDialog->Visible = false;
			this->dataGrid->Visible = true;
			this->backToSnifferButton->Visible = false;
			this->settingsSaveButton->Visible = false;
			this->rowCount->Visible = true;
			this->toolsButton->Visible = true;
			this->lookupSpecificIPButton->Visible = false;
			this->exportButton->Visible = false;
			this->exportButton_PacketData->Visible = false;
			this->checkBox_ShowPacketData->Visible = false;
			this->packetInfoDataGrid->Visible = false;
			if (settings_values::captureInfo) {
				this->packetDataGridRowCount->Visible = true;
			}
			this->portList->Visible = false;
			this->portList_Label ->Visible = false;
			this->echoCount->Visible = false;
			this->echoCount_Label->Visible = false;
			if (this->checkBox_ShowPacketData->Checked) {
				if (!sniffing) {
					this->packetDataButton->Visible = true;
					this->packetDataButton->Enabled = true;
				}
			}
			if (!sniffing) {
				this->settingsButton->Visible = true;
				this->settingsButton->Enabled = true;
			}
			this->Text = "EasySniff";

			this->interfaceList->Enabled = true;
			this->sniffButton->Enabled = true;
			this->clearRowsButton->Enabled = true;
			this->sniffStatusField->Enabled = true;
			this->interfaceStatusField->Enabled = true;
			this->saveResultsDialog->Enabled = false;
			this->dataGrid->Enabled = true;
			this->backToSnifferButton->Enabled = false;
			this->settingsSaveButton->Enabled = false;
			this->rowCount->Enabled = true;
			this->toolsButton->Enabled = true;
			this->lookupSpecificIPButton->Enabled = false;
			this->exportButton->Enabled = false;
			this->exportButton_PacketData->Enabled = false;
			this->checkBox_ShowPacketData->Enabled = false;
			this->packetInfoDataGrid->Enabled = false;
			if (settings_values::captureInfo) {
				this->packetDataGridRowCount->Enabled = true;
			}
			this->portList->Enabled = false;
			this->portList_Label->Enabled = false;
			this->echoCount->Enabled = false;
			this->echoCount_Label->Enabled = false;
		}
		private: System::Void settingsSaveButton_Click(System::Object^ sender, System::EventArgs^ e) {
			int hyphenCount = 0;
			this->saveResultsDialog->Text = "Config. Saved...";
			settings_values::captureInfo = this->checkBox_ShowPacketData->Checked;
			for (int i = 0; i < this->portList->Text->Length; i++) {
				if (this->portList->Text[i] == '-') {
					hyphenCount = hyphenCount + 1;
				}
			}
			if (hyphenCount == 1) {
				settings_values::startPort = this->portList->Text->Split('-')[0];
				settings_values::endPort = this->portList->Text->Split('-')[1];
			}
			else {
				MessageBox::Show("Use format <startPort>-<endPort>", "Notice");
			}
			try {
				if (Convert::ToUInt64(this->echoCount->Text) > 65535 || Convert::ToUInt64(this->echoCount->Text) < 1) {
					MessageBox::Show("Max ICMP Echoes is 65535, and min is 1.", "Notice");
				}
				else {
					settings_values::icmpCount = this->echoCount->Text;
				}
			}
			catch (FormatException ^ e) {
				MessageBox::Show("Invalid ICMP Echo count!", "Error");
			}
		} private: System::Void packetDataButton_Click(System::Object^ sender, System::EventArgs^ e) {
				this->selectedPage = PAGE_DATA;
				this->settingsButton->Visible = false;
				this->settingsButton->Enabled = false;
				this->dataGrid->Visible = false;
				this->dataGrid->Enabled = false;
				this->backToSnifferButton->Visible = true;
				this->backToSnifferButton->Enabled = true;
				this->toolsButton->Visible = false;
				this->toolsButton->Enabled = false;
				this->packetDataButton->Visible = false;
				this->packetDataButton->Enabled = false;
				this->packetInfoDataGrid->Visible = true;
				this->packetInfoDataGrid->Enabled = true;
				this->Text = "EasySniff | Packet Manager";
			}
		private: System::Void dataGrid_RowsAdded(System::Object^ sender, System::Windows::Forms::DataGridViewRowsAddedEventArgs^ e) {
			this->rowCount->Text = "Rows: " + this->dataGrid->Rows->Count;
		}
		private: System::Void ExportButton_Click(System::Object^ sender, System::EventArgs^ e) {
			try {
				this->dataGrid->SelectAll();
				Clipboard::SetDataObject(this->dataGrid->GetClipboardContent(), true);
				MessageBox::Show("Copied to clipboard!", "Notice");
			}
			catch (ArgumentNullException^  e) {
				MessageBox::Show("Capture log cannot be empty!", "Notice");
			}
		}
		private: System::Void exportButton_PacketData_Click(System::Object^ sender, System::EventArgs^ e) {
			try {
				if (this->checkBox_ShowPacketData->Checked) {
					this->packetInfoDataGrid->SelectAll();
					Clipboard::SetDataObject(this->packetInfoDataGrid->GetClipboardContent(), true);
					MessageBox::Show("Copied to clipboard!", "Notice");
				}
				else {
					MessageBox::Show("Extensive Data Capture must be enabled in order to export.");
				}
			}
			catch (ArgumentNullException ^ e) {
				MessageBox::Show("Packet data log cannot be empty!", "Notice");
			}
		}
		private: System::Void dataGrid_KeyDown(System::Object^ sender, System::Windows::Forms::KeyEventArgs^ e) {
			if (e->KeyCode == Keys::P) {
				this->portScanKeyDown = true;
			}
			else if (e->KeyCode == Keys::S) {
				this->sniffButton_Click(this, e);
			}
			else if (e->KeyCode == Keys::C) {
				this->clearRowsButton_Click(this, e);
			}
		}
		private: System::Void interfaceList_SelectedValueChanged(System::Object^ sender, System::EventArgs^ e) {
			if (this->sniffing) {
				this->interfaceStatusField->Text = "Interface: " + this->interfaceList->Text;
			}
		}
		private: System::Void packetInfoDataGrid_RowsAdded(System::Object^ sender, System::Windows::Forms::DataGridViewRowsAddedEventArgs^ e) {
			this->packetDataGridRowCount->Text = "Data Rows: " + this->packetInfoDataGrid->Rows->Count;
		}
		private: System::Void packetInfoDataGrid_KeyDown(System::Object^ sender, System::Windows::Forms::KeyEventArgs^ e) {
			if (e->KeyCode == Keys::S) {
				this->sniffButton_Click(this, e);
			}
			else if (e->KeyCode == Keys::C) {
				this->clearRowsButton_Click(this, e);
			}
		}
	};
}