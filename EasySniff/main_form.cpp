#include "main_form.h"

using namespace System;
using namespace System::Windows::Forms;

[STAThreadAttribute]
void main() {
	EasySniff::main_form entryForm;
	Application::Run(%entryForm);
}