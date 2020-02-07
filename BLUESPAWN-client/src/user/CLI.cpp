#include "user/CLI.h"
#include "util/log/Log.h"
#include <chrono>
#include <iostream>
#include <limits>
#include "common/stringutils.h"

#undef max

using namespace std;
using namespace std::chrono;

//              **CONFIGURABLE  SETTINGS**                            
//Identifiers for different message types
#define INFORM_ID L"[*]"
#define ALERT_ID L"[!]"
#define CONFIRM_ID L"[+]"
#define SELECT_ID L"[?]"
//Colors for different parts of messages
const MessageColor ID_COLOR = MessageColor::BLUE;
const MessageColor TEXT_COLOR = MessageColor::LIGHTGRAY;
//Case-insensitive options for user confirmation.
const set<wstring> affirmativeOptions = { L"yes", L"y" };
const set<wstring> negativeOptions = { L"no", L"n" };
const set<wstring> cancelOptions = { L"cancel" };
//Edit CLI.cpp to change properties of Importance Levels
const ImportanceLevel ImportanceLevel::LOW = { MessageColor::GREEN, L"LOW" };
const ImportanceLevel ImportanceLevel::MEDIUM = { MessageColor::YELLOW, L"MEDIUM" };
const ImportanceLevel ImportanceLevel::LOW = { MessageColor::RED, L"HIGH" };
//             **END CONFIGURABLE SETTINGS**





std::map<std::pair<HANDLE, HANDLE>, CLI> CLI::instances = {};
const HANDLE CLI::hDefaultOutput = GetStdHandle(STD_OUTPUT_HANDLE);
const HANDLE CLI::hDefaultInput = GetStdHandle(STD_INPUT_HANDLE);
CLI::CLI() :
	input{ input },
	output{ output }
{
	instances.emplace(std::pair(input, output), *this);
}

void SetConsoleColor(MessageColor color) {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, static_cast<WORD>(color));
}

void PrintLevel(ImportanceLevel level, MessageColor postColor=TEXT_COLOR) {
	SetConsoleColor(level.color);
	wcout << level.description;
}

std::wstring CLI::GetUserSelection(const std::wstring& prompt, const std::vector<std::wstring>& options,
	DWORD dwMaximumDelay, ImportanceLevel level) const {
	SetConsoleColor(ID_COLOR);
	wcout << SELECT_ID << L" ";
	PrintLevel(level);
	SetConsoleColor(TEXT_COLOR);

	wstringstream stream;
	stream << prompt << endl;
	int i = 1;

	for (auto str : options) {
		stream << i << L". " << str << endl;
		i++;
	}
	wcout << stream.str() << endl;

	int userIn;
	while (true) {
		wcin >> userIn;
		if (userIn > 0 && userIn <= options.size) {
			return options[userIn - 1];
		}
		else {
			wcout << L"Please Enter a valid number between 1 and " << options.size() << endl;
		}
	}
	return L"";
}

void CLI::InformUser(const std::wstring& information, ImportanceLevel level) const {
	SetConsoleColor(ID_COLOR);
	wcout << INFORM_ID << L" ";
	PrintLevel(level);

	SetConsoleColor(TEXT_COLOR);
	wcout << information << endl;
}
bool CLI::AlertUser(const std::wstring& information, DWORD dwMaximumDelay, ImportanceLevel level) const {
	SetConsoleColor(ID_COLOR);
	wcout << ALERT_ID << L" ";
	PrintLevel(level);
	SetConsoleColor(ID_COLOR);
	wcout << information << endl;
	wcin.ignore(numeric_limits<streamsize>::max(), '\n');
	return true;
}

DWORD CLI::GetUserConfirm(const std::wstring& prompt, DWORD dwMaximumDelay, ImportanceLevel level) const {
	wstring result;
	SetConsoleColor(ID_COLOR);
	wcout << CONFIRM_ID << L" ";
	PrintLevel(level);
	SetConsoleColor(TEXT_COLOR);
	wcout << prompt << endl;
	wcin >> result;
	result = ToLowerCase(result);
	if (affirmativeOptions.find(result) != affirmativeOptions.end()) {
		return 1;
	}
	else if (negativeOptions.find(result) != negativeOptions.end()) {
		return 0;
	}
	else {
		return -1;
	}
}