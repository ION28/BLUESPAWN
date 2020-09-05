#include "user/CLI.h"
#include "util/log/Log.h"
#include <chrono>
#include <iostream>
#include <limits>
#include "util/stringutils.h"

#undef max

//Identifiers for different message types
#define INFORM_ID L"[*]"
#define ALERT_ID L"[!]"
#define CONFIRM_ID L"[+]"
#define SELECT_ID L"[?]"

//Colors for different parts of messages
const MessageColor ID_COLOR = MessageColor::BLUE;
const MessageColor TEXT_COLOR = MessageColor::LIGHTGRAY;

//Case-insensitive options for user confirmation.
const std::set<std::wstring> affirmativeOptions = { L"yes", L"y" };
const std::set<std::wstring> negativeOptions = { L"no", L"n" };
const std::set<std::wstring> cancelOptions = { L"c", L"cancel" };

const std::wstring descriptions[3] = {
	L"[LOW]",
	L"[MEDIUM]",
	L"[HIGH]"
};

const MessageColor colors[3] = {
	MessageColor::GREEN,
	MessageColor::YELLOW,
	MessageColor::RED
};

CLI::CLI() : hMutex{ CreateMutexW(nullptr, false, L"Local\\CLI-Mutex") } {}

void Print(const std::wstring& wMessage, MessageColor color = TEXT_COLOR, bool newline=true){
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, static_cast<WORD>(color));
	if(newline){
		std::wcout << wMessage << std::endl;
	} else {
		std::wcout << wMessage;
	}
}

std::optional<std::wstring> GetInput(DWORD dwMaximumDelay){
	std::wstring output{};
	auto result = WaitForSingleObject(GetStdHandle(STD_INPUT_HANDLE), dwMaximumDelay);
	if(result == WAIT_OBJECT_0){
		std::wstring input{};
		std::getline(std::wcin, input);
		return input;
	} else {
		return std::nullopt;
	}
}

const CLI CLI::instance{};

const CLI& CLI::GetInstance(){
	return instance;
}

std::wstring CLI::GetUserSelection(const std::wstring& prompt, const std::vector<std::wstring>& options,
	DWORD dwMaximumDelay, ImportanceLevel level) const {
	auto mutex = AcquireMutex(hMutex);
	Print(SELECT_ID, ID_COLOR, false);
	Print(descriptions[static_cast<DWORD>(level)], colors[static_cast<DWORD>(level)], false);
	Print(L" " + prompt);

	int i = 0;
	for (auto str : options) {
		i += 1;
		Print(std::to_wstring(i), MessageColor::CYAN, false);
		Print(L". " + str);
	}
	Print(L"Please enter a number 1 through " + std::to_wstring(i) + L" to continue. ", MessageColor::LIGHTGRAY, false);

	while(true){
		size_t userIn = 0;
		std::wstringstream stream{};
		auto input = GetInput(dwMaximumDelay);
		if(!input){
			return {};
		} else {
			stream << *input;
			stream >> userIn;
			if(stream.good() && userIn > 0 && userIn <= i){
				return options[userIn - 1];
			} else {
				Print(L"Please enter a number 1 through " + std::to_wstring(i) + L" to continue. ", MessageColor::LIGHTGRAY, false);
			}
		}
	};

	return L"";
}

void CLI::InformUser(const std::wstring& information, ImportanceLevel level) const {
	auto mutex = AcquireMutex(hMutex);
	Print(INFORM_ID, ID_COLOR, false);
	Print(descriptions[static_cast<DWORD>(level)], colors[static_cast<DWORD>(level)], false);
	Print(L" " + information);
}
bool CLI::AlertUser(const std::wstring& information, DWORD dwMaximumDelay, ImportanceLevel level) const {
	auto mutex = AcquireMutex(hMutex);
	Print(ALERT_ID, ID_COLOR, false);
	Print(descriptions[static_cast<DWORD>(level)], colors[static_cast<DWORD>(level)], false);
	Print(L" " + information);
	Print(L"Press enter to continue. ", MessageColor::LIGHTGRAY, false);
	Print(L"");
	return GetInput(dwMaximumDelay).has_value();
}

DWORD CLI::GetUserConfirm(const std::wstring& prompt, DWORD dwMaximumDelay, ImportanceLevel level) const {
	auto mutex = AcquireMutex(hMutex);
	Print(CONFIRM_ID, ID_COLOR, false);
	Print(descriptions[static_cast<DWORD>(level)], colors[static_cast<DWORD>(level)], false);
	Print(L" " + prompt);
	while(true){
		Print(L"Enter y(es), n(o), or c(ancel). ", MessageColor::LIGHTGRAY, false);
		auto result = GetInput(dwMaximumDelay);
		if(!result){
			return -1;
		} else {
			auto choice = ToLowerCase(*result);
			if(affirmativeOptions.find(choice) != affirmativeOptions.end()) {
				return 1;
			} else if(negativeOptions.find(choice) != negativeOptions.end()) {
				return 0;
			} else if(cancelOptions.find(choice) != cancelOptions.end()) {
				return -1;
			}
		}
	}
}

const HandleWrapper& CLI::GetMutex() const {
	return hMutex;
}