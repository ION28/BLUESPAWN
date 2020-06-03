#include "user/CLI.h"
#include "util/log/Log.h"
#include <chrono>
#include <iostream>
#include <limits>
#include <pthread.h>
#include "common/StringUtils.h"

#undef max

//Identifiers for different message types
#define INFORM_ID "[*]"
#define ALERT_ID "[!]"
#define CONFIRM_ID "[+]"
#define SELECT_ID "[?]"

//Colors for different parts of messages
const MessageColor ID_COLOR = MessageColor::BLUE;
const MessageColor TEXT_COLOR = MessageColor::LIGHTGRAY;

//Case-insensitive options for user confirmation.
const std::set<std::wstring> affirmativeOptions = { "yes", "y" };
const std::set<std::wstring> negativeOptions = { "no", "n" };
const std::set<std::wstring> cancelOptions = { "c", "cancel" };

const std::string descriptions[3] = {
	"[LOW]",
	"[MEDIUM]",
	"[HIGH]"
};

const MessageColor colors[3] = {
	MessageColor::GREEN,
	MessageColor::YELLOW,
	MessageColor::RED
};

CLI::CLI() : hMutex{ pthread_mutex_init(&hMutex, NULL) } {}

void Print(const std::string& wMessage, MessageColor color = TEXT_COLOR, bool newline=true){
	if(newline){
		std::cout << wMessage << std::endl;
	} else {
		std::cout << wMessage;
	}
}

std::optional<std::string> GetInput(DWORD dwMaximumDelay){
	std::wstring output{};
	//TODO: port
	auto result = pthread_mutex_timedlock(&hMutex, &spec)
	if(result == 0){
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

std::wstring CLI::GetUserSelection(const std::string& prompt, const std::vector<std::string>& options,
	DWORD dwMaximumDelay, ImportanceLevel level) const {
	auto mutex = AcquireMutex(hMutex);
	Print(SELECT_ID, ID_COLOR, false);
	Print(descriptions[static_cast<DWORD>(level)], colors[static_cast<DWORD>(level)], false);
	Print(" " + prompt);

	int i = 0;
	for (auto str : options) {
		i += 1;
		Print(std::to_string(i), MessageColor::CYAN, false);
		Print(". " + str);
	}
	Print("Please enter a number 1 through " + std::to_string(i) + " to continue. ", MessageColor::LIGHTGRAY, false);

	while(true){
		size_t userIn = 0;
		std::stringstream stream{};
		auto input = GetInput(dwMaximumDelay);
		if(!input){
			return {};
		} else {
			stream << *input;
			stream >> userIn;
			if(stream.good() && userIn > 0 && userIn <= i){
				return options[userIn - 1];
			} else {
				Print("Please enter a number 1 through " + std::to_wstring(i) + " to continue. ", MessageColor::LIGHTGRAY, false);
			}
		}
	};

	return L"";
}

void CLI::InformUser(const std::string& information, ImportanceLevel level) const {
	auto mutex = AcquireMutex(hMutex);
	Print(INFORM_ID, ID_COLOR, false);
	Print(descriptions[static_cast<DWORD>(level)], colors[static_cast<DWORD>(level)], false);
	Print(" " + information);
}
bool CLI::AlertUser(const std::string& information, DWORD dwMaximumDelay, ImportanceLevel level) const {
	auto mutex = AcquireMutex(hMutex);
	Print(ALERT_ID, ID_COLOR, false);
	Print(descriptions[static_cast<DWORD>(level)], colors[static_cast<DWORD>(level)], false);
	Print(" " + information);
	Print("Press enter to continue. ", MessageColor::LIGHTGRAY, false);
	Print("");
	return GetInput(dwMaximumDelay).has_value();
}

DWORD CLI::GetUserConfirm(const std::string& prompt, DWORD dwMaximumDelay, ImportanceLevel level) const {
	auto mutex = AcquireMutex(hMutex);
	Print(CONFIRM_ID, ID_COLOR, false);
	Print(descriptions[static_cast<DWORD>(level)], colors[static_cast<DWORD>(level)], false);
	Print(" " + prompt);
	while(true){
		Print("Enter y(es), n(o), or c(ancel). ", MessageColor::LIGHTGRAY, false);
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

const pthread_mutex_t& CLI::GetMutex() const {
	return hMutex;
}