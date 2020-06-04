#include "user/CLI.h"
#include "util/log/Log.h"
#include <chrono>
#include <iostream>
#include <limits>
#include <pthread.h>
#include <time.h>
#include "common/StringUtils.h"

#undef max

//Identifiers for different message types
#define INFORM_ID "[*]"
#define ALERT_ID "[!]"
#define CONFIRM_ID "[+]"
#define SELECT_ID "[?]"

//Colors for different parts of messages
const MessageColor ID_COLOR = MessageColor::BLUE;
const MessageColor TEXT_COLOR = MessageColor::RED; //TODO: change color?

//Case-insensitive options for user confirmation.
const std::set<std::string> affirmativeOptions = { "yes", "y" };
const std::set<std::string> negativeOptions = { "no", "n" };
const std::set<std::string> cancelOptions = { "c", "cancel" };

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

CLI::~CLI(){
	pthread_mutex_destroy(&hMutex);
}

void Print(const std::string& wMessage, MessageColor color = TEXT_COLOR, bool newline=true){
	if(newline){
		std::cout << GetColorStr(color) << wMessage << std::endl;
	} else {
		std::cout << GetColorStr(color) << wMessage;
	}

	std::cout << GetColorStr(MessageColor::RESET);
}

std::optional<std::string> GetInput(unsigned int dwMaximumDelay){
	std::string output{};
	struct timeval time;

	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(STDIN_FILENO, &rfds);
	struct timeval * ptr = NULL;

	if(dwMaximumDelay != -1){
		time.tv_sec = dwMaximumDelay;
		time.tv_usec = 0;
		ptr = &time;
	}
	
	if(select(STDIN_FILENO + 1, &rfds, NULL, NULL, ptr) == 1){
		std::string input{};
		std::getline(std::cin, input);
		return input;
	} else {
		return std::nullopt;
	}
}

const CLI CLI::instance{};

const CLI& CLI::GetInstance(){
	return instance;
}

std::string CLI::GetUserSelection(const std::string& prompt, const std::vector<std::string>& options,
	unsigned int dwMaximumDelay, ImportanceLevel level) const {
	auto mutex = AcquireMutex(hMutex);
	Print(SELECT_ID, ID_COLOR, false);
	Print(descriptions[static_cast<unsigned int>(level)], colors[static_cast<unsigned int>(level)], false);
	Print(" " + prompt);

	int i = 0;
	for (auto str : options) {
		i += 1;
		Print(std::to_string(i), MessageColor::CYAN, false);
		Print(". " + str);
	}
	Print("Please enter a number 1 through " + std::to_string(i) + " to continue. ", MessageColor::CYAN, false);

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
				Print("Please enter a number 1 through " + std::to_string(i) + " to continue. ", MessageColor::CYAN, false);
			}
		}
	};

	return "";
}

void CLI::InformUser(const std::string& information, ImportanceLevel level) const {
	auto mutex = AcquireMutex(hMutex);
	Print(INFORM_ID, ID_COLOR, false);
	Print(descriptions[static_cast<unsigned int>(level)], colors[static_cast<unsigned int>(level)], false);
	Print(" " + information);
}
bool CLI::AlertUser(const std::string& information, unsigned int dwMaximumDelay, ImportanceLevel level) const {
	auto mutex = AcquireMutex(hMutex);
	Print(ALERT_ID, ID_COLOR, false);
	Print(descriptions[static_cast<unsigned int>(level)], colors[static_cast<unsigned int>(level)], false);
	Print(" " + information);
	Print("Press enter to continue. ", MessageColor::CYAN, false);
	Print("");
	return GetInput(dwMaximumDelay).has_value();
}

//TODO: Fix timeout in GetInput
unsigned int CLI::GetUserConfirm(const std::string& prompt, unsigned int dwMaximumDelay, ImportanceLevel level) const {
	auto mutex = AcquireMutex(hMutex);
	Print(CONFIRM_ID, ID_COLOR, false);
	Print(descriptions[static_cast<unsigned int>(level)], colors[static_cast<unsigned int>(level)], false);
	Print(" " + prompt);
	while(true){
		Print("Enter y(es), n(o), or c(ancel). ", MessageColor::CYAN, false); //TODO: change color code?
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

std::string GetColorStr(const enum MessageColor color){
	switch(color){
		case MessageColor::RESET:
			return std::string("\033[0m");
		case MessageColor::BLACK:
			return std::string("\033[30m");
		case MessageColor::RED:
			return std::string("\033[31m");
		case MessageColor::GREEN:
			return std::string("\033[32m");
		case MessageColor::YELLOW:
			return std::string("\033[33m");
		case MessageColor::BLUE:
			return std::string("\033[34m");
		case MessageColor::MAGENTA:
			return std::string("\033[35m");
		case MessageColor::CYAN:
			return std::string("\033[36m");
		case MessageColor::WHITE:
			return std::string("\033[37m");
		case MessageColor::BOLDBLACK:
			return std::string("\033[1m\033[30m");
		case MessageColor::BOLDRED:
			return std::string("\033[1m\033[31m");
		case MessageColor::BOLDGREEN:
			return std::string("\033[1m\033[32m");
		case MessageColor::BOLDYELLOW:
			return std::string("\033[1m\033[33m");
		case MessageColor::BOLDBLUE:
			return std::string("\033[1m\033[34m");
		case MessageColor::BOLDMAGENTA:
			return std::string("\033[1m\033[35m");
		case MessageColor::BOLDCYAN:
			return std::string("\033[1m\033[36m");
		case MessageColor::BOLDWHITE:
			return std::string("\033[1m\033[37m");
	}

	return std::string("");
}