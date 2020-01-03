#include "user/CLI.h"
#include "util/log/Log.h"

std::map<std::pair<HANDLE, HANDLE>, CLI> CLI::instances = {};
const HANDLE CLI::hDefaultOutput = GetStdHandle(STD_OUTPUT_HANDLE);
const HANDLE CLI::hDefaultInput = GetStdHandle(STD_INPUT_HANDLE);

void NewLine(HANDLE output){
    CONSOLE_SCREEN_BUFFER_INFO csbiInfo = {};
    if(!GetConsoleScreenBufferInfo(output, &csbiInfo)){
        LOG_ERROR("IO error in CLI");
    }

    csbiInfo.dwCursorPosition.X = 0;
    if((csbiInfo.dwSize.Y - 1) == csbiInfo.dwCursorPosition.Y){
        SMALL_RECT srctScrollRect = { 0, 1, csbiInfo.dwSize.X - (SHORT) 1, csbiInfo.dwSize.Y - (SHORT) 1 };
        SMALL_RECT srctClipRect = srctScrollRect;
        CHAR_INFO chiFill = { (char) ' ', FOREGROUND_RED | FOREGROUND_INTENSITY };
        ScrollConsoleScreenBuffer(output, &srctScrollRect, &srctClipRect, { 0, 0 }, &chiFill);
    }

    else csbiInfo.dwCursorPosition.Y += 1;

    if(!SetConsoleCursorPosition(output, csbiInfo.dwCursorPosition)){
        LOG_ERROR("IO error in CLI");
    }
}

CLI::CLI(const HANDLE output, const HANDLE input) :
	input{ input },
	output{ output } {
	instances.emplace(std::pair(input, output), *this);
}

const CLI& CLI::GetInstance(const HANDLE output, const HANDLE input){
	if(instances.find(std::pair(input, output)) != instances.end()){
		return instances.at(std::pair(input, output));
	}

	return CLI(output, input);
}

std::string CLI::GetUserSelection(const std::string& prompt, const std::set<std::string>& options,
	DWORD dwMaximumDelay) const {
	return "";
}

void CLI::InformUser(const std::string& information) const {
	WriteFile(output, information.c_str(), information.length() * 2, nullptr, nullptr);
    NewLine(output);
}

bool CLI::AlerUser(const std::string& information, DWORD dwMaximumDelay) const { return false; }

DWORD CLI::GetUserConfirm(const std::string& prompt, DWORD dwMaximumDelay) const { return 0; }