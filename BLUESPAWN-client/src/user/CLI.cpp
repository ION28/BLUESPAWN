#include "user/CLI.h"
#include "util/log/Log.h"
#include <chrono>
#include <iostream>
#include <limits>
#include "common/stringutils.h"

#undef max

using namespace std;
using namespace std::chrono;

std::map<std::pair<HANDLE, HANDLE>, CLI> CLI::instances = {};
const HANDLE CLI::hDefaultOutput = GetStdHandle(STD_OUTPUT_HANDLE);
const HANDLE CLI::hDefaultInput = GetStdHandle(STD_INPUT_HANDLE);
CLI::CLI() :
	input{ input },
	output{ output }
{
	//instances.emplace(std::pair(input, output), *this);
}
void SetConsoleColor(MessageColor color) {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, static_cast<WORD>(color));
}

std::wstring CLI::GetUserSelection(const std::wstring& prompt, const std::vector<std::wstring>& options,
	DWORD dwMaximumDelay) const {
	SetConsoleColor(MessageColor::BLUE);
	wcout << L"[?] ";
	SetConsoleColor(MessageColor::WHITE);

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
		if (userIn > 0 && userIn <= options.size()) {
			return options[userIn-1];
		}
		else {
			wcout << L"Please Enter a valid number between 1 and " << options.size() <<endl;
		}
	}
	return L"";
}

void CLI::InformUser(const std::wstring& information) const {
	SetConsoleColor(MessageColor::BLUE);
	wcout << L"[*] ";
	SetConsoleColor(MessageColor::WHITE);

	wcout << information << endl;
}
bool CLI::AlertUser(const std::wstring& information, DWORD dwMaximumDelay) const { 
	SetConsoleColor(MessageColor::BLUE);
	wcout << L"[!] ";
	SetConsoleColor(MessageColor::WHITE);
	wcout << information << endl;
	wcin.ignore(numeric_limits<streamsize>::max(),'\n');
	return true;
}
const set<wstring> affirmativeOptions = { L"yes", L"y"};
const set<wstring> negativeOptions = { L"no", L"n" };
const set<wstring> cancelOptions = { L"cancel" };
DWORD CLI::GetUserConfirm(const std::wstring& prompt, DWORD dwMaximumDelay) const {
	wstring result;
	wcout << prompt << endl;
	wcin >> result;
	result = ToLowerCase(result);
	if (affirmativeOptions.find(result)!=affirmativeOptions.end()) {
		return 1;
	}
	else if (negativeOptions.find(result) != negativeOptions.end()) {
		return 0;
	}
	else {
		return -1;
	}
}