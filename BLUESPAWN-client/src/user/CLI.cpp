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
	instances.emplace(std::pair(input, output), *this);
}
void SetConsoleColor(MessageColor color) {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, static_cast<WORD>(color));
}

std::string CLI::GetUserSelection(const std::string& prompt, const std::vector<std::string>& options,
	DWORD dwMaximumDelay) const {
	SetConsoleColor(MessageColor::BLUE);
	cout << "[?] ";
	SetConsoleColor(MessageColor::WHITE);

	stringstream stream;
	stream << prompt << endl;
	int i = 1;

	for (auto str : options) {
		stream << i << ". " << str << endl;
		i++;
	}
	cout << stream.str() << endl;
	
	int userIn;
	while (true) {
		cin >> userIn;
		if (userIn > 0 && userIn <= options.size()) {
			return options[userIn-1];
		}
		else {
			cout << "Please Enter a valid number between 1 and " << options.size() <<endl;
		}
	}
	return "";
}

void CLI::InformUser(const std::string& information) const {
	SetConsoleColor(MessageColor::BLUE);
	cout << "[*] ";
	SetConsoleColor(MessageColor::WHITE);

	cout << information << endl;
}
bool CLI::AlertUser(const std::string& information, DWORD dwMaximumDelay) const { 
	SetConsoleColor(MessageColor::BLUE);
	cout << "[!] ";
	SetConsoleColor(MessageColor::WHITE);
	cout << information << endl;
	cin.ignore(numeric_limits<streamsize>::max(),'\n');
	return true;
}
const set<string> affirmativeOptions = { "yes", "y"};
const set<string> negativeOptions = { "no", "n" };
const set<string> cancelOptions = { "cancel" };
DWORD CLI::GetUserConfirm(const std::string& prompt, DWORD dwMaximumDelay) const {
	string result;
	cout << prompt << endl;
	cin >> result;
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