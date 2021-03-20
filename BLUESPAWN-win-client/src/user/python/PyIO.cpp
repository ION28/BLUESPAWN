#include "user/PyIO.h"
#include "util/log/Log.h"
#include <iostream>
#include <limits>
#include "util/stringutils.h"

#undef max

//Identifiers for different message types
#define INFORM_ID L"[*]"
#define ALERT_ID L"[!]"
#define CONFIRM_ID L"[+]"
#define SELECT_ID L"[?]"

//Case-insensitive options for user confirmation.
const std::set<std::wstring> affirmativeOptions = { L"yes", L"y" };
const std::set<std::wstring> negativeOptions = { L"no", L"n" };
const std::set<std::wstring> cancelOptions = { L"c", L"cancel" };

std::vector<std::wstring> pyMessageBuffer{};

const std::wstring descriptions[3] = {
	L"[LOW]",
	L"[MEDIUM]",
	L"[HIGH]"
};

PyIO::PyIO() : hMutex{ CreateMutexW(nullptr, false, L"Local\\PyBuffer-Mutex") }{}

const PyIO PyIO::instance{};

const PyIO& PyIO::GetInstance(){
	return instance;
}

std::wstring PyIO::GetUserSelection(const std::wstring& prompt, const std::vector<std::wstring>& options,
								    DWORD dwMaximumDelay, ImportanceLevel level) const{
	auto mutex = AcquireMutex(hMutex);
	pyMessageBuffer.emplace_back(SELECT_ID + descriptions[static_cast<DWORD>(level)] + L" " + prompt + L"\n");

	int i = 0;
	for(auto& str : options){
		i += 1;
		pyMessageBuffer.emplace_back(std::to_wstring(i) + L". " + str + L"\n");
	}
	pyMessageBuffer.emplace_back(L"Selected 1 by default.\n");

	return options[0];
}

void PyIO::InformUser(const std::wstring& information, ImportanceLevel level) const{
	auto mutex = AcquireMutex(hMutex);
	pyMessageBuffer.emplace_back(INFORM_ID + descriptions[static_cast<DWORD>(level)] + L" " + information + L"\n");
}
bool PyIO::AlertUser(const std::wstring& information, DWORD dwMaximumDelay, ImportanceLevel level) const{
	auto mutex = AcquireMutex(hMutex);
	pyMessageBuffer.emplace_back(ALERT_ID + descriptions[static_cast<DWORD>(level)] + L" " + information + L"\n");
	pyMessageBuffer.emplace_back(L"Continuing without waiting for user confirmation...\n");
	return true;
}

DWORD PyIO::GetUserConfirm(const std::wstring& prompt, DWORD dwMaximumDelay, ImportanceLevel level) const{
	auto mutex = AcquireMutex(hMutex);
	pyMessageBuffer.emplace_back(CONFIRM_ID + descriptions[static_cast<DWORD>(level)] + L" " + prompt + L"\n");
	pyMessageBuffer.emplace_back(L"Accepting without waiting for user confirmation...\n");
	return 1;
}

const HandleWrapper& PyIO::GetMutex() const{
	return hMutex;
}