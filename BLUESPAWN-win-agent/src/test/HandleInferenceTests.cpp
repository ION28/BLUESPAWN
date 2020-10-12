#include "test/HandleInferenceTests.h"

#include <Windows.h>

#include <iostream>

#include "utils/HandleInfo.h"

namespace BLUESPAWN::Agent::Test{
	bool TestFileInference(){
		WCHAR name[260];

		bool error = false;
		if(GetTempFileNameW(L".", nullptr, 0, name)){
			auto file = CreateFileW(name, GENERIC_ALL, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
									nullptr);
			if(file && file != INVALID_HANDLE_VALUE){
				Util::FlushHandleCache(file);
				auto ftype = Util::GetHandleType(file);
				if(ftype != HandleType::File){
					std::wcerr << "[-] Failed to infer type of file " << name << std::endl;
					error = true;
				} else{
					std::cout << "[+] Successfully infered file type!" << std::endl;
				}

				auto fname = Util::GetHandleName(file);
				std::wstring cname{ name };
				auto canonical{ cname.substr(cname.find_last_of(L"\\/") + 1) };
				if(fname.substr(fname.size() - canonical.size()) != canonical){
					std::wcerr << "[-] Failed to infer name of file " << name << std::endl;
					error = true;
				} else{
					std::cout << "[+] Successfully infered file name!" << std::endl;
				}

				CloseHandle(file);
				DeleteFileW(name);
			} else{
				std::wcerr << "[?] Failed to create file to test file inference" << std::endl;
				error = true;
			}
		} else{
			std::wcerr << "[?] Failed to create file to test file inference" << std::endl;
			error = true;
		}
		
		return !error;
	}

	bool TestSectionInference(){
		bool error = false;
		std::wstring name{ L"bluespawn-section-test" };
		auto section = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READONLY | SEC_COMMIT, 0, 0x100, 
										  name.c_str());
		if(section && section != INVALID_HANDLE_VALUE){
			Util::FlushHandleCache(section);
			auto stype = Util::GetHandleType(section);
			if(stype != HandleType::Section){
				std::cerr << "[-] Failed to infer type of section" << std::endl;
				error = true;
			} else{
				std::cout << "[+] Successfully infered type of section" << std::endl;
			}

			auto sname = Util::GetHandleName(section);
			if(sname.substr(sname.length() - name.length()) != name){
				std::cerr << "[-] Failed to infer name of section" << std::endl;
				error = true;
			} else{
				std::cout << "[+] Successfully infered name of section" << std::endl;
			}

			CloseHandle(section);
		} else{
			std::wcerr << "[?] Failed to create section to test section inference" << std::endl;
			error = true;
		}
		return error;
	}

	bool TestFileSectionInference(){ 
		// TODO: Implement file-backed section name and file inference
		return false; 
	}

	bool TestProcessThreadInference(){ 
		bool error = false;
		STARTUPINFOW info{};
		info.cb = sizeof(info);
		PROCESS_INFORMATION procinfo{};
		auto status = CreateProcessW(L"C:\\Windows\\explorer.exe", nullptr, nullptr, nullptr, false, CREATE_SUSPENDED,
									 nullptr, nullptr, &info, &procinfo);
		if(status){
			Util::FlushHandleCache(procinfo.hProcess);
			Util::FlushHandleCache(procinfo.hThread);

			auto ptype = Util::GetHandleType(procinfo.hProcess);
			if(ptype != HandleType::Process){
				std::cerr << "[-] Failed to infer type of process" << std::endl;
				error = true;
			} else{
				std::cout << "[+] Successfully infered type of process" << std::endl;
			}

			auto pname = Util::GetHandleName(procinfo.hProcess);
			auto pcorrect = L"C:\\Windows\\explorer.exe (PID " + std::to_wstring(procinfo.dwProcessId) + L")";
			if(pname != pcorrect){
				std::cerr << "[-] Failed to infer name of process" << std::endl;
				error = true;
			} else{
				std::cout << "[+] Successfully infered name of process" << std::endl;
			}

			auto ttype = BLUESPAWN::Agent::Util::GetHandleType(procinfo.hThread);
			if(ttype != BLUESPAWN::Agent::HandleType::Thread){
				std::cerr << "[-] Failed to infer type of thread" << std::endl;
				error = true;
			} else{
				std::cout << "[+] Successfully infered type of thread" << std::endl;
			}

			auto tname = Util::GetHandleName(procinfo.hThread);
			auto tcorrect = L"(TID " + std::to_wstring(procinfo.dwThreadId) + L")";
			if(tname != tcorrect){
				std::cerr << "[-] Failed to infer name of thread" << std::endl;
				error = true;
			} else{
				std::cout << "[+] Successfully infered name of thread" << std::endl;
			}

			TerminateProcess(procinfo.hProcess, 0);
			CloseHandle(procinfo.hProcess);
			CloseHandle(procinfo.hThread);
		} else{
			std::wcerr << "[?] Failed to create process and thread to test process and thread inference" << std::endl;
			error = true;
		}
		return error;
	}

	bool TestRegistryKeyInference(){
		bool error = false;
		HKEY key = 0;
		auto status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM", 0, KEY_READ, &key);
		if(!status && key){
			Util::FlushHandleCache(key);
			auto ktype = Util::GetHandleType(key);
			if(ktype != HandleType::RegistryKey){
				std::cerr << "[-] Failed to infer type of registry key" << std::endl;
				error = true;
			} else{
				std::cout << "[+] Successfully infered type of registry key" << std::endl;
			}

			auto kname = Util::GetHandleName(key);
			if(kname != L"\\REGISTRY\\MACHINE\\SYSTEM"){
				std::cerr << "[-] Failed to infer name of registry key" << std::endl;
				error = true;
			} else{
				std::cout << "[+] Successfully infered name of registry key" << std::endl;
			}

			RegCloseKey(key);
		} else{
			std::wcerr << "[?] Failed to open registry key to test key inference" << std::endl;
			error = true;
		}

		return error;
	}

	bool TestTokenInference(){ 
		bool error = false;
		HANDLE hToken = nullptr;
		auto status = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
		if(hToken && status){
			Util::FlushHandleCache(hToken);
			auto ttype = Util::GetHandleType(hToken);
			if(ttype != HandleType::Token){
				std::cerr << "[-] Failed to infer type of token" << std::endl;
				error = true;
			} else{
				std::cout << "[+] Successfully infered type of token" << std::endl;
			}

			CloseHandle(hToken);
		} else{
			std::wcerr << "[?] Failed to open current process's token to token inference" << std::endl;
			error = true;
		}

		return error;
	}

	bool TestSynchronizationInference(){
		bool error = false;
		std::wstring evtName{ L"bluespawn-evt-test" };
		HANDLE hEvent = CreateEventW(nullptr, false, false, evtName.c_str());
		if(hEvent && hEvent != INVALID_HANDLE_VALUE){
			Util::FlushHandleCache(hEvent);
			auto etype = Util::GetHandleType(hEvent);
			if(etype != HandleType::Synchronization){
				std::cerr << "[-] Failed to infer type of event" << std::endl;
				error = true;
			} else{
				std::cout << "[+] Successfully infered type of event" << std::endl;
			}

			auto ename = Util::GetHandleName(hEvent);
			if(ename.substr(ename.length() - evtName.length()) != evtName){
				std::cerr << "[-] Failed to infer name of event" << std::endl;
				error = true;
			} else{
				std::cout << "[+] Successfully infered name of event" << std::endl;
			}

			CloseHandle(hEvent);
		} else{
			std::wcerr << "[?] Failed to open create event for event inference" << std::endl;
			error = true;
		}

		return error;
	}
};