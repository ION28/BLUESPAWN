#include "util/processes/ProcessUtils.h"

#include <Psapi.h>

#include "util/filesystem/FileSystem.h"
#include "shlwapi.h"

#include "util/log/Log.h"

typedef struct _CURDIR {
    UNICODE_STRING DosPath;
    PVOID Handle;
} CURDIR, * PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    WORD Flags;
    WORD Length;
    ULONG TimeStamp;
    STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;


typedef struct _RTL_USER_PROCESS_PARAMETERS_ {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    PVOID ConsoleHandle;
    ULONG ConsoleFlags;
    PVOID StandardInput;
    PVOID StandardOutput;
    PVOID StandardError;
    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
    ULONG EnvironmentSize;
} RTL_USER_PROCESS_PARAMETERS_, * PRTL_USER_PROCESS_PARAMETERS_;

bool HookIsOkay(const Hook& hook){
	// Once Detours is set up, this will become significantly more complicated...
	return false;
}

std::vector<LPVOID> GetExecutableNonImageSections(DWORD pid){
	// Make use of APIs in PE Sieve...
	return {};
}

std::wstring GetProcessCommandline(const HandleWrapper& process){
	if(process){
		PROCESS_BASIC_INFORMATION information{};
		NTSTATUS status = Linker::NtQueryInformationProcess(process, ProcessBasicInformation, &information, sizeof(information), nullptr);
		if(NT_SUCCESS(status)){
			auto peb = information.PebBaseAddress;

            ULONG_PTR pointer{};
            if(!ReadProcessMemory(process, &peb->ProcessParameters, &pointer, sizeof(pointer), nullptr)){
                LOG_ERROR("Unable to read memory from process with PID " << GetProcessId(process) << " to find its command line (error " << GetLastError() << ")");
                return {};
            }
            RTL_USER_PROCESS_PARAMETERS_ params{};
            if(!ReadProcessMemory(process, LPVOID(pointer), &params, sizeof(params), nullptr)){
                LOG_ERROR("Unable to read memory from process with PID " << GetProcessId(process) << " to find its command line (error " << GetLastError() << ")");
                return {};
            }

            DWORD dwLength = params.CommandLine.Length;
            auto cmdline = AllocationWrapper{ new WCHAR[dwLength / 2 + 1], dwLength + 2, AllocationWrapper::CPP_ARRAY_ALLOC };
            if(!ReadProcessMemory(process, params.CommandLine.Buffer, cmdline, dwLength, nullptr)){
                LOG_ERROR("Unable to read memory from process with PID " << GetProcessId(process) << " to find its command line (error " << GetLastError() << ")");
                return {};
            }
            cmdline.SetByte(dwLength, 0);
            cmdline.SetByte(dwLength + 1, 0);

            return std::wstring{ reinterpret_cast<PWCHAR>(LPVOID(cmdline)) };
		} else {
			LOG_ERROR("Unable to query information from process with PID " << GetProcessId(process) << " to find its command line (error " << status << ")");
            return {};
		}
	} else {
		LOG_ERROR("Unable to get command line of invalid process");
		return {};
	}
}

std::wstring GetProcessCommandline(DWORD dwPID){
    HandleWrapper process{ OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, dwPID) };
    if(process){
        return GetProcessCommandline(process);
    } else {
        LOG_ERROR("Unable to open process with PID " << dwPID << " to find its command line (error " << GetLastError() << ")");
        return {};
    }
}

std::wstring GetProcessImage(const HandleWrapper& process){
    if(process){
        PROCESS_BASIC_INFORMATION information{};
        NTSTATUS status = Linker::NtQueryInformationProcess(process, ProcessBasicInformation, &information, sizeof(information), nullptr);
        if(NT_SUCCESS(status)){
            auto peb = information.PebBaseAddress;
            RTL_USER_PROCESS_PARAMETERS_ params{};
            if(!ReadProcessMemory(process, &peb->ProcessParameters, &params, sizeof(params), nullptr)){
                LOG_ERROR("Unable to read memory from process with PID " << GetProcessId(process) << " to find its image path (error " << GetLastError() << ")");
                return {};
            }

            DWORD dwLength = params.DllPath.Length;
            auto path = AllocationWrapper{ new WCHAR[dwLength / 2 + 1], dwLength + 2, AllocationWrapper::CPP_ARRAY_ALLOC };
            if(!ReadProcessMemory(process, &peb->ProcessParameters, &params, sizeof(params), nullptr)){
                LOG_ERROR("Unable to read memory from process with PID " << GetProcessId(process) << " to find its image path (error " << GetLastError() << ")");
                return {};
            }

            if(!ReadProcessMemory(process, &params.DllPath.Buffer, path, dwLength, nullptr)){
                LOG_ERROR("Unable to read memory from process with PID " << GetProcessId(process) << " to find its image path (error " << GetLastError() << ")");
                return {};
            }
            path.SetByte(dwLength, 0);
            path.SetByte(dwLength + 1, 0);

            return std::wstring{ reinterpret_cast<PWCHAR>(LPVOID(path)) };
        } else {
            LOG_ERROR("Unable to query information from process with PID " << GetProcessId(process) << " to find its image path (error " << status << ")");
            return {};
        }
    } else {
        LOG_ERROR("Unable to get command line of invalid process");
        return {};
    }
}

std::wstring GetImagePathFromCommand(std::wstring wsCmd){
    if(wsCmd.substr(0, 11) == L"\\SystemRoot"){
        wsCmd = L"%SYSTEMROOT%" + wsCmd.substr(11);
    }

    wsCmd = ExpandEnvStringsW(wsCmd);
    
    auto start = wsCmd.find_first_not_of(L" \f\v\t\n\r", 0);
    if(wsCmd.substr(start, 4) == L"\\??\\"){
        start += 4;
    }
    if(start == std::wstring::npos){
        return L"";
    } else if(wsCmd.at(start) == '"' || wsCmd.at(start) == '\''){
        auto name = wsCmd.substr(start + 1, wsCmd.find_first_of(L"'\"", start + 1) - start - 1);
        auto path = FileSystem::SearchPathExecutable(name);
        if(path){
            return *path;
        } else return name;
    } else {
        auto idx = start;
        while(idx != std::wstring::npos){
            auto spacepos = wsCmd.find(L" ", idx);
            auto name = wsCmd.substr(start, spacepos - start);
            auto path = FileSystem::SearchPathExecutable(name);
            if(path && FileSystem::CheckFileExists(*path)){
                return *path;
            }

            if(name.length() > 4 && CompareIgnoreCaseW(name.substr(name.length() - 4), L".exe")){
                return name;
            }

            if(spacepos == std::wstring::npos){
                return name;
            }
            
            idx = spacepos + 1;
        }

        return wsCmd.substr(start, wsCmd.find_first_of(L" \t\n\r", start) - start);
    }
}

std::wstring GetProcessImage(DWORD dwPID){
    HandleWrapper process{ OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, dwPID) };
    if(process){
        return GetProcessImage(process);
    } else {
        LOG_ERROR("Unable to open process with PID " << dwPID << " to find its command line (error " << GetLastError() << ")");
        return {};
    }
}

std::vector<std::wstring> EnumModules(DWORD dwPID){
    HandleWrapper hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, dwPID);
    if(hProcess){
        return EnumModules(hProcess);
    } else {
        LOG_ERROR("Unable to open process with PID " << dwPID << " to enumerate its modules (error " << GetLastError() << ")");
        return {};
    }

}

std::vector<std::wstring> EnumModules(const HandleWrapper& hProcess){
    std::vector<HMODULE> modules(1024);
    DWORD dwBytesNeeded{};
    auto status{ EnumProcessModules(hProcess, modules.data(), 1024 * sizeof(HMODULE), &dwBytesNeeded) };
    if(dwBytesNeeded > 1024 * sizeof(HMODULE)){
        modules.resize(dwBytesNeeded / sizeof(HMODULE));
        status = EnumProcessModules(hProcess, modules.data(), dwBytesNeeded, &dwBytesNeeded);
    }

    std::vector<std::wstring> vModules{};

    if(status){
        for(auto mod : modules){
            WCHAR path[MAX_PATH];
            if(GetModuleFileNameExW(hProcess, mod, path, MAX_PATH)){
                vModules.emplace_back(path);
            } else {
                LOG_ERROR("Unable to get name of module at " << mod << " in process with PID " << GetProcessId(hProcess));
            }
        }
    } else {
        LOG_ERROR("Unable to enumerate modules in process with PID " << GetProcessId(hProcess) << " (Error " << GetLastError() << ")");
    }

    return vModules;
}

LPVOID GetModuleAddress(DWORD dwPID, const std::wstring& wsModuleName){
    HandleWrapper hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, dwPID);
    if(hProcess){
        return GetModuleAddress(hProcess, wsModuleName);
    } else {
        LOG_ERROR("Unable to open process with PID " << dwPID << " to enumerate its modules (error " << GetLastError() << ")");
        return {};
    }

}

LPVOID GetModuleAddress(const HandleWrapper& hProcess, const std::wstring& wsModuleName){
    std::vector<HMODULE> modules(1024);
    DWORD dwBytesNeeded{};
    auto status{ EnumProcessModules(hProcess, modules.data(), 1024 * sizeof(HMODULE), &dwBytesNeeded) };
    if(dwBytesNeeded > 1024 * sizeof(HMODULE)){
        modules.resize(dwBytesNeeded / sizeof(HMODULE));
        status = EnumProcessModules(hProcess, modules.data(), dwBytesNeeded, &dwBytesNeeded);
    }

    std::vector<std::wstring> vModules{};

    std::vector<HMODULE> modules(1024);
    DWORD dwBytesNeeded{};
    auto status{ EnumProcessModules(hProcess, modules.data(), 1024 * sizeof(HMODULE), &dwBytesNeeded) };
    if(dwBytesNeeded > 1024 * sizeof(HMODULE)){
        modules.resize(dwBytesNeeded / sizeof(HMODULE));
        status = EnumProcessModules(hProcess, modules.data(), dwBytesNeeded, &dwBytesNeeded);
    }

    std::vector<std::wstring> vModules{};

    if(status){
        for(auto mod : modules){
            WCHAR path[MAX_PATH];
            if(GetModuleFileNameExW(hProcess, mod, path, MAX_PATH)){
                if(path == wsModuleName){
                    return mod;
                }
            } else {
                LOG_ERROR("Unable to get name of module at " << mod << " in process with PID " << GetProcessId(hProcess));
            }
        }
    } else {
        LOG_ERROR("Unable to enumerate modules in process with PID " << GetProcessId(hProcess) << " (Error " << GetLastError() << ")");
    }

    LOG_ERROR("Unable to find address of module " << wsModuleName << " in process with PID " << GetProcessId(hProcess));
    return nullptr;
}

DWORD GetRegionSize(const HandleWrapper& hProcess, LPVOID lpBaseAddress){
    DWORD dwImageSize = 0;
    ULONG_PTR address = reinterpret_cast<ULONG_PTR>(lpBaseAddress);

    while(true){
        MEMORY_BASIC_INFORMATION memory{};
        if(VirtualQueryEx(hProcess, reinterpret_cast<LPVOID>(address), &memory, sizeof(memory))){
            if(memory.AllocationBase == lpBaseAddress){
                dwImageSize += memory.RegionSize;
                address += memory.RegionSize;
            } else break;
        } else break;
    }

    LOG_VERBOSE(2, "Determined the size of the region to remove is " << dwImageSize);
    return dwImageSize;
}

DWORD GetRegionSize(DWORD dwPID, LPVOID lpBaseAddress){
    HandleWrapper hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, dwPID);
    if(hProcess){
        return GetRegionSize(hProcess, lpBaseAddress);
    } else {
        LOG_ERROR("Unable to open process with PID " << dwPID << " to determine size of region at " << lpBaseAddress << " (error " << GetLastError() << ")");
        return {};
    }

}

namespace Utils::Process{
    AllocationWrapper ReadProcessMemory(const HandleWrapper& hProcess, LPVOID lpBaseAddress, DWORD dwSize){
        if(hProcess){
            if(dwSize == -1){
                dwSize = GetRegionSize(hProcess, lpBaseAddress);
            }

            AllocationWrapper wrapper{ VirtualAlloc(nullptr, dwSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE), dwSize };
            
            if(::ReadProcessMemory(hProcess, lpBaseAddress, wrapper, dwSize, nullptr)){
                return wrapper;
            } else {
                LOG_ERROR("Unable to read memory at " << lpBaseAddress << " in process with PID " << GetProcessId(hProcess) << " (error " << GetLastError() << ")");
            }
        } else {
            LOG_ERROR("Unable to read memory from invalid process!");
        }
    }

    AllocationWrapper ReadProcessMemory(DWORD dwPID, LPVOID lpBaseAddress, DWORD dwSize){
        HandleWrapper hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, dwPID);
        if(hProcess){
            return ReadProcessMemory(hProcess, lpBaseAddress, dwSize);
        } else {
            LOG_ERROR("Unable to open process with PID " << dwPID << " to read memory at " << lpBaseAddress << " (error " << GetLastError() << ")");
            return { nullptr, 0 };
        }
    }
}
