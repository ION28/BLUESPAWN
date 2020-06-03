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

std::vector<void*> GetExecutableNonImageSections(unsigned int pid){
    // Make use of APIs in PE Sieve...
    return {};
}

std::string GetProcessCommandline(const HandleWrapper& process){
    if(process){
        PROCESS_BASIC_INFORMATION information{};
        NTSTATUS status = Linker::NtQueryInformationProcess(process, ProcessBasicInformation, &information, sizeof(information), nullptr);
        if(NT_SUCCESS(status)){
            auto peb = information.PebBaseAddress;

            ULONG_PTR pointer{};
            if(!ReadProcessMemory(process, &peb->ProcessParameters, &pointer, sizeof(pointer), nullptr)){
                LOG_ERROR("Unable to read memory from process with PID " << GetProcessId(process) << " to find its command line (error " << errno << ")");
                return {};
            }
            RTL_USER_PROCESS_PARAMETERS_ params{};
            if(!ReadProcessMemory(process, void*(pointer), &params, sizeof(params), nullptr)){
                LOG_ERROR("Unable to read memory from process with PID " << GetProcessId(process) << " to find its command line (error " << errno << ")");
                return {};
            }

            unsigned int dwLength = params.CommandLine.Length;
            auto cmdline = AllocationWrapper{ new WCHAR[dwLength / 2 + 1], dwLength + 2, AllocationWrapper::CPP_ARRAY_ALLOC };
            if(!ReadProcessMemory(process, params.CommandLine.Buffer, cmdline, dwLength, nullptr)){
                LOG_ERROR("Unable to read memory from process with PID " << GetProcessId(process) << " to find its command line (error " << errno << ")");
                return {};
            }
            cmdline.SetByte(dwLength, 0);
            cmdline.SetByte(dwLength + 1, 0);

            return std::string{ reinterpret_cast<PWCHAR>(void*(cmdline)) };
        } else{
            LOG_ERROR("Unable to query information from process with PID " << GetProcessId(process) << " to find its command line (error " << status << ")");
            return {};
        }
    } else{
        LOG_ERROR("Unable to get command line of invalid process");
        return {};
    }
}

std::string GetProcessCommandline(unsigned int dwPID){
    HandleWrapper process{ OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, dwPID) };
    if(process){
        return GetProcessCommandline(process);
    } else{
        LOG_ERROR("Unable to open process with PID " << dwPID << " to find its command line (error " << errno << ")");
        return {};
    }
}

std::string GetProcessImage(const HandleWrapper& process){
    if(process){
        PROCESS_BASIC_INFORMATION information{};
        NTSTATUS status = Linker::NtQueryInformationProcess(process, ProcessBasicInformation, &information, sizeof(information), nullptr);
        if(NT_SUCCESS(status)){
            auto peb = information.PebBaseAddress;
            RTL_USER_PROCESS_PARAMETERS_ params{};
            if(!ReadProcessMemory(process, &peb->ProcessParameters, &params, sizeof(params), nullptr)){
                LOG_ERROR("Unable to read memory from process with PID " << GetProcessId(process) << " to find its image path (error " << errno << ")");
                return {};
            }

            unsigned int dwLength = params.DllPath.Length;
            auto path = AllocationWrapper{ new WCHAR[dwLength / 2 + 1], dwLength + 2, AllocationWrapper::CPP_ARRAY_ALLOC };
            if(!ReadProcessMemory(process, &peb->ProcessParameters, &params, sizeof(params), nullptr)){
                LOG_ERROR("Unable to read memory from process with PID " << GetProcessId(process) << " to find its image path (error " << errno << ")");
                return {};
            }

            if(!ReadProcessMemory(process, &params.DllPath.Buffer, path, dwLength, nullptr)){
                LOG_ERROR("Unable to read memory from process with PID " << GetProcessId(process) << " to find its image path (error " << errno << ")");
                return {};
            }
            path.SetByte(dwLength, 0);
            path.SetByte(dwLength + 1, 0);

            return std::string{ reinterpret_cast<PWCHAR>(void*(path)) };
        } else{
            LOG_ERROR("Unable to query information from process with PID " << GetProcessId(process) << " to find its image path (error " << status << ")");
            return {};
        }
    } else{
        LOG_ERROR("Unable to get command line of invalid process");
        return {};
    }
}

std::string GetProcessImage(unsigned int dwPID){
    HandleWrapper process{ OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, dwPID) };
    if(process){
        return GetProcessImage(process);
    } else{
        LOG_ERROR("Unable to open process with PID " << dwPID << " to find its command line (error " << errno << ")");
        return {};
    }
}

std::vector<std::string> EnumModules(unsigned int dwPID){
    HandleWrapper hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, dwPID);
    if(hProcess){
        return EnumModules(hProcess);
    } else{
        LOG_ERROR("Unable to open process with PID " << dwPID << " to enumerate its modules (error " << errno << ")");
        return {};
    }

}

std::vector<std::string> EnumModules(const HandleWrapper& hProcess){
    std::vector<HMODULE> modules(1024);
    unsigned int dwBytesNeeded{};
    auto status{ EnumProcessModules(hProcess, modules.data(), 1024 * sizeof(HMODULE), &dwBytesNeeded) };
    if(dwBytesNeeded > 1024 * sizeof(HMODULE)){
        modules.resize(dwBytesNeeded / sizeof(HMODULE));
        status = EnumProcessModules(hProcess, modules.data(), dwBytesNeeded, &dwBytesNeeded);
    }

    std::vector<std::string> vModules{};

    if(status){
        for(auto mod : modules){
            WCHAR path[MAX_PATH];
            if(GetModuleFileNameExW(hProcess, mod, path, MAX_PATH)){
                vModules.emplace_back(path);
            } else{
                LOG_ERROR("Unable to get name of module at " << mod << " in process with PID " << GetProcessId(hProcess));
            }
        }
    } else{
        LOG_ERROR("Unable to enumerate modules in process with PID " << GetProcessId(hProcess) << " (Error " << errno << ")");
    }

    return vModules;
}

void* GetModuleAddress(unsigned int dwPID, const std::string& wsModuleName){
    HandleWrapper hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, dwPID);
    if(hProcess){
        return GetModuleAddress(hProcess, wsModuleName);
    } else{
        LOG_ERROR("Unable to open process with PID " << dwPID << " to enumerate its modules (error " << errno << ")");
        return {};
    }

}

void* GetModuleAddress(const HandleWrapper& hProcess, const std::string& wsModuleName){
    std::vector<HMODULE> modules(1024);
    unsigned int dwBytesNeeded{};
    auto status{ EnumProcessModules(hProcess, modules.data(), 1024 * sizeof(HMODULE), &dwBytesNeeded) };
    if(dwBytesNeeded > 1024 * sizeof(HMODULE)){
        modules.resize(dwBytesNeeded / sizeof(HMODULE));
        status = EnumProcessModules(hProcess, modules.data(), dwBytesNeeded, &dwBytesNeeded);
    }

    if(status){
        for(auto mod : modules){
            WCHAR path[MAX_PATH];
            if(GetModuleFileNameExW(hProcess, mod, path, MAX_PATH)){
                if(path == wsModuleName){
                    return mod;
                }
            } else{
                LOG_ERROR("Unable to get name of module at " << mod << " in process with PID " << GetProcessId(hProcess));
            }
        }
    } else{
        LOG_ERROR("Unable to enumerate modules in process with PID " << GetProcessId(hProcess) << " (Error " << errno << ")");
    }

    LOG_ERROR("Unable to find address of module " << wsModuleName << " in process with PID " << GetProcessId(hProcess));
    return nullptr;
}

unsigned int GetRegionSize(const HandleWrapper& hProcess, void* lpBaseAddress){
    unsigned int dwImageSize = 0;
    ULONG_PTR address = reinterpret_cast<ULONG_PTR>(lpBaseAddress);

    while(true){
        MEMORY_BASIC_INFORMATION memory{};
        if(VirtualQueryEx(hProcess, reinterpret_cast<void*>(address), &memory, sizeof(memory))){
            if(memory.AllocationBase == lpBaseAddress){
                dwImageSize += memory.RegionSize;
                address += memory.RegionSize;
            } else break;
        } else break;
    }

    LOG_VERBOSE(2, "Determined the size of the region to remove is " << dwImageSize);
    return dwImageSize;
}

unsigned int GetRegionSize(unsigned int dwPID, void* lpBaseAddress){
    HandleWrapper hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, dwPID);
    if(hProcess){
        return GetRegionSize(hProcess, lpBaseAddress);
    } else{
        LOG_ERROR("Unable to open process with PID " << dwPID << " to determine size of region at " << lpBaseAddress << " (error " << errno << ")");
        return {};
    }

}

std::optional<FileSystem::File> GetMappedFile(unsigned int dwPID, void* lpAllocationBase){
    HandleWrapper hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, dwPID);
    if(hProcess){
        return GetMappedFile(hProcess, lpAllocationBase);
    } else{
        LOG_ERROR("Unable to open process with PID " << dwPID << " to determine size of region at " << lpAllocationBase << " (error " << errno << ")");
        return {};
    }
}

std::optional<FileSystem::File> GetMappedFile(const HandleWrapper& hProcess, void* lpAllocationBase){
    std::vector<WCHAR> filename(MAX_PATH);
    auto len = GetMappedFileNameW(hProcess, lpAllocationBase, filename.data(), MAX_PATH);
    if(!len){
        return std::nullopt;
    }

    return FileSystem::File(std::string{ filename.data(), len });
}

namespace Utils::Process{
    AllocationWrapper ReadProcessMemory(const HandleWrapper& hProcess, void* lpBaseAddress, unsigned int dwSize){
        if(hProcess){
            if(dwSize == -1){
                dwSize = GetRegionSize(hProcess, lpBaseAddress);
            }

            AllocationWrapper wrapper{ VirtualAlloc(nullptr, dwSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE), dwSize };

            if(::ReadProcessMemory(hProcess, lpBaseAddress, wrapper, dwSize, nullptr)){
                return wrapper;
            } else{
                LOG_ERROR("Unable to read memory at " << lpBaseAddress << " in process with PID " << GetProcessId(hProcess) << " (error " << errno << ")");
            }
        } else{
            LOG_ERROR("Unable to read memory from invalid process!");
        }
        return { nullptr, 0 };
    }

    AllocationWrapper ReadProcessMemory(unsigned int dwPID, void* lpBaseAddress, unsigned int dwSize){
        HandleWrapper hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, dwPID);
        if(hProcess){
            return ReadProcessMemory(hProcess, lpBaseAddress, dwSize);
        } else{
            LOG_ERROR("Unable to open process with PID " << dwPID << " to read memory at " << lpBaseAddress << " (error " << errno << ")");
            return { nullptr, 0 };
        }
    }
}
