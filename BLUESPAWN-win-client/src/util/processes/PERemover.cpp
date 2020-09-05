#include "util/processes/PERemover.h"

#include <DbgHelp.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <Windows.h>
#include <winternl.h>

#include "util/log/Log.h"
#include "util/processes/ProcessUtils.h"

#include "reaction/SuspendProcess.h"

LINK_FUNCTION(NtResumeProcess, NTDLL.DLL)

PERemover::PERemover(const HandleWrapper& hProcess, LPVOID lpBaseAddress, DWORD dwImageSize) :
    hProcess{ hProcess }, lpBaseAddress{ lpBaseAddress }, dwImageSize{ dwImageSize == -1 ?
                                                                           GetRegionSize(hProcess, lpBaseAddress) :
                                                                           dwImageSize } {
    if(!hProcess) {
        auto x = GetLastError();
        LOG_ERROR(L"Failed to retrieve process handle");
    }
}
PERemover::PERemover(DWORD dwPID, LPVOID lpBaseAddress, DWORD dwImageSize) :
    PERemover(OpenProcess(PROCESS_ALL_ACCESS, false, dwPID), lpBaseAddress, dwImageSize) {}
PERemover::PERemover(const HandleWrapper& hProcess, const std::wstring& wsImageName) :
    PERemover(hProcess, GetModuleAddress(hProcess, wsImageName.c_str()), -1) {}
PERemover::PERemover(DWORD dwPID, const std::wstring& wsImageName) :
    PERemover(OpenProcess(PROCESS_ALL_ACCESS, false, dwPID), GetModuleAddress(dwPID, wsImageName.c_str()), -1) {}

bool PERemover::RemoveImage() {
    Linker::NtSuspendProcess(hProcess);
    LOG_VERBOSE(2, "Suspended process with PID " << GetProcessId(hProcess) << " to remove image at " << lpBaseAddress);

    SCOPE_LOCK(Linker::NtResumeProcess(hProcess), RESUME_PROCESS);

    if(CheckThreads() && AdjustPointers() && WipeMemory()) {
        LOG_INFO(2, "Successfully removed image at " << lpBaseAddress << " from process with PID "
                                                     << GetProcessId(hProcess));
        return true;
    }

    LOG_ERROR("Failed to finish removing the memory from process with PID " << GetProcessId(hProcess));
    return false;
}

bool PERemover::AddressIsInRegion(LPVOID lpAddress) {
    return reinterpret_cast<ULONG_PTR>(lpAddress) >= reinterpret_cast<ULONG_PTR>(lpBaseAddress) &&
           reinterpret_cast<ULONG_PTR>(lpAddress) < reinterpret_cast<ULONG_PTR>(lpBaseAddress) + dwImageSize;
}

bool PERemover::CheckThreads() {
    HandleWrapper hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if(!hThreadSnapshot) {
        LOG_ERROR("Unable to open Tool Help Snapshot entry to scan threads"
                  << " (Error " << GetLastError() << ")");
        return false;
    }

    int PID = GetProcessId(hProcess);

    THREADENTRY32 ThreadEntry = { sizeof(THREADENTRY32), 0 };
    if(!Thread32First(hThreadSnapshot, &ThreadEntry)) {
        LOG_ERROR("Unable to open thread  entry to scan threads"
                  << " (Error " << GetLastError() << ")");
        return false;
    }

    do
        if(ThreadEntry.th32OwnerProcessID == PID) {
            HandleWrapper hThread = OpenThread(THREAD_ALL_ACCESS, false, ThreadEntry.th32ThreadID);
            if(!hThread) {
                LOG_ERROR("Unable to open thread with TID " << ThreadEntry.th32ThreadID
                                                            << " to scan for infected memory (Error " << GetLastError()
                                                            << ")");
                return false;
            }

            LOG_VERBOSE(2, "Thread with TID " << ThreadEntry.th32ThreadID
                                              << " detected in target process. Scanning stack now");
            if(!WalkThreadBack(hThread, ThreadEntry.th32ThreadID)) {
                LOG_ERROR("Unable to remove malicious threads from infected process");
                return false;
            }
        }
    while(Thread32Next(hThreadSnapshot, &ThreadEntry));

    return true;
}

/// TODO: Actually walk the thread back instead of terminating it
bool PERemover::WalkThreadBack(const HandleWrapper& hThread, DWORD dwTID) {
    CONTEXT context{};
    ZeroMemory(&context, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_FULL;
    if(!GetThreadContext(hThread, &context)) {
        LOG_ERROR("Unable to get the context of thread in infected process");
        return false;
    }

    STACKFRAME64 stack{};
    stack.AddrPC.Mode = AddrModeFlat;
    stack.AddrStack.Mode = AddrModeFlat;
    stack.AddrFrame.Mode = AddrModeFlat;

#ifdef _WIN64
    stack.AddrPC.Offset = context.Rip;
    stack.AddrStack.Offset = context.Rsp;
    stack.AddrFrame.Offset = context.Rbp;

    DWORD dwMachineType = IMAGE_FILE_MACHINE_AMD64;
    BOOL wow64 = false;
    IsWow64Process(hProcess, &wow64);
    if(wow64) {
        dwMachineType = IMAGE_FILE_MACHINE_I386;
    }

    if(AddressIsInRegion(reinterpret_cast<LPVOID>(context.Rip))) {
        if(TerminateThread(hThread, 0)) {
            LOG_INFO(1, "Thread with TID " << dwTID << " was executing malicious code at "
                                           << reinterpret_cast<LPVOID>(context.Rip) << " and was terminated");
            return true;
        } else {
            LOG_ERROR("Thread with TID " << dwTID << " was executing malicious code at "
                                         << reinterpret_cast<LPVOID>(context.Rip) << " but couldn't terminated"
                                         << " (Error " << GetLastError() << ")");
            return false;
        }
    }
#else
    stack.AddrPC.Offset = context.Eip;
    stack.AddrStack.Offset = context.Esp;
    stack.AddrFrame.Offset = context.Ebp;

    DWORD dwMachineType = IMAGE_FILE_MACHINE_I386;

    if(AddressIsInRegion(reinterpret_cast<LPVOID>(context.Eip))) {
        if(TerminateThread(hThread, 0)) {
            LOG_INFO(1, "Thread with TID " << dwTID << " was executing malicious code at "
                                           << reinterpret_cast<LPVOID>(context.Eip) << " and was terminated");
            return true;
        } else {
            LOG_ERROR("Thread with TID " << dwTID << " was executing malicious code at "
                                         << reinterpret_cast<LPVOID>(context.Eip) << " but couldn't terminated");
            return false;
        }
    }
#endif
    SymInitialize(hProcess, nullptr, true);
    while(StackWalk64(dwMachineType, hProcess, hThread, &stack, &context, nullptr, SymFunctionTableAccess64,
                      SymGetModuleBase64, nullptr)) {
        if(AddressIsInRegion(reinterpret_cast<LPVOID>(stack.AddrPC.Offset))) {
            if(TerminateThread(hThread, 0)) {
                LOG_INFO(1, "Thread with TID " << dwTID << " was executing malicious code at "
                                               << reinterpret_cast<LPVOID>(stack.AddrPC.Offset)
                                               << " and was terminated");
                return true;
            } else {
                LOG_ERROR("Thread with TID " << dwTID << " was executing malicious code at "
                                             << reinterpret_cast<LPVOID>(stack.AddrPC.Offset)
                                             << " but couldn't terminated"
                                             << " (Error " << GetLastError() << ")");
                return false;
            }
        }
    }
    SymCleanup(hProcess);

    return true;
}

DWORD GetFunctionStackSize(LPVOID lpFunction, const HandleWrapper& hProcess, const HandleWrapper& hThread) {
    CONTEXT context{};

    STACKFRAME64 stack{};
    stack.AddrPC.Mode = AddrModeFlat;
    stack.AddrStack.Mode = AddrModeFlat;
    stack.AddrFrame.Mode = AddrModeFlat;
    stack.AddrPC.Offset = reinterpret_cast<ULONG_PTR>(lpFunction);
    stack.AddrStack.Offset = 0x10000;
    stack.AddrFrame.Offset = 0x10000;

    context.ContextFlags = CONTEXT_CONTROL;
#ifdef _WIN64
    context.Rip = reinterpret_cast<ULONG_PTR>(lpFunction);
    context.Rsp = 0x10000;
    context.Rbp = 0x10000;

    DWORD dwMachineType = IMAGE_FILE_MACHINE_AMD64;
    BOOL wow64 = false;
    IsWow64Process(hProcess, &wow64);
    if(wow64) {
        dwMachineType = IMAGE_FILE_MACHINE_I386;
    }

#else
    context.Eip = reinterpret_cast<ULONG_PTR>(lpFunction);
    context.Esp = 0x10000;
    context.Ebp = 0x10000;

    DWORD dwMachineType = IMAGE_FILE_MACHINE_I386;
#endif

    SetThreadContext(hThread, &context);

    SymInitialize(hProcess, nullptr, true);
    if(StackWalk64(dwMachineType, hProcess, hThread, &stack, &context, nullptr, SymFunctionTableAccess64,
                   SymGetModuleBase64, nullptr) &&
       StackWalk64(dwMachineType, hProcess, hThread, &stack, &context, nullptr, SymFunctionTableAccess64,
                   SymGetModuleBase64, nullptr)) {
        if(stack.AddrStack.Offset == 0x10000) {
            return 0;
        }

        return stack.AddrStack.Offset - 0x10000 - sizeof(ULONG_PTR);
    }
    SymCleanup(hProcess);

    return 0;
}

bool PERemover::AdjustPointer(LPVOID lpAddress) {
    LOG_VERBOSE(2, "Updating address " << lpAddress << " to prevent calls to image");

    MEMORY_BASIC_INFORMATION memory{};
    if(!VirtualQueryEx(hProcess, lpAddress, &memory, sizeof(memory))) {
        LOG_ERROR("Unable to read memory protections at " << lpAddress << " (Error " << GetLastError() << ")");
        return false;
    } else {
        if(memory.Protect & 0xF0) {
            LOG_VERBOSE(3, "Address " << lpAddress << " is executable memory; patching with a return");

            // DWORD dwStackChange = GetFunctionStackSize(lpAddress, hProcess, hThread);
            // LOG_VERBOSE(3, "Determined that the function at " << lpAddress << " adds " << dwStackChange << " to the stack");

            DWORD dwOverwriteSize{};

#ifdef _WIN64
            bool x64 = true;
            BOOL wow64 = false;
            IsWow64Process(hProcess, &wow64);
            if(wow64) {
                x64 = false;
            }
#else
            bool x64 = false;
#endif
            // push 0
            // pop rax ; same opcode for pop eax
            // ret
            unsigned char instruction[4]{ 0x6a, 0x00, 0x58, 0xc3 };

            DWORD dwOldProtections{};
            if(!VirtualProtectEx(hProcess, lpAddress, 4, PAGE_READWRITE, &dwOldProtections)) {
                LOG_ERROR("Unable to adjust memory protections at " << lpAddress << " (Error " << GetLastError()
                                                                    << ")");
                return false;
            }
            if(!WriteProcessMemory(hProcess, lpAddress, instruction, 4, nullptr)) {
                LOG_ERROR("Unable to adjust memory protections at " << lpAddress << " (Error " << GetLastError()
                                                                    << ")");
                return false;
            }
            if(!VirtualProtectEx(hProcess, lpAddress, 4, dwOldProtections, &dwOldProtections)) {
                LOG_ERROR("Unable to repair memory protections at " << lpAddress << " (Error " << GetLastError()
                                                                    << ")");
                return false;
            }
        } else {
            LOG_VERBOSE(3, "Address " << lpAddress << " is data; ignoring.");
            // This is likely data and/or a pointer. In the interest of not causing crashes, this will be ignored.
        }
    }
    return true;
}

bool PERemover::AdjustPointers() {
    ULONG_PTR address = 0;
    while(address < (1LL << 48)) {
        MEMORY_BASIC_INFORMATION memory{};
        if(!VirtualQueryEx(hProcess, reinterpret_cast<LPVOID>(address), &memory, sizeof(memory))) {
            return true;
        } else {
            address += memory.RegionSize;

            AllocationWrapper buffer = { VirtualAlloc(nullptr, memory.RegionSize, MEM_COMMIT | MEM_RESERVE,
                                                      PAGE_READWRITE),
                                         memory.RegionSize, AllocationWrapper::VIRTUAL_ALLOC };
            if(ReadProcessMemory(hProcess, memory.BaseAddress, buffer, memory.RegionSize, nullptr)) {
                for(int i = 0; i < memory.RegionSize - sizeof(ULONG_PTR); i++) {
                    auto lpCheckAddress = *reinterpret_cast<LPVOID*>(reinterpret_cast<ULONG_PTR>(LPVOID(buffer)) + i);
                    if(AddressIsInRegion(lpCheckAddress)) {
                        if(!AdjustPointer(lpCheckAddress)) {
                            LOG_ERROR("Unable to adjust pointer to bad memory at " << address + i << " (Error "
                                                                                   << GetLastError() << ")");
                            return false;
                        }
                    }
                }
            }
        }
    }
    return true;
}

bool PERemover::WipeMemory() {
    // For now, this will only wipe exports and the entrypoint.

    AllocationWrapper headers = { VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE), 0x1000,
                                  AllocationWrapper::VIRTUAL_ALLOC };
    if(!ReadProcessMemory(hProcess, lpBaseAddress, headers, 0x1000, nullptr)) {
        LOG_ERROR("Unable to read memory to wipe at " << lpBaseAddress << " (Error " << GetLastError() << ")");
        return false;
    }

    if(headers[0] == 'M' && headers[1] == 'Z') {
        DWORD dwNTHeaderOffset = reinterpret_cast<PIMAGE_DOS_HEADER>(LPVOID(headers))->e_lfanew;

        DWORD dwEntrypointRVA{};
        DWORD dwExportsRVA{};
        DWORD dwExportsSize{};

        if(dwNTHeaderOffset + sizeof(IMAGE_NT_HEADERS64) < 0x1000) {
            auto lpNTHeaders =
                reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PCHAR>(LPVOID(headers)) + dwNTHeaderOffset);
            if(lpNTHeaders->Signature != 0x00004550) {
                return true;
            }

            dwEntrypointRVA = lpNTHeaders->OptionalHeader.AddressOfEntryPoint;
            dwExportsRVA = lpNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            dwExportsSize = lpNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        } else {
            AllocationWrapper NTHeaders = { VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE),
                                            0x1000, AllocationWrapper::VIRTUAL_ALLOC };
            if(!ReadProcessMemory(hProcess, reinterpret_cast<PCHAR>(lpBaseAddress) + dwNTHeaderOffset, NTHeaders,
                                  0x1000, nullptr)) {
                LOG_ERROR("Unable to read memory to wipe at " << lpBaseAddress << " (Error " << GetLastError() << ")");
                return false;
            }

            auto lpNTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(LPVOID(NTHeaders));
            if(lpNTHeaders->Signature != 0x00004550) {
                return true;
            }

            dwEntrypointRVA = lpNTHeaders->OptionalHeader.AddressOfEntryPoint;
            dwExportsRVA = lpNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            dwExportsSize = lpNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }

        if(dwEntrypointRVA && !AdjustPointer(reinterpret_cast<PCHAR>(lpBaseAddress) + dwEntrypointRVA)) {
            LOG_ERROR("Failed to adjust the entrypoint of image to remove");
            return false;
        }

        if(dwExportsRVA && dwExportsSize) {
            AllocationWrapper Exports = { VirtualAlloc(nullptr, dwExportsSize, MEM_COMMIT | MEM_RESERVE,
                                                       PAGE_READWRITE),
                                          dwExportsSize, AllocationWrapper::VIRTUAL_ALLOC };
            if(!ReadProcessMemory(hProcess, reinterpret_cast<PCHAR>(lpBaseAddress) + dwExportsRVA, Exports,
                                  dwExportsSize, nullptr)) {
                LOG_ERROR("Unable to read memory to wipe at " << lpBaseAddress << " (Error " << GetLastError() << ")");
                return false;
            }

            auto lpExports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(LPVOID(Exports));
            auto dwFunctions = lpExports->NumberOfFunctions;
            auto lpFuncionsPtr = reinterpret_cast<PDWORD>(reinterpret_cast<ULONG_PTR>(LPVOID(Exports)) +
                                                          lpExports->AddressOfFunctions - dwExportsRVA);

            for(DWORD i = 0; i < dwFunctions; i++) {
                if(lpFuncionsPtr[i] && !AdjustPointer(reinterpret_cast<PCHAR>(lpBaseAddress) + lpFuncionsPtr[i])) {
                    LOG_ERROR("Failed to adjust an export of image to remove");
                    return false;
                }
            }
        }
    }

    return true;
}
