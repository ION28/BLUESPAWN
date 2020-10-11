#include "utils/HandleInfo.h"
#include "utils/Common.h"
#include "utils/Debug.h"
#include "utils/ProcessUtils.h"

#include <winternl.h>

#include <optional>

#define ObjectNameInformation static_cast<OBJECT_INFORMATION_CLASS>(1)

namespace BLUESPAWN::Agent{
	namespace Util{
		std::unordered_map<HANDLE, std::pair<HandleType, std::wstring>> handleInfos{};
		CriticalSection guard{};

		void FlushHandleCache(_In_ HANDLE hHandle){
			BeginCriticalSection _(guard);
			if(handleInfos.find(hHandle) != handleInfos.end()){
				handleInfos.erase(hHandle);
			}
		}

		void FlushHandleCache(){
			BeginCriticalSection _(guard);
			handleInfos.clear();
		}

		// Looking up handles can get really nasty; NtQueryObject can hang indefinitely for pipes, and when this
		// happens, the thread performing the lookup must be terminated. To deal with this, a separate worker thread
		// takes care of performing handle lookups. Since creating and destroying threads is a costly procedure, the
		// worker thread will loop infinitely, waiting for hLookupTrigger. When this event is set, the thread will
		// query the handle stored in hQuery. Once it's done, it will store the result in `result` and trigger 
		// hLookupResultTrigger. For obvious reasons, this is a procedure that can be done only once at a time, so
		// any function using any of hQuery, hLookupTrigger, hLookupResultTrigger, or result must first acquire 
		// `guard`.
		namespace HandlesInternal{
			HANDLE hQuery;
			HANDLE hLookupTrigger{ CreateEventW(nullptr, false, false, nullptr) };
			HANDLE hLookupResultTrigger{ CreateEventW(nullptr, false, false, nullptr) };
			CriticalSection guard;
			std::optional<std::wstring> result;
			typedef NTSTATUS(NTAPI* NtQueryObject_t)(
				_In_opt_ HANDLE Handle,
				_In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
				_Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
				_In_ ULONG ObjectInformationLength,
				_Out_opt_ PULONG ReturnLength);
			NtQueryObject_t _NtQueryObject{};

			void ThreadDeleter(HANDLE* phThread){
				if(phThread){
					if(*phThread){
						TerminateThread(*phThread, 0);
						CloseHandle(*phThread);
					}
					delete phThread;
				}
			}
			std::unique_ptr<HANDLE, decltype(&ThreadDeleter)> hThread{ nullptr, &ThreadDeleter };

			void ThreadFunction(){
				if(!_NtQueryObject){
					_NtQueryObject = reinterpret_cast<NtQueryObject_t>(
						GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject"));
				}
				while(true){
					auto status{ WaitForSingleObject(hLookupTrigger, INFINITE) };
					if(status != WAIT_OBJECT_0){
						result = std::nullopt;

						// An error with the lookup trigger has occured; destroy the current (presumably broken) one 
						// and replace it with a new one. Since there's no way to know the state of other threads,
						// just go back to waiting on it. If it turns out that it was triggered, this thread will be
						// reset, which is intended behavior.
						LOG_DEBUG_MESSAGE(LOG_ERROR, "Internal handle lookup thread failed to wait for the lookup "
										  "trigger (error code " << GetLastError() << ")");
						SafeCloseHandle(hLookupTrigger);
						hLookupTrigger = CreateEventW(nullptr, false, false, nullptr);
					} else{
						result = std::nullopt;

						DWORD dwLength{ 0 };
						std::vector<WCHAR> buffer(MAX_PATH);
						NTSTATUS status{};
						while(0xC0000004L == (status = _NtQueryObject(hQuery, ObjectNameInformation, buffer.data(),
																	  buffer.size(), &dwLength))){
							buffer.resize(dwLength + 0x100);
						}
						if(NT_SUCCESS(status)){
							auto pstr{ reinterpret_cast<PUNICODE_STRING>(buffer.data()) };
							result = std::wstring{ pstr->Buffer, pstr->Length / sizeof(WCHAR) };
						}

						if(!SetEvent(hLookupResultTrigger)){

							// Same idea here as with the lookup event for the lookup result event
							LOG_DEBUG_MESSAGE(LOG_ERROR, "Internal handle lookup thread failed to trigger the lookup "
											  "response (error code " << GetLastError() << ")");
							SafeCloseHandle(hLookupResultTrigger);
							hLookupResultTrigger = CreateEventW(nullptr, false, false, nullptr);
						}
					}
				}
			}

			void ResetThread(){
				auto handle =
					CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(&ThreadFunction),
								 nullptr, CREATE_SUSPENDED, nullptr);
				auto phandle = new HANDLE(handle);
				hThread = std::unique_ptr<HANDLE, decltype(&ThreadDeleter)>(phandle, &ThreadDeleter);
			}
		}

		std::pair<HandleType, std::wstring> DeduceHandleInformation(_In_ HANDLE hHandle){
			auto result{ std::make_pair(HandleType::Other, std::wstring{ L"" }) };

			if(hHandle){
				if(!HandlesInternal::_NtQueryObject){
					HandlesInternal::_NtQueryObject = reinterpret_cast<HandlesInternal::NtQueryObject_t>(
						GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject"));
				}

				DWORD dwLength{ 0 };
				std::vector<char> buffer(sizeof(PUBLIC_OBJECT_TYPE_INFORMATION) + 0x100);
				NTSTATUS status = HandlesInternal::_NtQueryObject(hHandle, ObjectTypeInformation, buffer.data(),
																  buffer.size(), &dwLength);
				while(0xC0000004L == status){
					buffer.resize(dwLength + 0x100);
					status = HandlesInternal::_NtQueryObject(hHandle, ObjectTypeInformation, buffer.data(),
															 buffer.size(), &dwLength);
				}

				if(NT_SUCCESS(status)){
					auto typeinfo{ reinterpret_cast<PPUBLIC_OBJECT_TYPE_INFORMATION>(buffer.data()) };
					std::wstring name{ typeinfo->TypeName.Buffer, typeinfo->TypeName.Length / sizeof(WCHAR) };
					if(name == L"File"){
						result.first = HandleType::File;
						// correct file name
					} else if(name == L"Section"){
						result.first = HandleType::Section;
						// correct section name, potentially
					} else if(name == L"Process"){
						result.first = HandleType::Process;
						result.second = Util::GetProcessName(hHandle) + L" (PID " + 
							std::to_wstring(GetProcessId(hHandle)) + L")";
					} else if(name == L"Thread"){
						result.first = HandleType::Thread;
						result.second = L"(TID " + std::to_wstring(GetThreadId(hHandle)) + L")";
					}
				}
			}

			BeginCriticalSection __(guard);

			handleInfos.emplace(hHandle, result);

			return result;
		}

		std::optional<std::wstring> LookupHandle(_In_ HANDLE hHandle){
			FlushHandleCache(hHandle);
			BeginCriticalSection _(HandlesInternal::guard);
			HandlesInternal::hQuery = hHandle;
			HandlesInternal::result = std::nullopt;
			if(!HandlesInternal::hThread){
				HandlesInternal::ResetThread();
				ResumeThread(*HandlesInternal::hThread);
			}
			if(!SetEvent(HandlesInternal::hLookupTrigger)){

				// An error with the lookup trigger has occured; destroy the current (presumably broken) one 
				// and replace it with a new one. Kill the internal thread to reset everything.
				LOG_DEBUG_MESSAGE(LOG_ERROR, "Handle lookup failed to trigger the lookup event (error code " 
								  << GetLastError() << ")");
				HandlesInternal::ResetThread();
				SafeCloseHandle(HandlesInternal::hLookupTrigger);
				HandlesInternal::hLookupTrigger = CreateEventW(nullptr, false, false, nullptr);
				ResumeThread(*HandlesInternal::hThread);
			}
			
			auto wait = WaitForSingleObject(HandlesInternal::hLookupResultTrigger, 100);
			auto res{ HandlesInternal::result };
			if(wait == WAIT_OBJECT_0){
				return res;
			} else if(wait == WAIT_TIMEOUT){
				HandlesInternal::ResetThread();
				ResumeThread(*HandlesInternal::hThread);
				return res;
			} else{

				// An error with the lookup result trigger has occured; destroy the current (presumably broken) one 
				// and replace it with a new one. Kill the internal thread to reset everything.
				LOG_DEBUG_MESSAGE(LOG_ERROR, "Handle lookup failed to listen for the lookup result event (error code "
								  << GetLastError() << ")");
				HandlesInternal::ResetThread();
				SafeCloseHandle(HandlesInternal::hLookupResultTrigger);
				HandlesInternal::hLookupResultTrigger = CreateEventW(nullptr, false, false, nullptr);
				ResumeThread(*HandlesInternal::hThread);

				// try again
				_.Release();
				return LookupHandle(hHandle);
			}
		}

		HandleType GetHandleType(_In_ HANDLE hHandle){
			BeginCriticalSection _(guard);
			if(handleInfos.find(hHandle) != handleInfos.end()){
				return handleInfos.at(hHandle).first;
			}
			_.Release();

			return DeduceHandleInformation(hHandle).first;
		}

		std::wstring GetHandleName(_In_ HANDLE hHandle){
			BeginCriticalSection _(guard);
			if(handleInfos.find(hHandle) != handleInfos.end()){
				return handleInfos.at(hHandle).second;
			}
			_.Release();

			return DeduceHandleInformation(hHandle).second;
		}
	}
}