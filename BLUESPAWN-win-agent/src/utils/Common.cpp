#include "utils/Common.h"

namespace BLUESPAWN::Agent::Util {
	CriticalSection::CriticalSection(){
		counter = {
			new CRITICAL_SECTION{}, [](PCRITICAL_SECTION section) mutable{
				DeleteCriticalSection(section);
				delete section;
			}
		};
		InitializeCriticalSection(&*counter);
	}

	CriticalSection::operator LPCRITICAL_SECTION() const{ return static_cast<LPCRITICAL_SECTION>(&*counter); }

	BeginCriticalSection::BeginCriticalSection(_In_ const CriticalSection& section) :
		critsec{ section }{
		::EnterCriticalSection(critsec);
	}

	BeginCriticalSection::~BeginCriticalSection(){
		if(!released){
			::LeaveCriticalSection(critsec);
		}
	}

	void BeginCriticalSection::Acquire(){
		if(released){
			EnterCriticalSection(critsec);
		}
		released = false;
	}

	void BeginCriticalSection::Release(){
		if(!released){
			LeaveCriticalSection(critsec);
		}
		released = true;
	}

	void SafeCloseHandle(_In_ HANDLE handle){
		BY_HANDLE_FILE_INFORMATION hInfo;
		if(GetFileInformationByHandle(handle, &hInfo)){
			CloseHandle(handle);
		} else{
			HRESULT a = GetLastError();
			if(a != ERROR_INVALID_HANDLE){
				CloseHandle(handle);
			}
		}
	}
}