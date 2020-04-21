#include "util/users/users.h"
#include "util/log/Log.h"

namespace Users {
	User::User(IN const std::wstring uName) {
		LPWSTR Domain;
		DWORD sidLen = 0;
		DWORD DomainLen = 0;
		SID_NAME_USE SidType;
		bUserExists = true;
		Username = uName;
		LookupAccountName(NULL, uName.c_str(), NULL, &sidLen, NULL, &DomainLen, &SidType);
		sUserSID = AllocationWrapper{ HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sidLen), sidLen, AllocationWrapper::HEAP_ALLOC };
		Domain = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DomainLen);
		if (Domain == NULL) {
			LOG_ERROR("Heap allocation failed. Error: " << GetLastError());
		}
		else {
			if (!LookupAccountName(NULL, uName.c_str(), sUserSID, &sidLen, Domain, &DomainLen, &SidType)) {
				LOG_ERROR("Error getting user with name " << uName << " " << GetLastError());
				bUserExists = false;
			}
			else {
				DomainName = std::wstring(Domain);
				if (SidType == SidTypeDeletedAccount) {
					LOG_VERBOSE(2, "User with name " << uName << " has been deleted.");
					bUserExists = false;
				}
				else if (SidType != SidTypeUser) {
					LOG_VERBOSE(2, "User with name " << uName << " does not exist.");
					bUserExists = false;
				}
				else {
					bUserExists = true;
					LOG_VERBOSE(3, "User with name " << uName << " found.");
				}
			}
			HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, Domain);
		}
	}

	User::User(IN const PSID sid) {
		LPWSTR Domain;
		DWORD DomainLen = 0;
		LPWSTR Name;
		DWORD NameLen = 0;
		sUserSID = sid;
		bUserExists = true;
		SID_NAME_USE eUse = SidTypeUnknown;
		LookupAccountSid(NULL, sid, NULL, &NameLen, NULL, &DomainLen, &eUse);

		Domain = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DomainLen);
		if (Domain == NULL) {
			LOG_ERROR("Couldn't allocate memory. Error " << GetLastError());
		}
		else {
			Name = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, NameLen);
			if (Name == NULL) {
				LOG_ERROR("Couldn't allocate memory. Error " << GetLastError());
			}
			else {
				if (!LookupAccountSid(NULL, sid, Name, &NameLen, Domain, &DomainLen, &eUse)) {
					LOG_ERROR("Error getting user " << GetLastError());
					bUserExists = false;
				}
				else {
					DomainName = std::wstring(Domain);
					Username = std::wstring(Name);
					if (eUse == SidTypeDeletedAccount) {
						LOG_VERBOSE(2, "User " << Username << " has been deleted.");
						bUserExists = false;
					}
					else if (eUse != SidTypeUser) {
						LOG_VERBOSE(2, "User doesn't exist.");
						bUserExists = false;
					}
					else {
						LOG_VERBOSE(3, "User " << Username << " Exists.");
						bUserExists = true;
					}
				}
				HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, Name);
			}
			HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, Domain);
		}
	}
	
	std::wstring User::ToString() const {
		return Username;
	}
}