#include "util/users/users.h"
#include "util/log/Log.h"

namespace Permissions {
	SecurityDescriptor::SecurityDescriptor(DWORD dwSize, SecurityDescriptor::SecurityDataType type) :
		GenericWrapper<PISECURITY_DESCRIPTOR>(reinterpret_cast<PISECURITY_DESCRIPTOR>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize)),
			[](LPVOID memory) { HeapFree(GetProcessHeap(), 0, memory); }, nullptr) {
		switch (type) {
		case SecurityDescriptor::SecurityDataType::USER_SID:
			lpUserSid = reinterpret_cast<PSID>(WrappedObject);
			break;
		case SecurityDescriptor::SecurityDataType::GROUP_SID:
			lpGroupSid = reinterpret_cast<PSID>(WrappedObject);
			break;
		case SecurityDescriptor::SecurityDataType::DACL:
			dacl = reinterpret_cast<PACL>(WrappedObject);
			break;
		case SecurityDescriptor::SecurityDataType::SACL:
			sacl = reinterpret_cast<PACL>(WrappedObject);
			break;
		}
	}

	SecurityDescriptor::SecurityDescriptor(PISECURITY_DESCRIPTOR lpSecurity) :
		GenericWrapper<PISECURITY_DESCRIPTOR>(lpSecurity, LocalFree, nullptr) {
		if (lpSecurity) {
			lpUserSid = lpSecurity->Owner;
			lpGroupSid = lpSecurity->Group;
			dacl = lpSecurity->Dacl;
			sacl = lpSecurity->Sacl;
		}
	}

	SecurityDescriptor SecurityDescriptor::CreateUserSID(DWORD dwSize) {
		return SecurityDescriptor(dwSize, SecurityDescriptor::SecurityDataType::USER_SID);
	}

	SecurityDescriptor SecurityDescriptor::CreateGroupSID(DWORD dwSize) {
		return SecurityDescriptor(dwSize, SecurityDescriptor::SecurityDataType::GROUP_SID);
	}

	SecurityDescriptor SecurityDescriptor::CreateDACL(DWORD dwSize) {
		return SecurityDescriptor(dwSize, SecurityDescriptor::SecurityDataType::DACL);
	}

	SecurityDescriptor SecurityDescriptor::CreateSACL(DWORD dwSize) {
		return SecurityDescriptor(dwSize, SecurityDescriptor::SecurityDataType::SACL);
	}

	PACL SecurityDescriptor::GetDACL() const { return this->dacl; }
	PACL SecurityDescriptor::GetSACL() const { return this->sacl; }
	PSID SecurityDescriptor::GetUserSID() const { return this->lpUserSid; }
	PSID SecurityDescriptor::GetGroupSID() const { return this->lpGroupSid; }

	User::User(IN const std::wstring& uName) : Username{ uName }, bUserExists{ true } {

		DWORD dwSIDLen{};
		DWORD DomainLen{};
		SID_NAME_USE SidType{};
		LookupAccountNameW(nullptr, Username.c_str(), nullptr, &dwSIDLen, nullptr, &DomainLen, &SidType);

		sUserSID = SecurityDescriptor::CreateUserSID(dwSIDLen);
		std::vector<WCHAR> Domain(DomainLen);
		if (!LookupAccountNameW(nullptr, Username.c_str(), sUserSID.GetUserSID(), &dwSIDLen, Domain.data(), &DomainLen, &SidType)) {
			LOG_ERROR("Error getting user with name " << Username << " " << GetLastError());
			bUserExists = false;
		}
		else {
			DomainName = std::wstring(Domain.data());
			if (SidType == SidTypeDeletedAccount) {
				LOG_VERBOSE(2, "User with name " << Username << " has been deleted.");
				bUserExists = false;
			}
			else if (SidType != SidTypeUser) {
				LOG_VERBOSE(2, "User with name " << Username << " does not exist.");
				bUserExists = false;
			}
			else {
				LOG_VERBOSE(3, "User with name " << Username << " found.");
			}
		}

	}

	User::User(IN const SecurityDescriptor& sid) : sUserSID{ sid }, bUserExists{ true } {
		DWORD DomainLen = 0;
		DWORD NameLen = 0;
		SID_NAME_USE eUse = SidTypeUnknown;
		LookupAccountSidW(nullptr, sUserSID.GetUserSID(), nullptr, &NameLen, nullptr, &DomainLen, &eUse);

		std::vector<WCHAR> Domain(DomainLen);
		std::vector<WCHAR> Name(NameLen);

		if (!LookupAccountSid(nullptr, sUserSID.GetUserSID(), Name.data(), &NameLen, Domain.data(), &DomainLen, &eUse)) {
			LOG_ERROR("Error getting user " << GetLastError());
			bUserExists = false;
		}
		else {
			DomainName = std::wstring(Domain.data());
			Username = std::wstring(Name.data());
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
			}
		}
	}

	std::wstring User::ToString() const {
		return Username;
	}
}