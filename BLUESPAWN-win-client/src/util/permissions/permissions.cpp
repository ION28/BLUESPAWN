#include "util/permissions/permissions.h"
#include "util/log/Log.h"
#include <lm.h>


namespace Permissions {

	bool AccessIncludesAll(const ACCESS_MASK& access) {
		return ((access & GENERIC_ALL) == GENERIC_ALL) ||
			((access & FILE_ALL_ACCESS) == FILE_ALL_ACCESS);
	}

	bool AccessIncludesWrite(const ACCESS_MASK& access) {
		return AccessIncludesAll(access) || 
			((access & GENERIC_WRITE) == GENERIC_WRITE) ||
			((access & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE);
	}
	
	bool AccessIncludesRead(const ACCESS_MASK& access) {
		return AccessIncludesAll(access) || 
			((access & GENERIC_READ) == GENERIC_READ) || 
			((access & FILE_GENERIC_READ) == FILE_GENERIC_READ);
	}
	
	bool AccessIncludesExecute(const ACCESS_MASK& access) {
		return AccessIncludesAll(access) || 
			((access & GENERIC_EXECUTE) == GENERIC_EXECUTE) ||
			((access & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE);
	}

	bool AccessIncludesWriteOwner(const ACCESS_MASK& access) {
		return AccessIncludesAll(access) || 
			((access & WRITE_OWNER) == WRITE_OWNER);
	}

	bool AccessContainsDelete(const ACCESS_MASK& access) {
		return AccessIncludesAll(access) ||
			((access & DELETE) == DELETE);
	}

	void AccessAddAll(ACCESS_MASK& access) {
		access |= GENERIC_ALL;
	}

	void AccessAddWrite(ACCESS_MASK& access) {
		access |= GENERIC_WRITE;
	}

	void AccessAddRead(ACCESS_MASK& access) {
		access |= GENERIC_READ;
	}

	void AccessAddExecute(ACCESS_MASK& access) {
		access |= GENERIC_EXECUTE;
	}

	void AccessAddWriteOwner(ACCESS_MASK& access) {
		access |= WRITE_OWNER;
	}

	void AccessAddDelete(ACCESS_MASK& access) {
		access |= DELETE;
	}

	ACCESS_MASK GetOwnerRightsFromACL(const Owner& owner, const SecurityDescriptor& acl) {
		TRUSTEE_W tOwnerTrustee;
		BuildTrusteeWithSidW(&tOwnerTrustee, owner.GetSID());
		ACCESS_MASK amAccess{ 0 };
		auto dacl = acl.GetDACL();
		auto x{ GetLastError() };
		HRESULT hr = GetEffectiveRightsFromAclW(dacl, &tOwnerTrustee, &amAccess);
		if (hr != ERROR_SUCCESS) {
			LOG_ERROR("Error getting rights from acl with owner " << owner << ". ERROR: " << hr );
			return 0;
		}
		return amAccess;
	}

	bool UpdateObjectACL(const std::wstring& wsObjectName, SE_OBJECT_TYPE seObjectType, const Owner& oOwner, ACCESS_MASK amDesiredAccess, bool bDeny) {
		PACL pOldDacl;
		PSECURITY_DESCRIPTOR pDesc{ nullptr };
		HRESULT hr = GetNamedSecurityInfoW(reinterpret_cast<LPCWSTR>(wsObjectName.c_str()), seObjectType, DACL_SECURITY_INFORMATION, nullptr, nullptr, &pOldDacl, nullptr, &pDesc);
		AllocationWrapper awDesc{ pDesc, 0, AllocationWrapper::LOCAL_ALLOC };
		if (hr != ERROR_SUCCESS) {
			LOG_ERROR("Couldn't read current DACL for object " << wsObjectName << ". (Error " << hr << ")");
			SetLastError(hr);
			return false;
		}
		ACCESS_MODE amAccessMode = bDeny ? DENY_ACCESS : GRANT_ACCESS;
		EXPLICIT_ACCESS ea;
		ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
		ea.grfAccessPermissions = amDesiredAccess;
		ea.grfAccessMode = amAccessMode;
		ea.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
		BuildTrusteeWithSidW(&ea.Trustee, oOwner.GetSID());

		PACL pNewDacl{ nullptr };
		hr = SetEntriesInAcl(1, &ea, pOldDacl, &pNewDacl);
		AllocationWrapper awNewDacl{ pNewDacl, 0, AllocationWrapper::LOCAL_ALLOC };
		if (hr != ERROR_SUCCESS) {
			LOG_ERROR("Couldn't update DACL for object " << wsObjectName << ". (Error " << hr << ")");
			SetLastError(hr);
			return false;
		}

		hr = SetNamedSecurityInfoW(const_cast<LPWSTR>(wsObjectName.c_str()), seObjectType,
			DACL_SECURITY_INFORMATION,
			NULL, NULL, pNewDacl, NULL);
		if (hr != ERROR_SUCCESS) {
			LOG_ERROR("Couldn't set new DACL for object " << wsObjectName << ". (Error " << hr << ")");
			SetLastError(hr);
			return false;
		}
		return true;
	}


	SecurityDescriptor::SecurityDescriptor(DWORD dwSize, SecurityDescriptor::SecurityDataType type) :
		GenericWrapper<PISECURITY_DESCRIPTOR>(reinterpret_cast<PISECURITY_DESCRIPTOR>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize)),
			[](LPVOID memory) { HeapFree(GetProcessHeap(), 0, memory); }, nullptr) {
		switch (type) {
		case SecurityDescriptor::SecurityDataType::USER_SID:
			lpUserSID = reinterpret_cast<PSID>(*ReferenceCounter);
			break;
		case SecurityDescriptor::SecurityDataType::GROUP_SID:
			lpGroupSID = reinterpret_cast<PSID>(*ReferenceCounter);
			break;
		case SecurityDescriptor::SecurityDataType::DACL:
			dacl = reinterpret_cast<PACL>(*ReferenceCounter);
			break;
		case SecurityDescriptor::SecurityDataType::SACL:
			sacl = reinterpret_cast<PACL>(*ReferenceCounter);
			break;
		}
	}

	SecurityDescriptor::SecurityDescriptor(PISECURITY_DESCRIPTOR lpSecurity) :
		GenericWrapper<PISECURITY_DESCRIPTOR>(lpSecurity, LocalFree, nullptr) {
		if (lpSecurity) {
			lpUserSID = lpSecurity->Owner;
			lpGroupSID = lpSecurity->Group;
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
	PSID SecurityDescriptor::GetUserSID() const { return this->lpUserSID; }
	PSID SecurityDescriptor::GetGroupSID() const { return this->lpGroupSID; }

	LsaHandleWrapper::LsaHandleWrapper(LSA_HANDLE handle) :
		GenericWrapper(handle, std::function<void(LSA_HANDLE)>(SafeCloseLsaHandle), nullptr) {}

	LsaHandleWrapper::LsaHandleWrapper(LSA_HANDLE handle, std::function<void(LSA_HANDLE)> fSafeClose) : 
		GenericWrapper(handle, std::function<void(LSA_HANDLE)>(fSafeClose), nullptr) {}

	bool Owner::bPolicyInitialized{ false };
	LsaHandleWrapper Owner::lPolicyHandle{ nullptr };
	const std::vector<std::wstring> Owner::vSuperUserPrivs{ SE_DEBUG_NAME, SE_IMPERSONATE_NAME, SE_TCB_NAME, SE_LOAD_DRIVER_NAME,
			SE_ASSIGNPRIMARYTOKEN_NAME, SE_TAKE_OWNERSHIP_NAME };

	void LsaHandleWrapper::SafeCloseLsaHandle(LSA_HANDLE handle) {
		LsaClose(handle);
	}

	void Owner::InitializePolicy() {
		LSA_HANDLE lTempPolicyHandle;
		LSA_OBJECT_ATTRIBUTES lObjectAttr{};
		HRESULT hr = LsaNtStatusToWinError(LsaOpenPolicy(nullptr, &lObjectAttr, GENERIC_ALL, &lTempPolicyHandle));
		if (hr != ERROR_SUCCESS) {
			bPolicyInitialized = false;
			LOG_ERROR("Couldn't open policy handle. (Error:" << hr << ")");
			SetLastError(hr);
		}
		else {
			lPolicyHandle = { lTempPolicyHandle, std::function<void(LSA_HANDLE)>(Owner::DeinitializePolicy) };
			bPolicyInitialized = true;
		}
	}

	void Owner::DeinitializePolicy(LSA_HANDLE handle) {
		LsaClose(handle);
		bPolicyInitialized = false;
	}

	std::shared_ptr<LSA_UNICODE_STRING> Owner::WStringToLsaUnicodeString(IN const std::wstring& str) {
		LSA_UNICODE_STRING lsaWStr{};
		DWORD len = 0;
		len = str.length();
		PWCHAR cstr = new WCHAR[len + 1];
		MoveMemory(cstr, str.c_str(), (len + 1) * sizeof(WCHAR));
		lsaWStr.Buffer = cstr;
		lsaWStr.Length = (USHORT)((len) * sizeof(WCHAR));
		lsaWStr.MaximumLength = (USHORT)((len + 1) * sizeof(WCHAR));
		return std::shared_ptr<LSA_UNICODE_STRING>{ new LSA_UNICODE_STRING(lsaWStr), [](auto* object) {delete[] object->Buffer; delete object; }};
	}

	std::wstring Owner::LsaUnicodeStringToWString(IN const LSA_UNICODE_STRING& str) {
		return { str.Buffer };
	}

	Owner::Owner(IN const std::wstring& name) : wName{ name }, bExists{ true } {
		DWORD dwSIDLen{};
		DWORD dwDomainLen{};
		SID_NAME_USE SIDType{};
		LookupAccountNameW(nullptr, wName.c_str(), nullptr, &dwSIDLen, nullptr, &dwDomainLen, &SIDType);
		SecurityDescriptor tempSID = SecurityDescriptor::CreateUserSID(dwSIDLen);
		std::vector<WCHAR> Domain(dwDomainLen);
		DWORD dwTempDomainLen = dwDomainLen;
		DWORD dwTempSIDLen = dwSIDLen;
		LookupAccountNameW(nullptr, wName.c_str(), tempSID.GetUserSID(), &dwTempSIDLen, Domain.data(), &dwTempDomainLen, &SIDType);

		if (SIDType == SidTypeUser || SIDType == SidTypeDeletedAccount) {
			otType = OwnerType::USER;
			LOG_VERBOSE(3, "Owner with name " << wName << " is a user.");
			sdSID = SecurityDescriptor::CreateUserSID(dwSIDLen);
			if (!LookupAccountNameW(nullptr, wName.c_str(), sdSID.GetUserSID(), &dwSIDLen, Domain.data(), &dwDomainLen, &SIDType)) {
				LOG_ERROR("Error getting user with name " << wName << " " << GetLastError());
				bExists = false;
			}
			else {
				wDomainName = std::wstring(Domain.data());
				if (SIDType == SidTypeDeletedAccount) {
					LOG_VERBOSE(2, "User with name " << wName << " has been deleted.");
					bExists = false;
				}
				else if (SIDType != SidTypeUser) {
					LOG_VERBOSE(2, "User with name " << wName << " does not exist.");
					bExists = false;
				}
				else {
					LOG_VERBOSE(3, "User with name " << wName << " found.");
				}
			}
		}
		else if (SIDType == SidTypeGroup || SIDType == SidTypeWellKnownGroup || SIDType == SidTypeAlias) {
			otType = OwnerType::GROUP;
			if (SIDType == SidTypeWellKnownGroup) {
				LOG_VERBOSE(3, "Owner with name " << wName << " is a well known group.");
			}
			else {
				LOG_VERBOSE(3, "Owner with name " << wName << " is a group.");
			}
			sdSID = SecurityDescriptor::CreateGroupSID(dwSIDLen);
			if (!LookupAccountNameW(nullptr, wName.c_str(), sdSID.GetGroupSID(), &dwSIDLen, Domain.data(), &dwDomainLen, &SIDType)) {
				LOG_ERROR("Error getting group with name " << wName << " " << GetLastError());
				bExists = false;
			}
			else {
				wDomainName = std::wstring(Domain.data());
				LOG_VERBOSE(3, "Group with name " << wName << " exists.");
			}
		}
		else {
			otType = OwnerType::NONE;
			LOG_ERROR("Name " << wName << " does not correspond to a known owner type.");
			bExists = false;
		}
	}

	Owner::Owner(IN const SecurityDescriptor& sid) : sdSID{ sid }, bExists{ true } {
		DWORD dwDomainLen{};
		DWORD dwNameLen{};
		SID_NAME_USE SIDType{ SidTypeUnknown };
		LookupAccountSidW(nullptr, sdSID.GetUserSID(), nullptr, &dwNameLen, nullptr, &dwDomainLen, &SIDType);

		std::vector<WCHAR> Domain(dwDomainLen);
		std::vector<WCHAR> Name(dwNameLen);

		if (!LookupAccountSid(nullptr, sdSID.GetUserSID(), Name.data(), &dwNameLen, Domain.data(), &dwDomainLen, &SIDType)) {
			LOG_ERROR("Error getting owner " << GetLastError());
			bExists = false;
		}
		else {
			wDomainName = std::wstring(Domain.data());
			wName = std::wstring(Name.data());
			if (SIDType == SidTypeDeletedAccount) {
				otType = OwnerType::USER;
				LOG_VERBOSE(2, "User " << wName << " has been deleted.");
				bExists = false;
			}
			else if (SIDType == SidTypeGroup || SIDType == SidTypeWellKnownGroup || SIDType == SidTypeAlias) {
				LOG_VERBOSE(2, "Group " << wName << " exists.");
				otType = OwnerType::GROUP;
				auto temp = SecurityDescriptor::CreateGroupSID(GetLengthSid(sdSID.GetUserSID()));
				MoveMemory(temp.GetGroupSID(), sdSID.GetUserSID(), GetLengthSid(sdSID.GetUserSID()));
				sdSID = temp;
			}
			else if (SIDType == SidTypeUser) {
				LOG_VERBOSE(3, "User " << wName << " Exists.");
				otType = OwnerType::USER;
			}
			else {
				otType = OwnerType::NONE;
				LOG_ERROR("Unknown owner type.");
				bExists = false;
			}
		}
	}

	Owner::Owner(IN const std::wstring& name, IN bool exists, IN OwnerType type) : wName{ name }, bExists{ exists }, otType{ type } {}

	Owner::Owner(IN const SecurityDescriptor& sid, IN bool exists, IN OwnerType type) : sdSID{ sid }, bExists{ exists }, otType{ type } {}

	Owner::Owner(IN const std::wstring& name, IN const std::wstring& domain, IN const SecurityDescriptor& sid, IN bool exists, IN OwnerType type) :
		wName{ name }, wDomainName{ domain }, sdSID{ sid }, bExists{ exists }, otType{ type } {}

	bool Owner::Exists() const {
		return bExists;
	}

	std::wstring Owner::GetName() const {
		return wName;
	}

	std::wstring Owner::GetDomainName() const {
		return wDomainName;
	}

	PSID Owner::GetSID() const {
		if (otType == OwnerType::USER) return sdSID.GetUserSID();
		return sdSID.GetGroupSID();
	}

	OwnerType Owner::GetOwnerType() const {
		return otType;
	}

	std::wstring Owner::ToString() const {
		return wName;
	}

	std::vector<std::wstring> Owner:: GetPrivileges() {
		//Ensure policy handle is initialized
		if (!bPolicyInitialized) {
			InitializePolicy();
			if (!bPolicyInitialized) {
				LOG_ERROR("Error getting owner privliges, couldn't initialize policy handle.");
				return std::vector<std::wstring>{ };
			}
		}
		PLSA_UNICODE_STRING pReceivedPrivs{ nullptr };
		ULONG uPrivCount{ 0 };
		std::vector<std::wstring> vPrivs{ };
		auto hr = LsaNtStatusToWinError(LsaEnumerateAccountRights(lPolicyHandle, GetSID(), &pReceivedPrivs, &uPrivCount));
		AllocationWrapper awReceivedPrivsHandler{ pReceivedPrivs, 0, AllocationWrapper::NET_ALLOC };
		if (hr != ERROR_SUCCESS && otType != OwnerType::USER) {
			LOG_ERROR("Error getting owner privileges. (Error: " << GetLastError() << ")");
			SetLastError(hr);
			return std::vector<std::wstring>{ };
		}
		else if (hr == ERROR_SUCCESS) {
			for (int i = 0; i < uPrivCount; i++) {
				vPrivs.emplace_back(LsaUnicodeStringToWString(pReceivedPrivs[i]));
			}
		}
		//Get privileges from groups that a user belongs to
		if (otType == OwnerType::USER) {
			PGROUP_USERS_INFO_0 pGroupInfo{ nullptr };
			DWORD dEntriesRead{ 0 };
			DWORD dEntriesTotal{ 0 };
			NET_API_STATUS stat = NetUserGetLocalGroups(wDomainName.c_str(), wName.c_str(), 0, LG_INCLUDE_INDIRECT , reinterpret_cast<LPBYTE *>(&pGroupInfo), MAX_PREFERRED_LENGTH, &dEntriesRead, &dEntriesTotal);
			AllocationWrapper awGroupInfoHandler{ pGroupInfo, sizeof(GROUP_USERS_INFO_0) * dEntriesRead, AllocationWrapper::NET_ALLOC };
			if (stat != NERR_Success) {
				LOG_ERROR("Error getting user groups. (Net Error: " << stat << ")");
				return vPrivs;
			}
			//Add all privileges from groups to list of user's privileges
			for (int i = 0; i < dEntriesRead; i++) {
				Owner oGroup{ pGroupInfo[i].grui0_name };
				hr = LsaNtStatusToWinError(LsaEnumerateAccountRights(lPolicyHandle, oGroup.GetSID(), &pReceivedPrivs, &uPrivCount));
				awReceivedPrivsHandler = { pReceivedPrivs, 0, AllocationWrapper::NET_ALLOC };
				if (hr != ERROR_SUCCESS) {
					LOG_ERROR("Error getting group privileges. (Error: " << GetLastError() << ")");
				}
				else {
					for (int i = 0; i < uPrivCount; i++) {
						vPrivs.emplace_back(LsaUnicodeStringToWString(pReceivedPrivs[i]));
					}
				}
			}
		}
		SetLastError(ERROR_SUCCESS);
		return vPrivs;
	}

	bool Owner::HasPrivilege(IN const std::wstring& wPriv) {
		auto vOwnerPrivs = GetPrivileges();
		for (auto iter = vOwnerPrivs.begin(); iter != vOwnerPrivs.end(); iter++) {
			if (wPriv.compare(WStringToLsaUnicodeString(*iter)->Buffer) == 0) return true;
		}
		return false;
	}


	std::vector<Owner> Owner::GetOwnersWithPrivilege(IN const std::wstring& wPriv) {
		//Ensure policy handle is initialized
		if (!bPolicyInitialized) {
			InitializePolicy();
			if (!bPolicyInitialized) {
				LOG_ERROR("Error getting owners with privlige, couldn't initialize policy handle.");
				return std::vector<Owner>{ };
			}
		}
		LSA_UNICODE_STRING lPrivName = *WStringToLsaUnicodeString(wPriv);
		PLSA_ENUMERATION_INFORMATION pOwners{ nullptr };
		ULONG uNumOwners{ 0 };
		auto hr = LsaNtStatusToWinError(LsaEnumerateAccountsWithUserRight(lPolicyHandle, &lPrivName, reinterpret_cast<PVOID *>(&pOwners), &uNumOwners));
		AllocationWrapper awOwnersHandler{ pOwners, 0, AllocationWrapper::NET_ALLOC };
		if (hr != ERROR_SUCCESS) {
			LOG_ERROR("Error getting accounts with user privilege. (Error: " << hr << ")");
			SetLastError(hr);
			return std::vector<Owner>{ };
		}
		std::vector<Owner> vOwners;
		for (int i = 0; i < uNumOwners; i++) {
			DWORD dwSidLen = GetLengthSid(pOwners[i].Sid);
			SecurityDescriptor sdSID = SecurityDescriptor::CreateUserSID(dwSidLen);
			MoveMemory(sdSID.GetUserSID(), pOwners[i].Sid, dwSidLen);
			vOwners.emplace_back(Owner{ sdSID });
		}
		SetLastError(ERROR_SUCCESS);
		return vOwners;
	}

	bool Owner::RemovePrivilege(IN const std::wstring& wPriv) {
		//Ensure policy handle is initialized
		if (!bPolicyInitialized) {
			InitializePolicy();
			if (!bPolicyInitialized) {
				LOG_ERROR("Error removing owner privlige, couldn't initialize policy handle.");
				return false;
			}
		}
		LSA_UNICODE_STRING lPrivName = *WStringToLsaUnicodeString(wPriv);
		auto hr = LsaNtStatusToWinError(LsaRemoveAccountRights(lPolicyHandle, GetSID(), false, &lPrivName, 1));
		if (hr != ERROR_SUCCESS) {
			LOG_ERROR("Error removing privilege from account. (Error: " << hr << ")");
			SetLastError(hr);
			return false;
		}
		return true;
	}

	bool Owner::HasSuperUserPrivs() {
		auto vOwnerPrivs = GetPrivileges();
		for (auto priv : vSuperUserPrivs) {
			for (auto iter = vOwnerPrivs.begin(); iter != vOwnerPrivs.end(); iter++) {
				if (priv.compare(WStringToLsaUnicodeString(*iter)->Buffer) == 0) return true;
			}
		}
		return false;
	}

	bool Owner::RemoveSuperUserPrivs() {
		//Ensure policy handle is initialized
		if (!bPolicyInitialized) {
			InitializePolicy();
			if (!bPolicyInitialized) {
				LOG_ERROR("Error removing owner privlige, couldn't initialize policy handle.");
				return false;
			}
		}
		std::vector<LSA_UNICODE_STRING> lSuperUserPrivs{ };
		for (auto priv : vSuperUserPrivs) {
			lSuperUserPrivs.emplace_back(*WStringToLsaUnicodeString(priv));
		}
		auto hr = LsaNtStatusToWinError(LsaRemoveAccountRights(lPolicyHandle, GetSID(), false, lSuperUserPrivs.data(), lSuperUserPrivs.size()));
		if (hr != ERROR_SUCCESS) {
			LOG_ERROR("Error removing privilege from account. (Error: " << hr << ")");
			SetLastError(hr);
			return false;
		}
	}

	bool Owner::Delete() {
		if (otType == OwnerType::USER) {
			NET_API_STATUS nStat = NetUserDel(nullptr, GetName().c_str());
			if (nStat != NERR_Success) {
				LOG_ERROR("Error deleting user " << GetName() << ". (Net Error: " << nStat << ")");
				return false;
			}
			bExists = false;
			return true;
		}
		else if (otType == OwnerType::GROUP) {
			NET_API_STATUS nStat = NetLocalGroupDel(nullptr, GetName().c_str());
			if (nStat != NERR_Success) {
				LOG_ERROR("Error deleting group " << GetName() << ". (Net Error: " << nStat << ")");
				return false;
			}
			bExists = false;
			return true;

		}
		return true;
	}

	User::User(IN const std::wstring& uName) : Owner{ uName , true, OwnerType::USER} {
		DWORD dwSIDLen{};
		DWORD dwDomainLen{};
		SID_NAME_USE SIDType{};
		LookupAccountNameW(nullptr, wName.c_str(), nullptr, &dwSIDLen, nullptr, &dwDomainLen, &SIDType);

		sdSID = SecurityDescriptor::CreateUserSID(dwSIDLen);
		std::vector<WCHAR> Domain(dwDomainLen);
		if (!LookupAccountNameW(nullptr, wName.c_str(), sdSID.GetUserSID(), &dwSIDLen, Domain.data(), &dwDomainLen, &SIDType)) {
			if (GetLastError() == ERROR_NONE_MAPPED) {
				LOG_VERBOSE(2, L"User with name " << wName << " doesn't exist.");
			}
			else {
				LOG_ERROR("Error getting user with name " << wName << " " << GetLastError());
			}
			bExists = false;
		}
		else {
			wDomainName = std::wstring(Domain.data());
			if (SIDType == SidTypeDeletedAccount) {
				LOG_VERBOSE(2, "User with name " << wName << " has been deleted.");
				bExists = false;
			}
			else if (SIDType != SidTypeUser) {
				LOG_VERBOSE(2, "User with name " << wName << " does not exist.");
				bExists = false;
			}
			else {
				LOG_VERBOSE(3, "User with name " << wName << " found.");
			}
		}
	}

	User::User(IN const SecurityDescriptor& sid) : Owner{ sid , true, OwnerType::USER } {
		DWORD dwDomainLen{};
		DWORD dwNameLen{};
		SID_NAME_USE SIDType{ SidTypeUnknown };
		LookupAccountSidW(nullptr, sdSID.GetUserSID(), nullptr, &dwNameLen, nullptr, &dwDomainLen, &SIDType);

		std::vector<WCHAR> Domain(dwDomainLen);
		std::vector<WCHAR> Name(dwNameLen);

		if (!LookupAccountSid(nullptr, sdSID.GetUserSID(), Name.data(), &dwNameLen, Domain.data(), &dwDomainLen, &SIDType)) {
			if (GetLastError() == ERROR_NONE_MAPPED) {
				LOG_VERBOSE(2, L"User doesn't exist.");
			}
			else {
				LOG_ERROR("Error getting user " << GetLastError());
			}
			bExists = false;
		}
		else {
			wDomainName = std::wstring(Domain.data());
			wName = std::wstring(Name.data());
			if (SIDType == SidTypeDeletedAccount) {
				LOG_VERBOSE(2, "User " << wName << " has been deleted.");
				bExists = false;
			}
			else if (SIDType != SidTypeUser) {
				LOG_VERBOSE(2, "User doesn't exist.");
				bExists = false;
			}
			else {
				LOG_VERBOSE(3, "User " << wName << " Exists.");
			}
		}
	}

	Group::Group(IN const std::wstring& name) : Owner{ name, true, OwnerType::GROUP } {
		DWORD dwSIDLen{};
		DWORD dwDomainLen{};
		SID_NAME_USE SIDType{};
		LookupAccountNameW(nullptr, wName.c_str(), nullptr, &dwSIDLen, nullptr, &dwDomainLen, &SIDType);

		sdSID = SecurityDescriptor::CreateUserSID(dwSIDLen);
		std::vector<WCHAR> Domain(dwDomainLen);
		if (!LookupAccountNameW(nullptr, wName.c_str(), sdSID.GetUserSID(), &dwSIDLen, Domain.data(), &dwDomainLen, &SIDType)) {
			LOG_ERROR("Error getting user with name " << wName << " " << GetLastError());
			bExists = false;
		}
		else {
			wDomainName = std::wstring(Domain.data());
			if (SIDType == SidTypeWellKnownGroup) {
				LOG_VERBOSE(2, "Group with name " << wName << " is a well known group.");
			}
			else if (SIDType == SidTypeGroup || SIDType == SidTypeAlias) {
				LOG_VERBOSE(2, "Group with name " << wName << " found.");
			}
			else {
				LOG_VERBOSE(3, "Group with name " << wName << " does not exist.");
				bExists = false;
			}
		}
	}

	Group::Group(IN const SecurityDescriptor& sid) : Owner{ sid, true, OwnerType::GROUP } {
		DWORD dwDomainLen{};
		DWORD dwNameLen{};
		SID_NAME_USE SIDType{ SidTypeUnknown };
		LookupAccountSidW(nullptr, sdSID.GetUserSID(), nullptr, &dwNameLen, nullptr, &dwDomainLen, &SIDType);

		std::vector<WCHAR> Domain(dwDomainLen);
		std::vector<WCHAR> Name(dwNameLen);

		if (!LookupAccountSid(nullptr, sdSID.GetUserSID(), Name.data(), &dwNameLen, Domain.data(), &dwDomainLen, &SIDType)) {
			LOG_ERROR("Error getting user " << GetLastError());
			bExists = false;
		}
		else {
			wDomainName = std::wstring(Domain.data());
			wName = std::wstring(Name.data());
			if (SIDType == SidTypeWellKnownGroup) {
				LOG_VERBOSE(2, "Group with name " << wName << " is a well known group.");
			}
			else if (SIDType == SidTypeGroup || SIDType == SidTypeAlias) {
				LOG_VERBOSE(2, "Group with name " << wName << " found.");
			}
			else {
				LOG_VERBOSE(3, "Group with name " << wName << " does not exist.");
				bExists = false;
			}
		}
	}

	std::optional<Owner> GetProcessOwner() {
		HandleWrapper hToken{ nullptr };
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
			LOG_ERROR("Couldn't access process token. Error " << GetLastError());
			return std::nullopt;
		}
		DWORD dwSize{ 0 };
		GetTokenInformation(hToken, TokenOwner, nullptr, dwSize, &dwSize);
		AllocationWrapper owner{ GlobalAlloc(GPTR, dwSize), dwSize, AllocationWrapper::GLOBAL_ALLOC };
		DWORD dwDomainLen{};
		DWORD dwNameLen{};
		SID_NAME_USE SIDType{ SidTypeUnknown };

		std::vector<WCHAR> Domain(dwDomainLen);
		std::vector<WCHAR> Name(dwNameLen);
		if (owner == nullptr) {
			LOG_ERROR("Unable to allocate space for owner token.");
			return std::nullopt;
		}
		if (!GetTokenInformation(hToken, TokenOwner, owner, dwSize, &dwSize)) {
			LOG_ERROR("Couldn't get owner from token. Error " << GetLastError());
			return std::nullopt;
		}
		LookupAccountSidW(nullptr, owner.GetAsPointer<TOKEN_OWNER>()->Owner, nullptr, &dwNameLen, nullptr, &dwDomainLen, &SIDType);
		Domain = std::vector<WCHAR>(dwDomainLen);
		Name = std::vector<WCHAR>(dwNameLen);

		if (!LookupAccountSid(nullptr, owner.GetAsPointer<TOKEN_OWNER>()->Owner, Name.data(), &dwNameLen, Domain.data(), &dwDomainLen, &SIDType)) {
			LOG_ERROR("Error getting owner " << GetLastError());
		}
		CloseHandle(hToken);
		return Owner(Name.data());
	}
}