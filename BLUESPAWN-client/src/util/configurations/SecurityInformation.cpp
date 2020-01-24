#include <Windows.h>
#include <sddl.h>

#include "util/configurations/SecurityInformation.h"
#include "util/log/Log.h"

namespace Permissions {
	SecurityInformation::SecurityInformation(PSECURITY_DESCRIPTOR pSD) {
		pSecurityDescriptor = pSD;
	}

	PSID SecurityInformation::GetSid() {
		PSID pOwner;
		BOOL bOwnerDefaulted;

		bool status = GetSecurityDescriptorOwner(pSecurityDescriptor, &pOwner, &bOwnerDefaulted);
		if (!status) {
			LOG_ERROR("Unable to retrieve owner information for given security descriptor.");
			SetLastError(status);

			return L"";
		}

		return pOwner;
	}

	PACL SecurityInformation::GetDacl() {
		PACL pDacl;
		LPBOOL lpbDaclPresent;
		LPBOOL lpbDaclDefaulted;

		bool status = GetSecurityDescriptorDacl(pSecurityDescriptor, lpbDaclPresent, &pDacl, lpbDaclDefaulted);
		if (!status) {
			LOG_ERROR("Unable to retrieve DACL for given security descriptor.");
			SetLastError(status);

			return {};
		}

		return pDacl;
	}

	std::wstring SecurityInformation::GetOwnerSid(){
		PSID pOwner = GetSid();
		
		return GetStringSid(pOwner);
	}

	std::wstring SecurityInformation::GetStringSid(PSID pSid){
		LPWSTR lpwSid = NULL;

		bool status = ConvertSidToStringSid(pSid, &lpwSid);
		if (!status) {
			LOG_ERROR("Unable to convert SID to string SID likely due to not enough memory, an invalid SID, or invalid parameter.");
			SetLastError(status);

			return L"";
		}

		return std::wstring{ lpwSid };
	}

	std::wstring SecurityInformation::GetOwnerUsername() {
		PSID pOwner = GetSid();
		
		return GetUsernameFromSid(pOwner);
	}

	std::wstring SecurityInformation::GetUsernameFromSid(PSID pSid){
		LPWSTR lpwUsername = NULL;
		DWORD dwAccountNameSize = 0;
		LPWSTR lpwDomainName = NULL;
		DWORD dwDomainNameSize = 0;
		SID_NAME_USE eSidType;
		std::wstring sDivider = L"\\";

		bool status = LookupAccountSid(NULL, pSid, lpwUsername, &dwAccountNameSize, lpwDomainName, &dwDomainNameSize, &eSidType);

		if (!status) {
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
				lpwUsername = (LPWSTR)LocalAlloc(LPTR, dwAccountNameSize * sizeof(WCHAR));
				lpwDomainName = (LPWSTR)LocalAlloc(LPTR, dwDomainNameSize * sizeof(WCHAR));
				status = LookupAccountSid(NULL, pSid, lpwUsername, &dwAccountNameSize, lpwDomainName, &dwDomainNameSize, &eSidType);
			}
			else if (GetLastError() == ERROR_NONE_MAPPED) {
				lpwUsername = L"NO_ACCOUNT_MAPPED";
				lpwDomainName = L"";
				sDivider = L"";
			}
			else {
				LOG_ERROR("Unable to convert SID to username.");
				SetLastError(status);

				return L"";
			}
		}

		return std::wstring{ lpwDomainName + sDivider + lpwUsername };
	}

	std::vector<std::wstring> SecurityInformation::GetDaclEntries(){
		DWORD dwRet = 0;
		DWORD dwCount = 0;
		ACCESS_ALLOWED_ACE* ACE;

		PACL pDacl = GetDacl();

		if (IsValidAcl(pDacl)) {
			for (dwCount = 0; dwCount < pDacl->AceCount; dwCount++) {
				if (GetAce(pDacl, dwCount, (LPVOID*)&ACE)) {
					SID* sSID = (SID*) & (ACE->SidStart);
					if (sSID != NULL) {
						DWORD dwSize = 2048;
						char lpName[2048];
						char lpDomain[2048];
						SID_NAME_USE SNU;

						std::wcout << std::endl;
						std::wcout << GetStringSid(sSID) << std::endl;
						std::wcout << GetUsernameFromSid(sSID) << std::endl;

						switch (ACE->Header.AceType) {
						case ACCESS_ALLOWED_ACE_TYPE:
							if (ACE->Mask & SPECIFIC_RIGHTS_ALL) fprintf(stdout, "SPECIFIC_RIGHTS_ALL\n");
							if (ACE->Mask & KEY_QUERY_VALUE) fprintf(stdout, "KEY_QUERY_VALUE\n");
							if (ACE->Mask & KEY_SET_VALUE) fprintf(stdout, "KEY_SET_VALUE\n");
							if (ACE->Mask & KEY_CREATE_SUB_KEY) fprintf(stdout, "KEY_CREATE_SUB_KEY\n");
							if (ACE->Mask & KEY_ENUMERATE_SUB_KEYS) fprintf(stdout, "KEY_ENUMERATE_SUB_KEYS\n");
							if (ACE->Mask & KEY_NOTIFY) fprintf(stdout, "KEY_NOTIFY\n");
							if (ACE->Mask & KEY_CREATE_LINK) fprintf(stdout, "KEY_CREATE_LINK\n");
							if (ACE->Mask & DELETE) fprintf(stdout, "DELETE\n");
							if (ACE->Mask & WRITE_DAC) fprintf(stdout, "WRITE_DAC\n");
							if (ACE->Mask & WRITE_OWNER) fprintf(stdout, "WRITE_OWNER\n");
							if (ACE->Mask & READ_CONTROL) fprintf(stdout, "READ_CONTROL\n");

						case ACCESS_DENIED_ACE_TYPE:
							break;

						default:
							break;
						}
					}
				}
			}
		}
		else {
			return {};
		}

		return std::vector<std::wstring>();
	}

	std::wstring SecurityInformation::ToString(){
		SECURITY_INFORMATION dwSecurityInfo = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
			LABEL_SECURITY_INFORMATION | ATTRIBUTE_SECURITY_INFORMATION | SCOPE_SECURITY_INFORMATION;

		LPWSTR lpwSecurityDescriptor = L"";
		ConvertSecurityDescriptorToStringSecurityDescriptor(pSecurityDescriptor, SDDL_REVISION_1, dwSecurityInfo, &lpwSecurityDescriptor, NULL);

		return std::wstring{lpwSecurityDescriptor};
	}
}