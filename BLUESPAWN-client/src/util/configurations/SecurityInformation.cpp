#include <Windows.h>
#include <sddl.h>

#include "util/configurations/SecurityInformation.h"
#include "util/log/Log.h"

namespace Information {
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

	std::wstring SecurityInformation::GetOwnerSid(){
		PSID pOwner = GetSid();
		LPWSTR lpwOwnerSid = NULL;

		bool status = ConvertSidToStringSid(pOwner, &lpwOwnerSid);
		if (!status) {
			LOG_ERROR("Unable to convert SID to string SID likely due to not enough memory, an invalid SID, or invalid parameter.");
			SetLastError(status);

			return L"";
		}

		return std::wstring{lpwOwnerSid};
	}

	std::wstring SecurityInformation::GetOwnerUsername() {
		PSID pOwner = GetSid();
		LPWSTR lpwUsername = NULL;
		DWORD dwAccountNameSize = 0;
		LPWSTR lpwDomainName = NULL;
		DWORD dwDomainNameSize = 0;
		SID_NAME_USE eSidType;

		bool status = LookupAccountSid(NULL, pOwner, lpwUsername, &dwAccountNameSize, lpwDomainName, &dwDomainNameSize, &eSidType);

		if (!status) {
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
				lpwUsername = (LPWSTR)LocalAlloc(LPTR, dwAccountNameSize * sizeof(WCHAR));
				lpwDomainName = (LPWSTR)LocalAlloc(LPTR, dwDomainNameSize * sizeof(WCHAR));
				status = LookupAccountSid(NULL, pOwner, lpwUsername, &dwAccountNameSize, lpwDomainName, &dwDomainNameSize, &eSidType);
			}
			else if (GetLastError() == ERROR_NONE_MAPPED) {
				lpwUsername = L"NO_ACCOUNT_MAPPED";
			}
			else {
				LOG_ERROR("Unable to convert SID to username.");
				SetLastError(status);

				return L"";
			}
		}

		return std::wstring{lpwUsername};
	}

	std::wstring SecurityInformation::ToString(){
		SECURITY_INFORMATION dwSecurityInfo = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
			LABEL_SECURITY_INFORMATION | ATTRIBUTE_SECURITY_INFORMATION | SCOPE_SECURITY_INFORMATION;

		LPWSTR lpwSecurityDescriptor = L"";
		ConvertSecurityDescriptorToStringSecurityDescriptor(pSecurityDescriptor, SDDL_REVISION_1, dwSecurityInfo, &lpwSecurityDescriptor, NULL);

		return std::wstring{lpwSecurityDescriptor};
	}
}