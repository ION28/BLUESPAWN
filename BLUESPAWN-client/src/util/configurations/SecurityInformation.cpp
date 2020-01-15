#include <Windows.h>
#include <sddl.h>

#include "util/configurations/SecurityInformation.h"
#include "util/log/Log.h"

namespace Information {
	SecurityInformation::SecurityInformation(PSECURITY_DESCRIPTOR pSD) {
		pSecurityDescriptor = pSD;
	}

	std::wstring SecurityInformation::GetOwnerSid(){
		PSID pOwner;
		BOOL bOwnerDefaulted;
		LPWSTR lpwOwnerSid = NULL;

		bool status = GetSecurityDescriptorOwner(pSecurityDescriptor, &pOwner, &bOwnerDefaulted);
		if (!status) {
			LOG_ERROR("Unable to retrieve owner information for given security descriptor.");
			SetLastError(status);

			return L"";
		}
		status = ConvertSidToStringSid(pOwner, &lpwOwnerSid);
		if (!status) {
			LOG_ERROR("Unable to convert SID to string SID likely due to not enough memory, an invalid SID, or invalid parameter.");
			SetLastError(status);

			return L"";
		}

		return std::wstring{lpwOwnerSid};
	}

	std::wstring SecurityInformation::ToString(){
		SECURITY_INFORMATION dwSecurityInfo = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
			LABEL_SECURITY_INFORMATION | ATTRIBUTE_SECURITY_INFORMATION | SCOPE_SECURITY_INFORMATION;

		LPWSTR lpwSecurityDescriptor = L"";
		ConvertSecurityDescriptorToStringSecurityDescriptor(pSecurityDescriptor, SDDL_REVISION_1, dwSecurityInfo, &lpwSecurityDescriptor, NULL);

		return std::wstring{lpwSecurityDescriptor};
	}
}