#pragma once

#include <windows.h>

#include <string>
#include <map>
#include <vector>
#include <set>
#include <iostream>
#include <vector>

#include "util/log/Log.h"

namespace Permissions {
	class SecurityInformation {
	private:
		PSECURITY_DESCRIPTOR pSecurityDescriptor;

		PSID GetSid();
		PACL GetDacl();

	public:
		SecurityInformation(PSECURITY_DESCRIPTOR pSD);

		std::wstring GetOwnerSid();
		std::wstring GetStringSid(PSID pSid);
		std::wstring GetOwnerUsername();
		std::wstring GetUsernameFromSid(PSID pSid);

		std::vector<std::wstring> GetDaclEntries();

		virtual std::wstring ToString();
	};
}