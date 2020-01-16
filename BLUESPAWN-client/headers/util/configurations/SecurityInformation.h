#pragma once

#include <windows.h>

#include <string>
#include <map>
#include <vector>
#include <set>
#include <iostream>

#include "util/log/Log.h"

namespace Information {
	class SecurityInformation {
	private:
		PSECURITY_DESCRIPTOR pSecurityDescriptor;

		PSID GetSid();

	public:
		SecurityInformation(PSECURITY_DESCRIPTOR pSD);

		std::wstring GetOwnerSid();
		std::wstring GetOwnerUsername();

		virtual std::wstring ToString();
	};
}