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
		PSECURITY_DESCRIPTOR pSecurityDescriptor;

	public:
		SecurityInformation(PSECURITY_DESCRIPTOR pSD);

		std::wstring GetOwnerSid();

		virtual std::wstring ToString();
	};
}