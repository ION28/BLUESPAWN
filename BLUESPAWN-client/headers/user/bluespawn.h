#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <Windows.h>

// The developer of this library is a bad developer who left warnings in his code.
// Since we enforce no warnings, this is bad.
#pragma warning(push)

#pragma warning(disable : 26451)
#pragma warning(disable : 26444)

#include <cxxopts.hpp>

#pragma warning(pop)

#include "user/banners.h"

#include "util/log/Log.h"
#include "util/log/CLISink.h"
#include "util/configurations/Registry.h"

#include "hunt/Hunt.h"
#include "hunt/HuntRegister.h"
#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"

class Bluespawn {
	public:
		Bluespawn();

		void dispatch_hunt(Aggressiveness aHuntLevel);
		void dispatch_mitigations_analysis(MitigationMode mode, bool bForceEnforce);
		void monitor_system(Aggressiveness aHuntLevel);

	private:
		static HuntRegister huntRecord;
		static MitigationRegister mitigationRecord;
		static IOBase& io;
};

void print_help(cxxopts::ParseResult result, cxxopts::Options options);