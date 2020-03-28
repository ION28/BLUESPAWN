#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>

#include "user/banners.h"

#include "util/log/Log.h"
#include "util/log/CLISink.h"
#include "util/configurations/Registry.h"

#include "hunt/Hunt.h"
#include "hunt/HuntRegister.h"
#include "reaction/Reaction.h"

#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"

class Bluespawn {
	Reaction reaction;

	public:
		Bluespawn();

		void SetReaction(const Reaction& reaction);

		void dispatch_hunt(Aggressiveness aHuntLevel);
		void dispatch_mitigations_analysis(MitigationMode mode, bool bForceEnforce);
		void monitor_system(Aggressiveness aHuntLevel);

		static HuntRegister huntRecord;
		static MitigationRegister mitigationRecord;
		static const IOBase& io;
};
