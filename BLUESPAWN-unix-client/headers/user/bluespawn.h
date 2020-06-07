#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif


#include "user/banners.h"

#include "util/log/Log.h"
#include "util/log/CLISink.h"

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

		void dispatch_hunt(Aggressiveness aHuntLevel, vector<string> vExcludedHunts, vector<string> vIncludedHunts);
		void dispatch_mitigations_analysis(MitigationMode mode, bool bForceEnforce);
		void monitor_system(Aggressiveness aHuntLevel);
		void check_correct_arch();

		static HuntRegister huntRecord;
		static MitigationRegister mitigationRecord;
		static const IOBase& io;
};
