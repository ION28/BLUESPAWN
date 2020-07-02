#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>

#include "user/banners.h"

#include "util/log/Log.h"
#include "util/log/DetectionSink.h"
#include "util/configurations/Registry.h"

#include "hunt/Hunt.h"
#include "hunt/HuntRegister.h"

#include "scan/DetectionRegister.h"

#include "reaction/ReactionManager.h"

#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"

#include <map>

enum class BluespawnMode {
	HUNT, SCAN, MONITOR, MITIGATE
};

class Bluespawn {
	
	std::map<BluespawnMode, int> modes;

	void RunMitigations(bool enforce, bool force);
	void RunHunts();
	void RunMonitor();

	public:
		Bluespawn();

		void AddReaction(std::unique_ptr<Reaction>&& reaction);
		void EnableMode(BluespawnMode mode, int argument = 0);

		void Run();

		static HuntRegister huntRecord;
		static MitigationRegister mitigationRecord;
		static Aggressiveness aggressiveness;
		static DetectionRegister detections;
		static std::vector<std::shared_ptr<DetectionSink>> detectionSinks;
		static bool EnablePreScanDetections;

		static ReactionManager reaction;
		static const IOBase& io;
};
