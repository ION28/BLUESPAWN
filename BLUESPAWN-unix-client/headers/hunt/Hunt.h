#pragma once

#include <string>
#include <chrono>

#include "Scope.h"
#include "HuntInfo.h"

#include "reaction/Reaction.h"
#include "monitor/Event.h"

class HuntRegister;

#define GET_INFO() \
    HuntInfo{ this->name, __func__ == std::string{"ScanCursory"}  ? Aggressiveness::Cursory  :                             \
                          __func__ == std::string{"ScanNormal"} ? Aggressiveness::Normal : Aggressiveness::Intensive, \
              this->dwTacticsUsed, this->dwCategoriesAffected, this->dwSourcesInvolved }

class Hunt {
protected:
	unsigned int dwTacticsUsed;
	unsigned int dwSourcesInvolved;
	unsigned int dwCategoriesAffected;
	unsigned int dwSupportedScans;

	std::string name;

public:
	Hunt(const std::string& name);

	std::string GetName();

	bool UsesTactics(unsigned int tactics);
	bool UsesSources(unsigned int sources);
	bool AffectsCategory(unsigned int category);
	bool SupportsScan(Aggressiveness scan);

	virtual int ScanCursory(const Scope& scope, Reaction reaction);
	virtual int ScanNormal(const Scope& scope, Reaction reaction);
	virtual int ScanIntensive(const Scope& scope, Reaction reaction);

	virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents();
};