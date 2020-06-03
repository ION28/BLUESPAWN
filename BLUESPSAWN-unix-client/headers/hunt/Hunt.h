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
	DWORD dwTacticsUsed;
	DWORD dwSourcesInvolved;
	DWORD dwCategoriesAffected;
	DWORD dwSupportedScans;

	std::wstring name;

public:
	Hunt(const std::wstring& name);

	std::wstring GetName();

	bool UsesTactics(DWORD tactics);
	bool UsesSources(DWORD sources);
	bool AffectsCategory(DWORD category);
	bool SupportsScan(Aggressiveness scan);

	virtual int ScanCursory(const Scope& scope, Reaction reaction);
	virtual int ScanNormal(const Scope& scope, Reaction reaction);
	virtual int ScanIntensive(const Scope& scope, Reaction reaction);

	virtual std::vector<std::shared_ptr<Event>> GetMonitoringEvents();
};