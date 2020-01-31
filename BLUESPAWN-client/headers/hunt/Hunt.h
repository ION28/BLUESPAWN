#pragma once
#include <Windows.h>

#include <string>
#include <chrono>

#include "Scope.h"
#include "HuntInfo.h"

#include "hunt/reaction/Reaction.h"

class HuntRegister;

#define GET_INFO() \
    HuntInfo{ this->name, __func__ == std::string{"ScanCursory"}  ? Aggressiveness::Cursory  :                             \
                          __func__ == std::string{"ScanNormal"} ? Aggressiveness::Normal : Aggressiveness::Intensive, \
              this->dwTacticsUsed, this->dwCategoriesAffected, this->dwSourcesInvolved,                                    \
              (long) std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count() }

class Hunt {
protected:
	DWORD dwTacticsUsed;
	DWORD dwSourcesInvolved;
	DWORD dwCategoriesAffected;
	DWORD dwSupportedScans;

	std::wstring name;

public:
	Hunt(HuntRegister& hr, const std::wstring& name);

	bool UsesTactics(DWORD tactics);
	bool UsesSources(DWORD sources);
	bool AffectsCategory(DWORD category);
	bool SupportsScan(Aggressiveness scan);

	virtual int ScanCursory(const Scope& scope, Reaction reaction);
	virtual int ScanNormal(const Scope& scope, Reaction reaction);
	virtual int ScanIntensive(const Scope& scope, Reaction reaction);
};