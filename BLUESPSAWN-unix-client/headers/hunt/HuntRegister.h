#pragma once

#include <vector>
#include <map>
#include <string>
#include <type_traits>

#include "Hunt.h"
#include "Scope.h"
#include "user/CLI.h"

using namespace std;

class HuntRegister {
private:
	vector<std::shared_ptr<Hunt>> vRegisteredHunts{};
	const IOBase& io;

	map<Tactic, vector<reference_wrapper<Hunt>>> mTactics{};
	map<DataSource, vector<reference_wrapper<Hunt>>> mDataSources{};
	map<Category, vector<reference_wrapper<Hunt>>> mAffectedThings{};

	Aggressiveness getLevelForHunt(Hunt& hunt, Aggressiveness aggressiveness);

public:
	HuntRegister(const IOBase& oIo);

	void RunHunts(DWORD dwTactics, DWORD dwDataSource, DWORD dwAffectedThings, const Scope& scope, Aggressiveness aggressiveness, const Reaction& reaction, vector<string> vExcludedHunts, vector<string> vIncludedHunts);
	void RunHunt(Hunt& hunt, const Scope& scope, Aggressiveness aggressiveness, const Reaction& reaction);

	bool HuntRegister::HuntShouldRun(Hunt& hunt, vector<string> vExcludedHunts, vector<string> vIncludedHunts);
	void SetupMonitoring(Aggressiveness aggressiveness, const Reaction& reaction);
	void RegisterHunt(std::shared_ptr<Hunt> hunt);
};