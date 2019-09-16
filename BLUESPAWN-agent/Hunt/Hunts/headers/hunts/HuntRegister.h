#pragma once
#include <Windows.h>

#include <vector>
#include <map>
#include <string>
#include <type_traits>

#include "Hunt.h"
#include "Scope.h"

using namespace std;

class HuntRegister {
private:
	vector<Hunt> vRegisteredHunts{};

	map<Tactic, vector<reference_wrapper<Hunt>>> mTactics{};
	map<DataSource, vector<reference_wrapper<Hunt>>> mDataSources{};
	map<Category, vector<reference_wrapper<Hunt>>> mAffectedThings{};

public:
	void RunHunts(DWORD dwTactics, DWORD dwDataSource, DWORD dwAffectedThings, Scope& scope, Aggressiveness aggressiveness, const Reaction& reaction);
	void RunHunt(const Hunt& hunt, const Scope& scope, Aggressiveness aggressiveness, const Reaction& reaction);

	void RegisterHunt(const Hunt& hunt);
};