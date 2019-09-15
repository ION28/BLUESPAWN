#pragma once
#include <Windows.h>
#include <vector>
#include <map>
#include <string>
#include "Hunt.h"
#include "Scope.h"

using namespace std;

class HuntRegister {
private:
	vector<Hunt*> vRegisteredHunts{};

	map<Tactic, vector<Hunt*>> mTactics{};
	map<DataSource, vector<Hunt*>> mDataSources{};
	map<Category, vector<Hunt*>> mAffectedThings{};

public:
	void RunHunts(DWORD dwTactics, DWORD dwDataSource, DWORD dwAffectedThings, Scope& scope, Aggressiveness aggressiveness, Reaction* = nullptr);
	void RunHunt(const Hunt& hunt, const Scope& scope, Aggressiveness aggressiveness, Reaction* = nullptr);

	void RegisterHunt(Hunt* hunt);
};