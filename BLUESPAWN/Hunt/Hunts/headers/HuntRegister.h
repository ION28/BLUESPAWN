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
	vector<Hunt*> vRegisteredHunts;

	map<Tactic::Tactic, vector<Hunt*>> mTactics;
	map<DataSource::DataSource, vector<Hunt*>> mDataSources;
	map<AffectedThing::AffectedThing, vector<Hunt*>> mAffectedThings;

	void RunHunts(DWORD dwTactics, DWORD dwDataSource, DWORD dwAffectedThings, Scope& scope, Aggressiveness::Aggressiveness a);
	void RunHunt(string& name);
	void RunHunt(int number);
};