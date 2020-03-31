#pragma once
#include <Windows.h>

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

public:
	HuntRegister(const IOBase& oIo);

	std::vector<std::shared_ptr<DETECTION>> RunHunts(DWORD dwTactics, DWORD dwDataSource, DWORD dwAffectedThings, const Scope& scope);
	std::vector<std::shared_ptr<DETECTION>> RunHunt(Hunt& hunt, const Scope& scope);

	void SetupMonitoring();
	void RegisterHunt(std::shared_ptr<Hunt> hunt);
};