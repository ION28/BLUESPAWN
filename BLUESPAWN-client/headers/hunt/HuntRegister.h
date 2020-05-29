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
	static vector<std::shared_ptr<Hunt>> vRegisteredHunts;

public:

	/**
	 * Runs the hunts registered with the RegisterHunt function with the given
	 * scope.
	 *
	 * @param scope An optional scope object representing the limitations of the hunt
	 * @param async A boolean indicating whether this function should wait for all hunts
	 *        to finish before returning.
	 */
	static std::vector<Detection> RunHuntsAsync(
		IN CONST Scope& scope = {} OPTIONAL, 
		IN CONST bool async = false OPTIONAL
	);

	static std::vector<Detection> RunHunt(Hunt& hunt, const Scope& scope);

	static void SetupMonitoring();
	static void RegisterHunt(const std::shared_ptr<Hunt>& hunt);
};