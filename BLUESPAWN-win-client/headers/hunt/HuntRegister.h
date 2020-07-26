#pragma once
#include <Windows.h>

#include <map>
#include <string>
#include <vector>

#include "Hunt.h"
#include "Scope.h"

#include "util/Promise.h"
/**
 * HuntRegister is a class meant to be used to manage running hunts and monitoring.
 * Rather than make HuntRegister a singleton, all members are instead static.
 */
class HuntRegister {
    private:
    /// A vector of registered hunts
    static std::vector<std::unique_ptr<Hunt>> vRegisteredHunts;

    /* Called before a hunt is run or added to monitor mode to see if it should be enabled. This
	 * provide the ability to use the --hunts or --exclude-hunts flags to limit to looking for only 
	 * certain MITRE ATT&CK Techniques
	 * @param hunt The particular hunt to check
	 * @param vExcludedHunts A vector of Technique IDs that should be excluded
	 * @param vIncludedHunts A vector of Technique IDs that should be the only ones to run
	 * 
	 * @return A boolean whether or not the hunt should be included
	 */
    static bool HuntRegister::HuntShouldRun(IN Hunt* hunt,
                                            IN CONST std::vector<std::wstring> vIncludedHunts,
                                            IN CONST std::vector<std::wstring> vExcludedHunts);

    public:
    /**
	 * Runs all hunts registered with the RegisterHunt function with the given scope.
	 * note that the resulting vector of detections contains only items that *may* be
	 * malicious. Furthermore, they may be duplicates and numerous false positives present.
	 * These detections should be passed to scan mode for further analysis.
	 *
	 * @param scope An optional scope object representing the limitations of the hunt
	 * @param async A boolean indicating whether this function should wait for all hunts
	 *        to finish before returning.
	 *
	 * @return A vector of possibly malicious items. 
	 */
    static std::vector<Promise<std::vector<std::shared_ptr<Detection>>>> RunHunts(
        IN CONST std::vector<std::wstring> vIncludedHunts,
        IN CONST std::vector<std::wstring> vExcludedHunts,
        IN CONST Scope& scope = {} OPTIONAL,
        IN CONST bool async = false OPTIONAL);

    /**
	 * Queues a specified hunt, returning a promise for its result
	 *
	 * @param hunt The hunt to queue
	 * @param An optional scope object representing the limitations of the hunt
	 */
    static Promise<std::vector<std::shared_ptr<Detection>>> RunHunt(
        IN Hunt* hunt, IN CONST Scope& scope = {} OPTIONAL);

    /**
	 * Sets up monitoring mode by subscribing to all monitor events for each hunt in
	 * vRegisteredHunts. Note that in earlier versions of Windows, the thread that calls
	 * this function being terminated will result in the event subscriptions ending.
	 */
    static void SetupMonitoring(IN CONST std::vector<std::wstring> vIncludedHunts,
                                IN CONST std::vector<std::wstring> vExcludedHunts);

    /**
	 * Registers a hunt. This must be called prior to SetupMonitoring or RunHunts in
	 * order for the registered hunt to be run. Note that ownership of the hunt must be
	 * transferred to the HuntRegister.
	 *
	 * @param hunt A unique pointer to the hunt
	 */
    static void RegisterHunt(IN std::unique_ptr<Hunt>&& hunt);
};
