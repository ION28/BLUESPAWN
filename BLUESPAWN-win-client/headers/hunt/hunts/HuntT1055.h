#pragma once
#include "util/DynamicLinker.h"
#include "util/Promise.h"

#include "hunt/Hunt.h"
#include "pe_sieve.h"
#include "pe_sieve_types.h"

namespace Hunts {

    /**
	 * HuntT1055 examines all processes for shellcode injections, injected PE images,
	 * function hooks, and doppelganging. This individual hunt will eventually be broken
	 * into separate hunts
	 */
    class HuntT1055 : public Hunt {
        public:
        HuntT1055();

        /**
		 * Handles waiting for the promise to be fufilled, checking for invalidated data, and recording any detections
		 * that have been identified.
		 *
		 * @param detections A vector of detections to which any new detections will be added
		 * @param promise A promise for the result of a process scan
		 */
        void HuntT1055::HandleReport(OUT std::vector<std::shared_ptr<Detection>>& detections,
                                     IN CONST Promise<GenericWrapper<pesieve::ReportEx*>>& promise);

        virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope) override;
    };
}   // namespace Hunts
