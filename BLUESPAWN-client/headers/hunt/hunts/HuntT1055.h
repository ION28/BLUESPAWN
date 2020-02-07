#pragma once
#include "../Hunt.h"
#include "hunt/reaction/Reaction.h"
#include "hunt/reaction/Log.h"
#include "common/DynamicLinker.h"

namespace Hunts {

	/**
	 * HuntT1055 examines all processes for shellcode injections, injected PE images,
	 * function hooks, and doppelganging. This individual hunt will eventually be broken
	 * into separate hunts
	 *
	 * @scans Cursory checks System logs for event id 7045 for new events
	 * @scans Moderate Scan not supported.
	 * @scans Careful Scan not supported.
	 * @scans Aggressive Scan not supported.
	 */
	class HuntT1055 : public Hunt {

	public:
		HuntT1055();

		virtual int ScanNormal(const Scope& scope, Reaction reaction) override;
	};
}
