#pragma once
#include "../Hunt.h"
#include "reaction/Reaction.h"
#include "reaction/Log.h"
#include "common/DynamicLinker.h"

namespace Hunts {

	/**
	 * HuntT1055 examines all processes for shellcode injections, injected PE images,
	 * function hooks, and doppelganging. This individual hunt will eventually be broken
	 * into separate hunts
	 *
	 * @scans Cursory Scan not supported.
	 * @scans Normal Scans all processes running on the system for evidence of process injection
	 * @scans Intensive Scan not supported.
	 */
	class HuntT1055 : public Hunt {

	public:
		HuntT1055();

		virtual int ScanNormal(const Scope& scope, Reaction reaction) override;
	};
}
