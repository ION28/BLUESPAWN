#pragma once

#include "../Hunt.h"
#include "hunt/reaction/Reaction.h"
#include "hunt/reaction/Log.h"

namespace Hunts{

	/**
	 * HuntT1183 examines the Image File Execution Options for debuggers and silent
	 * process exit hooks
	 *
	 * @scans Cursory checks the values of the debugger and global flags for each process
	 *	      with an Image File Execution Options key
	 * @scans Normal Scan not supported.
	 * @scans Intensive Scan not supported.
	 */
	class HuntT1183 : public Hunt {
	public:
		HuntT1183(HuntRegister& record);

		virtual int ScanCursory(const Scope& scope, Reaction reaction);
	};
}