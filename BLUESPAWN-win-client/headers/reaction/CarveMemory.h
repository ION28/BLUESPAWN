#pragma once
#include "Reaction.h"

#include "hunt/HuntInfo.h"
#include "user/iobase.h"

namespace Reactions{

	class CarveMemoryReaction : public Reaction {

		/**
		 * Reacts to a registry detection by carving infected memory sections from a process
		 * Note that this will cause a crash if function pointers are stored to the infected
		 * memory for functions with more than four arguments in x64 or any arguments with 
		 * stdcall functions in x86.
		 *
		 * @param detection The detection to which the reaction will be applied.
		 */
		virtual void React(
			IN Detection& detection
		);

		/**
		 * Function to determine if this reaction applies to a detection. This ensures that
		 * the detection is not stale and that it references a registry value.
		 *
		 * @param detection The detection to check
		 *
		 * @return True if this reaction applies; false otherwise
		 */
		virtual bool Applies(
			IN CONST Detection& detection
		);
	};
}

