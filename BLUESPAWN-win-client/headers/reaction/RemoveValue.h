#pragma once
#include "Reaction.h"

#include "hunt/HuntInfo.h"
#include "user/iobase.h"
#include "util/DynamicLinker.h"

#include <optional>

namespace Reactions{

	class RemoveValueReaction : public Reaction {

		/**
		 * Reacts to a registry detection by removing it from the registry
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

