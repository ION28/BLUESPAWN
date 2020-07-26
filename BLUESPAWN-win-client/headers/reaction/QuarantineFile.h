#pragma once
#include <optional>

#include "util/DynamicLinker.h"

#include "Reaction.h"
#include "hunt/HuntInfo.h"
#include "user/iobase.h"

namespace Reactions {

	class QuarantineFileReaction : public Reaction {
		/**
		 * Reacts to a file detection by quarantining it
		 *
		 * @param detection The detection to which the reaction will be applied.
		 */
		virtual void React(IN Detection& detection);

		/**
		 * Function to determine if this reaction applies to a detection. This ensures that
		 * the detection is not stale and reference a file
		 *
		 * @param detection The detection to check
		 *
		 * @return True if this reaction applies; false otherwise
		 */
		virtual bool Applies(IN CONST Detection& detection);
	};
}   // namespace Reactions
