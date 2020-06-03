#pragma once
#include "Reaction.h"

#include "hunt/HuntInfo.h"
#include "user/iobase.h"
#include "common/DynamicLinker.h"

#include <optional>

DEFINE_FUNCTION(NTSTATUS, NtSuspendProcess, NTAPI, IN HANDLE ProcessHandle);

namespace Reactions{

	class SuspendProcessReaction : public Reaction {
	private:
		const IOBase& io;

		bool CheckModules(const HandleWrapper& process, const std::string& file) const;

		/// Handlers for detections that log the detection
		void SuspendFileIdentified(std::shared_ptr<FILE_DETECTION> detection);
		void SuspendProcessIdentified(std::shared_ptr<PROCESS_DETECTION> detection);
		void SuspendServiceIdentified(std::shared_ptr<SERVICE_DETECTION> detection);

	public:
		SuspendProcessReaction(const IOBase& io);
	};
}

