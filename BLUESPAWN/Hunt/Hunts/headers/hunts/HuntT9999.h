#pragma once
#include "Hunt.h"
#include "reactions/Reaction.h"
#include "reactions/Log.h"

#include <string>
#include <vector>

namespace Hunts {

	/**
	 * This hunt is created as a proof of concept and as an example for the structure of a hunt.
	 *
	 * HuntT9999 will attempt to detect the existence of a given list of files. After instantiating
	 * it, call AddFileToSeach on each file to add to the search.
	 *
	 * @scans Cursory Checks if the file exists as an absolute path or relative path to the current
	 *        working directory.
	 * @scans Moderate Scan not supported.
	 * @scans Careful Scan not supported.
	 * @scans Aggressive Scan not supported.
	 */
	class HuntT9999 : public Hunt {
	private:
		std::vector<std::string> vFileNames{};

	public:
		HuntT9999(HuntRegister& record);

		void AddFileToSearch(std::string sFileName);

		int ScanCursory(Scope& scope, Reaction* reaction = new Reactions::LogReaction());
	};
}