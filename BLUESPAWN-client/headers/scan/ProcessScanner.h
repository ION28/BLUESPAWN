#pragma once

#include "scan/ScanNode.h"

#include <map>
#include <vector>

#include "util/filesystem/FileSystem.h"

class ProcessScanner {
public:
	static std::map<ScanNode, Association> GetAssociatedDetections(const Detection& base, Aggressiveness level);
	static std::vector<FileSystem::File> ScanCommand(const std::wstring& command);
	static Certainty ScanItem(const Detection& base, Aggressiveness level);
};