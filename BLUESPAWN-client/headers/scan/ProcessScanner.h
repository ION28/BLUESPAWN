#pragma once

#include <map>
#include <vector>

#include "util/filesystem/FileSystem.h"

class ProcessScanner {
public:
	static std::map<std::shared_ptr<ScanNode>, Association> GetAssociatedDetections(const std::shared_ptr<ScanNode>& node);
	static std::vector<FileSystem::File> ScanCommand(const std::wstring& command);
	static Certainty ScanItem(const std::shared_ptr<ScanNode>& base);
};