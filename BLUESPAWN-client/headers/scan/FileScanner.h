#pragma once

#include "scan/Scanner.h"

class FileScanner : public Scanner {
public:
	virtual std::vector<std::shared_ptr<DETECTION>> GetAssociatedDetections(std::shared_ptr<DETECTION> base, Aggressiveness level);
	
	static std::vector<std::wstring> ExtractFilePaths(const std::vector<std::wstring>& strings);
	static std::vector<std::wstring> ExtractStrings(const AllocationWrapper& data, DWORD dwMinLength = 5);
};