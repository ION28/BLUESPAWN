#pragma once

#include "yara.h"
#include "util/filesystem/FileSystem.h"
#include "common/wrappers.hpp"

#include <vector>
#include <string>

enum class YaraStatus {
	Success,
	RulesMissing,
	RulesInvalid,
	Failure,
};

struct YaraScanResult {
	std::vector<std::string> vKnownBadRules;
	std::vector<std::string> vIndicatorRules;

	YaraStatus status;

	operator bool();
	bool operator!();

	void AddBadRule(const char* identifier);
	void AddIndicatorRule(const char* identifier);
};

class YaraScanner {
private:
	static const YaraScanner instance;

	YaraScanner();
	
	YR_RULES* KnownBad = nullptr;
	YR_RULES* KnownBad2 = nullptr;
	YR_RULES* Indicators = nullptr;

	YaraStatus status;

public:

	static const YaraScanner& GetInstance();

	~YaraScanner();

	YaraScanResult ScanFile(const FileSystem::File& file) const;
	YaraScanResult ScanMemory(void* location, unsigned int size) const;
	YaraScanResult ScanMemory(const AllocationWrapper& allocation) const;
	YaraScanResult ScanMemory(const MemoryWrapper<>& memory) const;

	YaraScanner(const YaraScanner&) = delete;
	YaraScanner operator=(const YaraScanner&) = delete;
	YaraScanner(YaraScanner&&) = delete;
	YaraScanner operator=(YaraScanner&&) = delete;
};