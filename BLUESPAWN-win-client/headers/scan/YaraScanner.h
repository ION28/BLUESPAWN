#pragma once

#include <string>
#include <vector>

#include "util/filesystem/FileSystem.h"
#include "util/wrappers.hpp"

#include "yara/types.h"

enum class YaraStatus {
    Success,
    RulesMissing,
    RulesInvalid,
    Failure,
};

struct YaraScanResult {
    std::vector<std::wstring> vKnownBadRules;
    std::vector<std::wstring> vIndicatorRules;

    YaraStatus status;

    operator bool();
    bool operator!();

    void AddBadRule(IN CONST std::wstring& identifier);
    void AddIndicatorRule(IN CONST std::wstring& identifier);
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
    YaraScanResult ScanMemory(LPVOID location, DWORD size) const;
    YaraScanResult ScanMemory(const AllocationWrapper& allocation) const;
    YaraScanResult ScanMemory(const MemoryWrapper<>& memory) const;

    YaraScanner(const YaraScanner&) = delete;
    YaraScanner operator=(const YaraScanner&) = delete;
    YaraScanner(YaraScanner&&) = delete;
    YaraScanner operator=(YaraScanner&&) = delete;
};
