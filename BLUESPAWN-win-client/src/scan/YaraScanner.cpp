#include "scan/YaraScanner.h"

#include <zip.h>

#include "util/StringUtils.h"
#include "util/log/Log.h"
#include "util/wrappers.hpp"

#include "../resources/resource.h"
#include "yara/libyara.h"
#include "yara/rules.h"

const YaraScanner YaraScanner::instance{};

AllocationWrapper GetResourceRule(DWORD identifier) {
    auto hRsrcInfo = FindResourceW(nullptr, MAKEINTRESOURCE(identifier), L"yararule");
    if(!hRsrcInfo) {
        return { nullptr, 0 };
    }

    auto hRsrc = LoadResource(nullptr, hRsrcInfo);
    if(!hRsrc) {
        return { nullptr, 0 };
    }

    zip_error_t err{};
    auto lpZipSource = zip_source_buffer_create(LockResource(hRsrc), SizeofResource(nullptr, hRsrcInfo), 0, &err);
    if(lpZipSource) {
        auto zip = zip_open_from_source(lpZipSource, 0, &err);
        if(zip) {
            auto fdRules = zip_fopen(zip, "data", 0);
            if(fdRules) {
                zip_stat_t stats{};
                if(-1 != zip_stat(zip, "data", ZIP_STAT_SIZE, &stats)) {
                    if(-1 != stats.size) {
                        AllocationWrapper data{ HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                                          static_cast<SIZE_T>(stats.size)),
                                                static_cast<SIZE_T>(stats.size), AllocationWrapper::HEAP_ALLOC };
                        if(-1 != zip_fread(fdRules, data, stats.size)) {
                            zip_fclose(fdRules);
                            zip_close(zip);
                            zip_source_close(lpZipSource);

                            return data;
                        }
                    }
                }

                zip_fclose(fdRules);
            }
            zip_close(zip);
        }
        zip_source_close(lpZipSource);
    }

    return { nullptr, 0 };
}

struct AllocationWrapperStream {
    AllocationWrapper wrapper;
    size_t offset;
};

size_t ReadAllocationWrapper(LPVOID dest, size_t size, size_t count, AllocationWrapperStream* data) {
    size_t desired_amnt = size * count;
    size_t actual_amnt = min(desired_amnt, data->wrapper.GetSize() - data->offset);

    CopyMemory(dest, reinterpret_cast<PCHAR>((LPVOID) data->wrapper) + data->offset, actual_amnt);

    data->offset += actual_amnt;
    return actual_amnt / size;
}

YR_RULES* LoadRules(const AllocationWrapper& memory) {
    AllocationWrapperStream stream_data = { memory, 0 };
    YR_STREAM stream = { &stream_data, YR_STREAM_READ_FUNC(ReadAllocationWrapper) };
    YR_RULES* rules;
    auto status = yr_rules_load_stream(&stream, &rules);
    if(status != ERROR_SUCCESS) {
        return nullptr;
    }
    return rules;
}

YaraScanner::YaraScanner() : status{ YaraStatus::Success } {
    yr_initialize();

    auto hSevereYara = GetResourceRule(YaraSevere);
    if(!hSevereYara) {
        status = YaraStatus::RulesMissing;
        return;
    }
    KnownBad = LoadRules(hSevereYara);
    if(!KnownBad) {
        status = YaraStatus::RulesMissing;
        return;
    }

    auto hSevereYara2 = GetResourceRule(YaraSevere2);
    if(!hSevereYara2) {
        status = YaraStatus::RulesMissing;
        return;
    }
    KnownBad2 = LoadRules(hSevereYara2);
    if(!KnownBad2) {
        status = YaraStatus::RulesMissing;
        return;
    }

    auto hIndicatorsYara = GetResourceRule(YaraIndicators);
    if(!hIndicatorsYara) {
        status = YaraStatus::RulesInvalid;
        return;
    }
    Indicators = LoadRules(hIndicatorsYara);
    if(!Indicators) {
        status = YaraStatus::RulesInvalid;
        return;
    }
}

YaraScanner::~YaraScanner() {
    if(KnownBad) {
        yr_rules_destroy(KnownBad);
        KnownBad = nullptr;
    }

    if(KnownBad2) {
        yr_rules_destroy(KnownBad2);
        KnownBad2 = nullptr;
    }

    if(Indicators) {
        yr_rules_destroy(Indicators);
        Indicators = nullptr;
    }
    yr_finalize();
}

const YaraScanner& YaraScanner::GetInstance() {
    return instance;
}

struct YaraScanArg {
    YaraScanResult result;
    enum { Severe, Indicator } type;
};

int YaraCallbackFunction(int message, LPVOID lpMessageData, YaraScanArg* arg) {
    if(message == CALLBACK_MSG_RULE_MATCHING) {
        auto rule = reinterpret_cast<YR_RULE*>(lpMessageData);
        if(arg->type == arg->Severe) {
            arg->result.AddBadRule(StringToWidestring(rule->identifier));
        } else if(arg->type == arg->Indicator) {
            arg->result.AddIndicatorRule(StringToWidestring(rule->identifier));
        }
    }
    return CALLBACK_CONTINUE;
}

YaraScanResult YaraScanner::ScanFile(const FileSystem::File& file) const {
    if(status != YaraStatus::Success) {
        YaraScanResult res = {};
        res.status = status;
        return res;
    }

    auto memory = file.Read();
    if(!memory) {
        YaraScanResult result{};
        result.status = YaraStatus::Failure;
        return result;
    }
    auto result{ ScanMemory(memory) };

    for(auto identifier : result.vKnownBadRules) {
        LOG_INFO(1, file.GetFilePath() << L" matches known malicious identifier " << identifier);
    }
    for(auto identifier : result.vIndicatorRules) {
        LOG_INFO(2, file.GetFilePath() << L" matches known indicator identifier " << identifier);
    }

    return result;
}

YaraScanResult YaraScanner::ScanMemory(const AllocationWrapper& memory) const {
    YaraScanArg arg{};
    arg.result.status = YaraStatus::Success;
    arg.type = arg.Severe;
    auto status = yr_rules_scan_mem(KnownBad, reinterpret_cast<const uint8_t*>((LPVOID) memory), memory.GetSize(), 0,
                                    YR_CALLBACK_FUNC(YaraCallbackFunction), &arg, 0);
    if(status != ERROR_SUCCESS) {
        arg.result.status = YaraStatus::Failure;
    }

    arg.type = arg.Severe;
    status = yr_rules_scan_mem(KnownBad2, reinterpret_cast<const uint8_t*>((LPVOID) memory), memory.GetSize(), 0,
                               YR_CALLBACK_FUNC(YaraCallbackFunction), &arg, 0);
    if(status != ERROR_SUCCESS) {
        arg.result.status = YaraStatus::Failure;
    }

    arg.type = arg.Indicator;
    status = yr_rules_scan_mem(Indicators, reinterpret_cast<const uint8_t*>((LPVOID) memory), memory.GetSize(), 0,
                               YR_CALLBACK_FUNC(YaraCallbackFunction), &arg, 0);
    if(status != ERROR_SUCCESS) {
        arg.result.status = YaraStatus::Failure;
    }

    return arg.result;
}

YaraScanResult YaraScanner::ScanMemory(LPVOID memory, DWORD dwSize) const {
    return ScanMemory(AllocationWrapper{ memory, dwSize });
}

YaraScanResult YaraScanner::ScanMemory(const MemoryWrapper<>& memory) const {
    return ScanMemory(memory.ToAllocationWrapper());
}

void YaraScanResult::AddBadRule(const std::wstring& identifier) {
    vKnownBadRules.emplace_back(identifier);
}

void YaraScanResult::AddIndicatorRule(const std::wstring& identifier) {
    vIndicatorRules.emplace_back(identifier);
}

YaraScanResult::operator bool() {
    return vKnownBadRules.empty() && status == YaraStatus::Success;
}

bool YaraScanResult::operator!() {
    return !(vKnownBadRules.empty() && status == YaraStatus::Success);
}
