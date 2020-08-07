#include "hunt/HuntRegister.h"

#include <functional>
#include <iostream>

#include "util/log/Log.h"

#include "monitor/EventManager.h"
#include "user/bluespawn.h"
#include "util/Utils.h"
#include "util/ThreadPool.h"
#include "util/Promise.h"

decltype(HuntRegister::vRegisteredHunts) HuntRegister::vRegisteredHunts{};

void HuntRegister::RegisterHunt(std::unique_ptr<Hunt>&& hunt) {
    vRegisteredHunts.emplace_back(std::move(hunt));
}

bool HuntRegister::HuntShouldRun(IN Hunt* hunt,
                                 IN CONST std::vector<std::wstring> vIncludedHunts,
                                 IN CONST std::vector<std::wstring> vExcludedHunts) {
    if(vExcludedHunts.size() != 0) {
        for(auto name : vExcludedHunts) {
            if(hunt->GetName().find(name) != std::wstring::npos) {
                return false;
            }
        }
        return true;
    }
    if(vIncludedHunts.size() != 0) {
        for(auto name : vIncludedHunts) {
            if(hunt->GetName().find(name) != std::wstring::npos) {
                return true;
            }
        }
        return false;
    }
    return true;
}

std::vector<Promise<std::vector<std::shared_ptr<Detection>>>>
HuntRegister::RunHunts(IN CONST std::vector<std::wstring> vIncludedHunts,
                       IN CONST std::vector<std::wstring> vExcludedHunts,
                       IN CONST Scope& scope OPTIONAL,
                       IN CONST bool async OPTIONAL) {
    if(vExcludedHunts.size() != 0) {
        Bluespawn::io.InformUser(L"Starting a hunt for " +
                                 std::to_wstring(vRegisteredHunts.size() - vExcludedHunts.size()) + L" techniques.");
    } else if(vIncludedHunts.size() != 0) {
        Bluespawn::io.InformUser(L"Starting a hunt for " + std::to_wstring(vIncludedHunts.size()) + L" techniques.");
    } else {
        Bluespawn::io.InformUser(L"Starting a hunt for " + std::to_wstring(vRegisteredHunts.size()) + L" techniques.");
    }

    std::vector<Promise<std::vector<std::shared_ptr<Detection>>>> detections{};
    for(auto& hunt : vRegisteredHunts) {
        if(HuntShouldRun(hunt.get(), vIncludedHunts, vExcludedHunts)) {
            detections.emplace_back(RunHunt(hunt.get(), scope));
        }
    }

    if(async) {
        std::vector<HANDLE> handles(detections.begin(), detections.end());

        for(size_t idx{ 0 }; idx < handles.size(); idx += MAXIMUM_WAIT_OBJECTS) {
            auto count{ min(handles.size() - idx, MAXIMUM_WAIT_OBJECTS) };
            auto result{ WaitForMultipleObjects(count, handles.data() + idx, true, INFINITE) };
            if(result != WAIT_OBJECT_0) {
                LOG_ERROR("Failed to wait for hunts to finish (status 0x" << std::hex << result << ", error "
                                                                          << std::hex << GetLastError() << ")");
                throw std::exception("Failed to wait for hunts to finish!");
            }
        }

        auto successes{ std::count_if(detections.begin(), detections.end(),
                                      [](auto result) { return result.Fufilled(); }) };

        Bluespawn::io.InformUser(L"Successfully ran " + std::to_wstring(successes) + L" hunts.");
    }

    return detections;
}

Promise<std::vector<std::shared_ptr<Detection>>> HuntRegister::RunHunt(IN Hunt* hunt, IN CONST Scope& scope OPTIONAL) {
    Bluespawn::io.InformUser(L"Starting scan for " + hunt->GetName());

    return ThreadPool::GetInstance().RequestPromise<std::vector<std::shared_ptr<Detection>>>(
        [hunt, scope]() mutable { return hunt->RunHunt(scope); });
}

void HuntRegister::SetupMonitoring(IN CONST std::vector<std::wstring> vIncludedHunts,
                                   IN CONST std::vector<std::wstring> vExcludedHunts) {
    auto& EvtManager{ EventManager::GetInstance() };
    for(auto& hunt : vRegisteredHunts) {
        if(HuntShouldRun(hunt.get(), vIncludedHunts, vExcludedHunts)) {
            Bluespawn::io.InformUser(L"Setting up monitoring for " + hunt->GetName());
            for(auto& event : hunt->GetMonitoringEvents()) {
                auto callback{ std::bind(&Hunt::RunHunt, hunt.get(), std::placeholders::_1) };
                DWORD status{ EvtManager.SubscribeToEvent(std::move(event.first), callback, event.second) };
                if(status != ERROR_SUCCESS) {
                    LOG_ERROR(L"Monitoring for " << hunt->GetName() << L" failed with error code " << status);
                }
            }
        }
    }
}
