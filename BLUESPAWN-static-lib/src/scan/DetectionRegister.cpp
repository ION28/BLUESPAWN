#include "scan/DetectionRegister.h"

#include <unordered_set>

#include "util/ThreadPool.h"

#include "scan/Scanner.h"
#include "user/bluespawn.h"

DetectionRegister::DetectionRegister(IN CONST Certainty& threshold) :
    threshold{ threshold }, hEvent{ CreateEventW(nullptr, true, true, nullptr) } {}

void DetectionRegister::AddDetectionAsync(IN CONST std::shared_ptr<Detection>& detection,
                                          IN CONST Certainty& certainty) {
    EnterCriticalSection(*detection);
    detection->info.SetCertainty(certainty);
    for(auto& scan : Scanner::scanners) {
        detection->info.AddCertainty(scan->ScanDetection(*detection));
    }

    auto associations{ detection->info.GetAssociations() };
    LeaveCriticalSection(*detection);
    for(auto& pair : associations){
        pair.first->info.bAssociativeStale = true;
        for(auto& sink : Bluespawn::detectionSinks){
            sink->UpdateCertainty(pair.first);
        }
    }
    EnterCriticalSection(*detection);

    for(auto& scan : Scanner::scanners) {
        for(auto& pair : scan->GetAssociatedDetections(*detection)){
            detection->info.AddAssociation(pair.first, pair.second);
            pair.first->info.AddAssociation(detection, pair.second);

            auto first{ detection->dwID < pair.first->dwID ? detection : pair.first };
            auto second{ detection->dwID < pair.first->dwID ? pair.first : detection };

            LeaveCriticalSection(*detection);
            for(auto& sink : Bluespawn::detectionSinks){
                sink->RecordAssociation(first, second, pair.second);
            }
            EnterCriticalSection(*detection);
        }
    }

    EnterCriticalSection(hScannedGuard);
    scanned.emplace(detection);
    LeaveCriticalSection(hScannedGuard);

    EnterCriticalSection(hQueueGuard);
    queue.erase(detection);
    if(queue.size() == 0) {
        SetEvent(hEvent);
    }
    LeaveCriticalSection(hQueueGuard);

    if(detection->info.GetCertainty() >= threshold) {
        LeaveCriticalSection(*detection);
        for(auto& sink : Bluespawn::detectionSinks) {
            sink->RecordDetection(detection, RecordType::PostScan);
        }

        EnterCriticalSection(*detection);
        Bluespawn::reaction.React(*detection);
    }
    LeaveCriticalSection(*detection);
}

void DetectionRegister::UpdateDetectionCertainty(IN CONST std::shared_ptr<Detection>& detection,
                                                 IN CONST Certainty& certainty) {
    EnterCriticalSection(*detection);

    // if the detection is queued and we can enter its critical section, it hasn't been scanned yet
    bool queued{ false };
    EnterCriticalSection(hQueueGuard);
    if(queue.find(detection) != queue.end()) {
        detection->info.AddCertainty(certainty);
        queued = true;
    }
    LeaveCriticalSection(hQueueGuard);

    // The detection has been scanned
    if(!queued) {
        bool below{ !(detection->info.GetCertainty() >= threshold) };

        detection->info.AddCertainty(certainty);

        // This update caused it to pass the threshold, so scan for assocations
        if(below && detection->info.GetCertainty() >= threshold) {
            for(auto& scan : Scanner::scanners) {
                for(auto& pair : scan->GetAssociatedDetections(*detection)) {
                    detection->info.AddAssociation(pair.first, pair.second);
                    pair.first->info.AddAssociation(detection, pair.second);

                    auto first{ detection->dwID < pair.first->dwID ? detection : pair.first };
                    auto second{ detection->dwID < pair.first->dwID ? pair.first : detection };
                    for(auto& sink : Bluespawn::detectionSinks) {
                        sink->RecordAssociation(first, second, pair.second);
                    }
                }
            }

            LeaveCriticalSection(*detection);
            for(auto& sink : Bluespawn::detectionSinks){
                sink->RecordDetection(detection, RecordType::PostScan);
            }

            EnterCriticalSection(*detection);
            Bluespawn::reaction.React(*detection);
        } else if(!below && detection->info.GetCertainty() >= threshold){
            LeaveCriticalSection(*detection);
            for(auto& sink : Bluespawn::detectionSinks){
                sink->UpdateCertainty(detection);
            }
            EnterCriticalSection(*detection);
        }

        // Existing associations' associativity scores are now stale
        for(auto& pair : detection->info.GetAssociations()) {
            pair.first->info.bAssociativeStale = true;
            for(auto& sink : Bluespawn::detectionSinks){
                sink->UpdateCertainty(pair.first);
            }
        }
    } 

    LeaveCriticalSection(*detection);
}

std::shared_ptr<Detection> DetectionRegister::AddDetection(IN Detection&& raw, IN CONST Certainty& certainty) {
    auto detection{ std::make_shared<Detection>(raw) };
    for(auto& sink : Bluespawn::detectionSinks){
        sink->RecordDetection(detection, RecordType::PreScan);
    }

    EnterCriticalSection(hScannedGuard);
    auto itr{ scanned.find(detection) };
    if(itr != scanned.end()) {
        LeaveCriticalSection(hScannedGuard);
        auto ref{ *itr };
        for(auto& hunt : raw.context.hunts){
            if(ref->context.hunts.find(hunt) == ref->context.hunts.end()){
                ThreadPool::GetInstance().EnqueueTask(
                    std::bind(&DetectionRegister::UpdateDetectionCertainty, this, ref, certainty));
                return ref;
            }
        }
        return ref;
    }
    LeaveCriticalSection(hScannedGuard);

    EnterCriticalSection(hQueueGuard);
    itr = queue.find(detection);
    if(itr != queue.end()) {
        LeaveCriticalSection(hQueueGuard);
        auto ref{ *itr };
        for(auto& hunt : raw.context.hunts){
            if(ref->context.hunts.find(hunt) == ref->context.hunts.end()){
                ThreadPool::GetInstance().EnqueueTask(
                    std::bind(&DetectionRegister::UpdateDetectionCertainty, this, ref, certainty));
                return ref;
            }
        }
        return ref;
    }
    LeaveCriticalSection(hQueueGuard);

    EnterCriticalSection(hGuard);
    detections.emplace_back(detection);
    std::shared_ptr<Detection> ref{ detections[detections.size() - 1] };
    ids.emplace(detection->dwID, ref);
    LeaveCriticalSection(hGuard);

    for(auto& sink : Bluespawn::detectionSinks) {
        sink->RecordDetection(ref, RecordType::PreScan);
    }

    ResetEvent(hEvent);

    EnterCriticalSection(hQueueGuard);
    queue.emplace(ref);
    LeaveCriticalSection(hQueueGuard);

    ThreadPool::GetInstance().EnqueueTask(std::bind(&DetectionRegister::AddDetectionAsync, this, ref, certainty));

    return ref;
}

void DetectionRegister::Wait() CONST {
    auto status{ WaitForSingleObject(hEvent, INFINITE) };
    if(status != ERROR_SUCCESS) {
        BeginCriticalSection _{ hQueueGuard };
        if(queue.size() != 0) {
            throw std::exception{ "Failed to wait for detection register to finish scans!" };
        }
    }
}

DetectionRegister::operator HANDLE() CONST {
    return hEvent;
}

std::vector<std::shared_ptr<Detection>> DetectionRegister::GetAllDetections(IN CONST Certainty& level OPTIONAL) CONST {
    Wait();
    BeginCriticalSection _{ hScannedGuard };
    std::vector<std::shared_ptr<Detection>> found{};
    for(auto detection : scanned) {
        if(detection->info.certainty >= level) {
            found.emplace_back(detection);
        }
    }
    return found;
}

std::shared_ptr<Detection> DetectionRegister::GetByID(IN DWORD ID) CONST{
    BeginCriticalSection _{ hGuard };
    if(ids.find(ID) != ids.end()){
        return ids.at(ID);
    } else{
        return nullptr;
    }
}