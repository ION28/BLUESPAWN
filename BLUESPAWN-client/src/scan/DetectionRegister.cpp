#include "scan/DetectionRegister.h"
#include "scan/Scanner.h"
#include "user/bluespawn.h"
#include "common/ThreadPool.h"

#include <unordered_set>

DetectionRegister::DetectionRegister(IN CONST Certainty& threshold) :
    threshold{ threshold },
    hEvent{ CreateEventW(nullptr, true, true, nullptr) }{}


void DetectionRegister::AddDetectionAsync(
    IN CONST std::reference_wrapper<Detection>& detection, IN CONST Certainty& certainty){

    EnterCriticalSection(detection.get());
    detection.get().info.SetCertainty(certainty);
    for(auto& scan : Scanner::scanners){
        detection.get().info.AddCertainty(scan.ScanDetection(detection.get()));
    }
    if(detection.get().info.GetCertainty() >= threshold){
        for(auto& scan : Scanner::scanners){
            for(auto& pair : scan.GetAssociatedDetections(detection.get())){
                detection.get().info.AddAssociation(pair.first, pair.second);
                pair.first.get().info.AddAssociation(detection.get(), pair.second);

                auto first{ detection.get().dwID < pair.first.get().dwID ? detection : pair.first };
                auto second{ detection.get().dwID < pair.first.get().dwID ? pair.first : detection };
                for(auto& sink : Bluespawn::detectionSinks){
                    sink->RecordAssociation(first, second, pair.second);
                }
            }
        }
    }
    LeaveCriticalSection(detection.get());

    EnterCriticalSection(hScannedGuard);
    scanned.emplace(detection);
    LeaveCriticalSection(hScannedGuard);

    EnterCriticalSection(hQueueGuard);
    queue.erase(detection);
    if(queue.size() == 0){
        SetEvent(hEvent);
    }
    LeaveCriticalSection(hQueueGuard);

    for(auto& sink : Bluespawn::detectionSinks){
        sink->RecordDetection(detection, RecordType::PostScan);
    }

    EnterCriticalSection(detection.get());
    Bluespawn::reaction.React(detection.get());
    LeaveCriticalSection(detection.get());
}

void DetectionRegister::UpdateDetectionCertainty(
    IN CONST std::reference_wrapper<Detection>& detection, IN CONST Certainty& certainty){

    EnterCriticalSection(detection.get());

    // if the detection is queued and we can enter its critical section, it hasn't been scanned yet
    bool queued{ false };
    EnterCriticalSection(hQueueGuard);
    if(queue.find(detection) != queue.end()){
        detection.get().info.AddCertainty(certainty);
        queued = true;
    }
    LeaveCriticalSection(hQueueGuard);

    // The detection has been scanned
    if(!queued){
        bool below{ !(detection.get().info.GetCertainty() >= threshold) };

        detection.get().info.AddCertainty(certainty);
        
        // This update caused it to pass the threshold, so scan for assocations
        if(below && detection.get().info.GetCertainty() >= threshold){
            for(auto& scan : Scanner::scanners){
                for(auto& pair : scan.GetAssociatedDetections(detection.get())){
                    detection.get().info.AddAssociation(pair.first, pair.second);
                    pair.first.get().info.AddAssociation(detection.get(), pair.second);

                    auto first{ detection.get().dwID < pair.first.get().dwID ? detection : pair.first };
                    auto second{ detection.get().dwID < pair.first.get().dwID ? pair.first : detection };
                    for(auto& sink : Bluespawn::detectionSinks){
                        sink->RecordAssociation(first, second, pair.second);
                    }
                }
            }
        } 

        // Existing associations' associativity scores are now stale
        else{
            for(auto& pair : detection.get().info.associations){
                pair.first.get().info.bAssociativeStale = true;
            }
        }
    }

    LeaveCriticalSection(detection.get());
}

std::reference_wrapper<Detection> DetectionRegister::AddDetection(IN Detection&& detection, 
                                                                  IN CONST Certainty& certainty){
    EnterCriticalSection(hScannedGuard);
    auto itr{ scanned.find(detection) };
    if(itr != scanned.end()){
        LeaveCriticalSection(hScannedGuard);
        auto ref{ *itr };
        for(auto& sink : Bluespawn::detectionSinks){
            sink->RecordDetection(ref, RecordType::PreScan);
        }
        ThreadPool::GetInstance().EnqueueTask(std::bind(&DetectionRegister::UpdateDetectionCertainty, this, ref, 
                                                        certainty));
        return ref;
    }
    LeaveCriticalSection(hScannedGuard);

    EnterCriticalSection(hQueueGuard);
    itr = queue.find(detection);
    if(itr != queue.end()){
        LeaveCriticalSection(hQueueGuard);
        auto ref{ *itr };
        for(auto& sink : Bluespawn::detectionSinks){
            sink->RecordDetection(ref, RecordType::PreScan);
        }
        ThreadPool::GetInstance().EnqueueTask(std::bind(&DetectionRegister::UpdateDetectionCertainty, this, ref,
                                                        certainty));
        return ref;
    }
    LeaveCriticalSection(hQueueGuard);

    EnterCriticalSection(hGuard);
    detections.emplace_back(std::move(detection));
    std::reference_wrapper<Detection> ref{ detections[detections.size() - 1] };
    LeaveCriticalSection(hGuard);

    for(auto& sink : Bluespawn::detectionSinks){
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
    if(status != ERROR_SUCCESS){
        EnterCriticalSection(hQueueGuard);
        if(queue.size() != 0){
            LeaveCriticalSection(hQueueGuard);
            throw std::exception{ "Failed to wait for detection register to finish scans!" };
        }
        LeaveCriticalSection(hQueueGuard);
    }
}

DetectionRegister::operator HANDLE() CONST{
    return hEvent;
}

std::vector<std::reference_wrapper<Detection>> DetectionRegister::GetAllDetections(
    IN CONST Certainty& level OPTIONAL) CONST {
    Wait();
    EnterCriticalSection(hScannedGuard);
    std::vector<std::reference_wrapper<Detection>> found{};
    for(auto detection : scanned){
        if(detection.get().info.certainty >= level){
            found.emplace_back(detection);
        }
    }
    LeaveCriticalSection(hScannedGuard);
    return found;
}