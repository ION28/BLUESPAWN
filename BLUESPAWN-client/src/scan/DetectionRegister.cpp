#include "scan/DetectionRegister.h"
#include "scan/Scanner.h"

#include <unordered_set>

DetectionRegister::DetectionRegister(IN CONST Certainty& threshold) :
    threshold{ threshold },
    hEvent{ CreateEventW(nullptr, true, true, nullptr) }{}


void DetectionRegister::AddDetectionAsync(
    IN CONST std::reference_wrapper<Detection>& detection, IN CONST Certainty& certainty){

    BeginCriticalSection guard{ detection.get().hGuard };
    detection.get().info.SetCertainty(certainty);
    for(auto& scan : Scanner::scanners){
        detection.get().info.AddCertainty(scan.ScanDetection(detection.get()));
    }
    if(detection.get().info.GetCertainty() >= threshold){
        for(auto& scan : Scanner::scanners){
            for(auto& pair : scan.GetAssociatedDetections(detection.get())){
                Detection copy{ pair.first };
                detection.get().info.AddAssociation(AddDetection(std::move(copy), Certainty::None), pair.second);
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
}

std::reference_wrapper<Detection> DetectionRegister::AddDetection(IN Detection&& detection, 
                                                                  IN CONST Certainty& certainty){
    EnterCriticalSection(hScannedGuard);
    auto itr{ scanned.find(detection) };
    if(itr != scanned.end()){
        LeaveCriticalSection(hScannedGuard);
        auto ref{ *itr };
        EnterCriticalSection(ref.get());
        ref.get().info.AddCertainty(certainty);
        LeaveCriticalSection(ref.get());
        return std::reference_wrapper<Detection>{ ref };
    }
    LeaveCriticalSection(hScannedGuard);

    EnterCriticalSection(hQueueGuard);
    itr = queue.find(detection);
    if(itr != queue.end()){
        LeaveCriticalSection(hQueueGuard);
        auto ref{ *itr };
        EnterCriticalSection(ref.get());
        ref.get().info.AddCertainty(certainty);
        LeaveCriticalSection(ref.get());
        return ref;
    }
    LeaveCriticalSection(hQueueGuard);

    EnterCriticalSection(hGuard);
    detections.emplace_back(std::move(detection));
    std::reference_wrapper<Detection> ref{ detections[detections.size() - 1] };
    LeaveCriticalSection(hGuard);

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