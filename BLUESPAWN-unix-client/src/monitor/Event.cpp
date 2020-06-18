#include "monitor/Event.h"
#include "reaction/Log.h"
#include "util/eventlogs/EventLogs.h"
#include "monitor/EventListener.h"
#include "user/bluespawn.h"
#include <string>

Event::Event(EventType type) : type(type) {

}

void RunCallback(const HuntEnd& callback){
    callback(); //TODO: error check?
}

std::optional<Scope> Event::GetScope() const {
    return this->scope;
}

EventType Event::GetType() const{
    return this->type;
}

FileEvent::FileEvent(const std::string& path, FileEventAction action, bool watchSubdirs = false){

}

std::string FileEvent::GetPath() const {
    return this->path;
}

bool FileEvent::IsWatchingSubdirs() const {
    return this->watchSubdirs;
}

bool FileEvent::Subscribe(){

}

FileEventAction FileEvent::GetAction() const{
    return this->action;
}

bool FileEvent::operator==(const Event& e) const{
    
}

ProcessEvent::ProcessEvent(ProcessEventAction action, std::optional<int> signo = std::nullopt){

}

ProcessEventAction ProcessEvent::GetAction() const{
    return this->action;
}

bool ProcessEvent::Subscribe(){

}

bool ProcessEvent::operator==(const Event& e) const{

}

std::optional<int> ProcessEvent::GetSignalNumber() const {
    return this->signo;
}


