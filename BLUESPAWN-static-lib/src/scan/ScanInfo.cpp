#include "scan/ScanInfo.h"

#include <queue>
#include <unordered_map>
#include <atomic>

#include "scan/Detections.h"

const Certainty Certainty::Certain =  1.00;
const Certainty Certainty::Strong =   0.75;
const Certainty Certainty::Moderate = 0.50;
const Certainty Certainty::Weak =     0.25;
const Certainty Certainty::None =     0.00;
Certainty::Certainty(double certainty) : confidence{ certainty }{}
Certainty::operator double() const { return confidence; }
Certainty Certainty::operator*(Certainty c) const { return confidence * c.confidence; }
Certainty Certainty::operator+(Certainty c) const { return 1 - (1 - confidence) * (1 - c.confidence); }
bool Certainty::operator==(Certainty c) const {
	return c.confidence > confidence ? c.confidence - confidence <= 0.125 : confidence - c.confidence <= 0.125;
}
bool Certainty::operator!=(Certainty c) const { 
	return c.confidence > confidence ? c.confidence - confidence > 0.125 : confidence - c.confidence > 0.125; 
}
bool Certainty::operator>=(Certainty c) const { return *this > c || *this == c; }
bool Certainty::operator<=(Certainty c) const { return *this > c || *this == c; }
bool Certainty::operator>(Certainty c) const { return confidence > c.confidence; }
bool Certainty::operator<(Certainty c) const { return confidence < c.confidence; }

volatile std::atomic<DWORD> Detection::IDCounter{ 1 };

ScanInfo::ScanInfo() : 
	certainty{ Certainty::None },
	cAssociativeCertainty{ Certainty::None },
	associations{ std::make_unique<std::unordered_map<std::shared_ptr<Detection>, Association>>() },
	bAssociativeStale{ true }{}

std::unordered_map<std::shared_ptr<Detection>, Association> ScanInfo::GetAssociations(){
	BeginCriticalSection _{ hGuard };
	return *associations;
}

Certainty ScanInfo::GetCertainty(){ 
	BeginCriticalSection _{ hGuard };
	if(bAssociativeStale){
		cAssociativeCertainty = Certainty::None;
		
		for(auto& pair : *associations){
			LeaveCriticalSection(hGuard);
			auto raw{ pair.first->info.GetIntrinsicCertainty() };
			EnterCriticalSection(hGuard);
			cAssociativeCertainty = cAssociativeCertainty + (raw * pair.second);
		}

		bAssociativeStale = false;
	}
	return certainty + cAssociativeCertainty; 
};

Certainty ScanInfo::GetIntrinsicCertainty(){
	BeginCriticalSection _{ hGuard };
	return certainty;
};

void ScanInfo::AddAssociation(IN CONST std::shared_ptr<Detection>& node, IN CONST Association& a){
	BeginCriticalSection _{ hGuard };
	bAssociativeStale = true;
	if(associations->find(node) == associations->end()){
		associations->emplace(node, a);
	} else{
		auto& assoc{ associations->at(node) };
		assoc = assoc + a;
	}
}

void ScanInfo::SetCertainty(IN CONST Certainty& certainty){
	this->certainty = certainty;
}

void ScanInfo::AddCertainty(IN CONST Certainty& certainty){
	this->certainty = this->certainty + certainty;
}

ScanInfo::operator LPCRITICAL_SECTION() const {
	return hGuard;
}