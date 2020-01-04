#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"
#include "util/reaction/Reaction.h"

Mitigation::Mitigation(MitigationRegister& record, const std::string& name) :
	name{ name } {
	record.RegisterMitigation(this);
}

std::string Mitigation::getName() {
	return this->name;
}

std::string Mitigation::getDescription() {
	return this->description;
}

bool Mitigation::isEnforced(SecurityLevel level, Reaction reaction) {
	return false;
}

bool Mitigation::enforce(SecurityLevel level, Reaction reaction) {
	return false;
}