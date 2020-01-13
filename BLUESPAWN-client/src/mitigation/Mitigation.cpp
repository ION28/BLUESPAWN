#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"
#include "hunt/reaction/Reaction.h"

Mitigation::Mitigation(MitigationRegister& record, const std::wstring& name) :
	name{ name } {
	record.RegisterMitigation(std::shared_ptr<Mitigation>(this));
}

std::wstring Mitigation::getName() {
	return this->name;
}

std::wstring Mitigation::getDescription() {
	return this->description;
}