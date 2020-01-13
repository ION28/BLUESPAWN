#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"
#include "hunt/reaction/Reaction.h"

Mitigation::Mitigation(MitigationRegister& reg, const std::wstring& name, const std::wstring& description, const std::wstring& software,
	SoftwareAffected category, MitigationSeverity severity) :
	name{ name },
	description{ description },
	software{ software },
	category{ category },
	severity{ severity } {
	reg.RegisterMitigation(std::shared_ptr<Mitigation>(this));
}

std::wstring Mitigation::getName() {
	return this->name;
}

std::wstring Mitigation::getDescription() {
	return this->description;
}