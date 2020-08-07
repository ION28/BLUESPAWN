#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"

Mitigation::Mitigation(const std::wstring& name, const std::wstring& description, const std::wstring& software,
	SoftwareAffected category, MitigationSeverity severity) :
	name{ name },
	description{ description },
	software{ software },
	category{ category },
	severity{ severity } {
}

std::wstring Mitigation::getName() {
	return this->name;
}

std::wstring Mitigation::getDescription() {
	return this->description;
}