#include "pe/Relocation_Section.h"

#include <Windows.h>

#include "pe/PE_Section.h"

Relocation_Section::Relocation_Section(const PE_Section& section) : PE_Section(section) {
	
};