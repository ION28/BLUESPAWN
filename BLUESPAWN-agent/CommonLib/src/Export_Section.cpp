#include "pe/Export_Section.h"

#include <Windows.h>
#include <winternl.h>

#include <vector>
#include <string>

Export_Section::Export_Section(const PE_Section& section) : 
	exports{}, export_directory{}{

}