#include "hunt/Scope.h"

Scope Scope::CreateSubhuntScope(IN DWORD Subtechniques, IN DWORD64 Subsections OPTIONAL){
	Scope scope{};
	scope.Subtechniques = Subtechniques;
	if(Subsections != -1ULL){
		scope.Subsections = Subsections;
	}

	return scope;
}