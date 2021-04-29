#include "hunt/Scope.h"

Scope Scope::CreateSubhuntScope(IN DWORD64 Subsections, IN DWORD Subtechniques OPTIONAL) {
    Scope scope{};
    scope.Subtechniques = Subtechniques;
    if(Subsections != -1ULL) {
        scope.Subsections = Subsections;
    }

    return scope;
}
