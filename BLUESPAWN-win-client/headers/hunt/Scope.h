#pragma once
#include <Windows.h>

#include <optional>
#include <vector>

/**
 * Used to define the scope of a hunt. Currently, this operates by requiring the programmer to
 * define a new class for each new scope. This is less than ideal, as scopes should eventually 
 * be defined by the end user. Future implementation will allow the programmer to pass in lambdas
 * which will be handled by the functions built in to the class, removing the need for new scopes.
 */
class Scope {
    public:
    /// This field is specific to the hunt being run. It is computed as a bitwise OR of segments of the hunt. Note that
    /// subsections should be unique per hunt and that different subtechniques should not use the same hunt segments.
    std::optional<DWORD64> Subsections;

    /// This field is specific to the hunt being run. It is computed as a bitwise OR of subtechnique IDs to be run.
    std::optional<DWORD> Subtechniques;

    static Scope CreateSubhuntScope(IN DWORD64 Subsections, IN DWORD Subtechniques = -1UL OPTIONAL);
};
