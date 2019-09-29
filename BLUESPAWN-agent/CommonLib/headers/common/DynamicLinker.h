#pragma once

#include <Windows.h>
#include <winternl.h>

#define DEFINE_FUNCTION(retval, name, convention, ...)    \
    typedef retval(convention *name##_type)(__VA_ARGS__); \
    extern name##_type name##_func;

DEFINE_FUNCTION(NTSTATUS, LdrpPreprocessDllName, NTAPI, __in PUNICODE_STRING input, __out PUNICODE_STRING output, PULONG_PTR zero1, PULONG_PTR zero2);