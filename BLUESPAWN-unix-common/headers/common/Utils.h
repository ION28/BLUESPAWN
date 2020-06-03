#pragma once

#include <sys/stat.h>
#include <vector>
#include <string>

#define ADD_ALL_VECTOR(v1, v2)  \
    {                           \
        auto& tmp = v2;         \
		for(auto& v : tmp){     \
			v1.emplace_back(v); \
		}                       \
    }


std::string FormatStatTime(const struct statx_timestamp systemtime); 