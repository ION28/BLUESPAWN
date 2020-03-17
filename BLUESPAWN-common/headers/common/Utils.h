#pragma once

#include <vector>

#define ADD_ALL_VECTOR(v1, v2)  \
    {                           \
        auto& tmp = v2;         \
		for(auto& v : tmp){     \
			v1.emplace_back(v); \
		}                       \
    }