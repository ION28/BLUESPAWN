#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>

// The developer of this library is a bad developer who left warnings in his code.
// Since we enforce no warnings, this is bad.
#pragma warning(push)

#pragma warning(disable : 26451)
#pragma warning(disable : 26444)

#include <cxxopts.hpp>

#pragma warning(pop)

#include "bluespawn/banners.h"
#include "logging/Log.h"
#include "logging/CLISink.h"
#include "logging/NetworkSink.h"
#include "configuration/Registry.h"

#include "hunts/Hunt.h"
#include "hunts/HuntRegister.h"
#include "hunts/HuntT1004.h"
#include "hunts/HuntT1037.h"
#include "hunts/HuntT1060.h"
#include "hunts/HuntT1100.h"
#include "hunts/HuntT1101.h"
#include "hunts/HuntT1103.h"
#include "hunts/HuntT1131.h"
#include "hunts/HuntT1138.h"
#include "hunts/HuntT1182.h"

void print_help(cxxopts::ParseResult result, cxxopts::Options options);
void dispatch_hunt(cxxopts::ParseResult result, cxxopts::Options options);