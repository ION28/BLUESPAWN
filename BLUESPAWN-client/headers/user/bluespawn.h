#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <Windows.h>

// The developer of this library is a bad developer who left warnings in his code.
// Since we enforce no warnings, this is bad.
#pragma warning(push)

#pragma warning(disable : 26451)
#pragma warning(disable : 26444)

    #include "cxxopts.hpp"

#pragma warning(pop)

#include "user/banners.h"

#include "util/log/Log.h"
#include "util/log/CLISink.h"
#include "util/configurations/Registry.h"

#include "monitor/ETW_Wrapper.h"

#include "hunt/Hunt.h"
#include "hunt/HuntRegister.h"
#include "hunt/hunts/HuntT1004.h"
#include "hunt/hunts/HuntT1037.h"
#include "hunt/hunts/HuntT1050.h"
#include "hunt/hunts/HuntT1055.h"
#include "hunt/hunts/HuntT1060.h"
#include "hunt/hunts/HuntT1100.h"
#include "hunt/hunts/HuntT1101.h"
#include "hunt/hunts/HuntT1103.h"
#include "hunt/hunts/HuntT1131.h"
#include "hunt/hunts/HuntT1138.h"
#include "hunt/hunts/HuntT1182.h"
#include "hunt/hunts/HuntT1183.h"

#include "mitigation/Mitigation.h"
#include "mitigation/MitigationRegister.h"
#include "mitigation/mitigations/MitigateM1042-LLMNR.h"
#include "mitigation/mitigations/MitigateM1042-WSH.h"
#include "mitigation/mitigations/MitigateV1093.h"
#include "mitigation/mitigations/MitigateV1153.h"
#include "mitigation/mitigations/MitigateV3338.h"
#include "mitigation/mitigations/MitigateV63597.h"
#include "mitigation/mitigations/MitigateV63817.h"
#include "mitigation/mitigations/MitigateV63825.h"
#include "mitigation/mitigations/MitigateV63829.h"
#include "mitigation/mitigations/MitigateV72753.h"
#include "mitigation/mitigations/MitigateV73519.h"

void print_help(cxxopts::ParseResult result, cxxopts::Options options);
void dispatch_hunt(cxxopts::ParseResult result, cxxopts::Options options, IOBase& io);
void dispatch_mitigations_analysis(cxxopts::ParseResult result, cxxopts::Options options, IOBase& io);