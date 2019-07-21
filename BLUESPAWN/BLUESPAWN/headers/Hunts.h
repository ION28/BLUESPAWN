#pragma once

#include "Output.h"
#include "Registry.h"
#include "FileSystem.h"

void GoHuntingATTACK();
void GoHuntingWeakSecuritySettings();

void HuntWSSRegistryKeys();

void HuntT1004WinlogonHelperDll();
void HuntT1037LogonScripts();
void HuntT1060RegistryRunKeysStartUpFolder();
void HuntT1101SecuritySupportProvider();
void HuntT1103AppInitDlls();
void HuntT1131AuthenticationPackage();
void HuntT1138ApplicationShimming();
void HuntT1182AppCertDlls();

