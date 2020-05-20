#pragma once

#include <string>

#include "util/filesystem/FileSystem.h"

/**
 * Checks whether the file given is a well known living off the land binary.
 * This is done by comparing the hash of this file against that of known lolbins such
 * as cmd.exe, powershell.exe, netsh.exe, net.exe, net1.exe, explorer.exe, rundll32.exe,
 * wscript.exe, wmic.exe, regsvr32.exe, and cscript.exe
 *
 * @param file The file to check
 *
 * @return true if this file is a lolbin; false otherwise
 */
bool IsLolbin(const FileSystem::File& file);

/**
 * Checks whether a command will run a "living off the land" binary in a potentially malicious
 * manner. See IsLolbin for more information.
 *
 * @param command The command to check
 *
 * @return True if command may execute malicious code through a lolbin; false if otherwise.
 */
bool IsLolbinMalicious(const std::wstring& command);