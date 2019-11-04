#pragma once

#define _SILENCE_EXPERIMENTAL_FILESYSTEM_DEPRECATION_WARNING

#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>
#include <tchar.h>
#include <string>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <algorithm>

#define BUFSIZE 1024
#define MD5LEN  16

using namespace std;
namespace fs = std::experimental::filesystem::v1;

bool CheckFileExists(LPCWSTR);
string GetFileContents(LPCWSTR);
bool HashFileMD5(LPCWSTR, string&);