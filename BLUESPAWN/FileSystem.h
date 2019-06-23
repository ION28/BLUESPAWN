#pragma once

#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>
#include <tchar.h>
#include <string>
#include <iostream>
#include <fstream>
#include <experimental/filesystem>
#include <filesystem>
#include <regex> 

#define BUFSIZE 1024
#define MD5LEN  16

using namespace std;
namespace fs = std::experimental::filesystem::v1;

void SearchForWebShell();
void TestCheckFiles();
bool CheckFileExists(LPCWSTR);
string GetFileContents(LPCWSTR);
bool HashFileMD5(LPCWSTR, string&);