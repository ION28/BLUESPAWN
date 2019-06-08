#pragma once

#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>
#include <tchar.h>
#include <string>
#include <iostream>


#define BUFSIZE 1024
#define MD5LEN  16

using namespace std;

void TestCheckFiles();
bool CheckFileExists(LPCWSTR);
bool HashFileMD5(LPCWSTR, string&);