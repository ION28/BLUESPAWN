#pragma once

#include <stdio.h>
#include <ntstatus.h>
#include <windows.h>
#include <Wincrypt.h>
#include <tchar.h>
#include <string>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <fileapi.h>

#define BUFSIZE 1024
#define MD5LEN  16

using namespace std;
//namespace fs = std::experimental::filesystem::v1;
namespace FileSystem {
	bool CheckFileExists(LPCWSTR);
	//string GetFileContents(LPCWSTR);
	//bool HashFileMD5(LPCWSTR, string&);
	class File {
		//Whether or not this current file actually exists
		bool FileExists; 
		//Path to the file
		wstring FilePath;
		//Handle for the file
		HANDLE hFile;
	public:
		/**
		* Creates a file object with a given path
		* If the file already exists, opens a handle to it
		* 
		* @param path The path to the file to be opened
		*/
		File(IN const LPCWSTR path);

		/**
		* Function to check if a file exists
		*
		* return true if file exists, false otherwise
		*/
		bool getFileExists() {
			return FileExists;
		}

		/**
		* Function to write to arbitrary offset in the file
		* 
		* @param value The value to be written
		* @param offset The offset to write to 
		* @param insert If true insert the value at the offset. If false, overwrite the bytes at that location in the file
		*
		* @return 1 if write successful, 0 if write unsuccessful
		*/
		short Write(IN const LPVOID value, IN const long offset, IN const bool insert = false);

		/**
		* Function to read from arbitrary offset in the file
		* 
		* @param buffer The buffer to read to
		* @param offset The offset to read from
		* @param amount	How many bytes to read. Ammount should be less than the size of the buffer - 1
		*
		* @return 1 if write successful, 0 if write unsuccessful
		*/
		short Read(OUT LPVOID buffer, IN const long offset, IN const long amount);

		/**
		* Function to compute the MD5 hash of the file
		* 
		* @param buffer The buffer to write the hash to
		*
		* @return 1 if hashing successful, 0 if hashing unsuccessful
		*/
		bool GetMD5Hash(OUT string& buffer);

		/**
		* Function to create the file if it doesn't exist
		* 
		* @return 1 if creation was successful, 0 if unsuccessful
		*/
		short MakeFile();

		/**
		* Functio to delete the file
		*
		* @return 1 if deletion was successful, 0 if unsuccessful
		*/
		short RemoveFile();
	};

	class Folder : File {

	};
}