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
#include <vector>
#define LOG_VERBOSE(x, __VAR_ARGS)
#define LOG_ERROR(__VAR_ARGS)
#define BUFSIZE 1024
#define MD5LEN  16

using namespace std;
//namespace fs = std::experimental::filesystem::v1;
namespace FileSystem {
	bool CheckFileExists(LPCWSTR);
	
	struct FileAttribs {
		long size;
		long permissions;
		bool hidden;
	};

	class File {
		//Whether or not this current file actually exists
		bool FileExists; 
		//Path to the file
		LPCWSTR FilePath;
		//Handle for the file
		HANDLE hFile;
		/**
		* Function to get offsets in format needed by SetFilePointer
		*
		* @param val - value to be translated. Upper bit will be ignored
		* @param lowerVal - variable to store lower value
		* @param upperVal - variable to store upper value
		* @param upper - variable to store pointer to upper value
		*/
		static void TranslateLongToFilePointer(long val, LONG& lowerVal, LONG& upperVal, PLONG& upper);
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
		short Write(IN const LPVOID value, IN const long offset, IN const unsigned long length, IN const bool truncate = false, IN const bool insert = false);

		/**
		* Function to read from arbitrary offset in the file
		* 
		* @param buffer The buffer to read to
		* @param offset The offset to read from
		* @param amount	How many bytes to read. Ammount should be less than the size of the buffer - 1
		*
		* @return 1 if write successful, 0 if write unsuccessful
		*/
		short Read(OUT LPVOID buffer, IN const long offset, IN const unsigned long amount, OUT DWORD& amountRead);

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
		short Create();

		/**
		* Function to delete the file
		*
		* @return 1 if deletion was successful, 0 if unsuccessful
		*/
		short Delete();

		/**
		* Function to truncate or extend file length
		*
		* @param length - new length of the file in bytes
		*
		* @return 1 if trucation or extension was successful, 0 if unsuccessful
		*/
		short ChangeFileLength(IN const long length);
	};

	class Folder {
		//Path to the current folder
		LPCWSTR FolderPath;
		//Whether or not the current folder exists
		bool FolderExists;
		//Handle to current file or directory
		HANDLE hCurFile;
		//Is the current handle a file or directory
		bool IsFile;
		//Information about found files
		WIN32_FIND_DATA ffd;
	public:
		/**
		* Constructor for the folder object
		* 
		* @param path - the path to the folder
		*/
		Folder(LPCWSTR path);
		
		/**
		* Function to move to the next file
		*
		* @return 1 if successfully moved to next file 0 if no next file exists
		*/
		short moveToNextFile();
		/**
		* Function to move to the previous file
		*
		* @return 1 if successfully moved to next file 0 if no previous file exists
		*/
		short moveToPrevFile();
		/**
		* Function to move to the beginnning of the directory
		* 
		* @return 1 if successful, 0 otherwise
		*/
		short moveToBeginning();
		/**
		* Function to check if the folder exists
		* 
		* @return whether or not the folder exists.
		*/
		bool getFolderExists();
		/**
		* Function to check if current handle is directory or file
		*
		* @return true if current is a file, false otherwise. 
		*/bool getCurIsFile();
		/**
		* Function to enter the current directory
		*
		* @return 1 if the directory was successfully entered, 0 otherwise
		*/
		short EnterDir(OUT Folder*& folder);
		/**
		* Function to open the current file for reading and writing
		*
		* @param file - a pointer where the function will store the opened file
		* 
		* @return 1 if the function was successful, 0 otherwise
		*/
		short Open(OUT File*& file);
		/**
		* Function to add a file to the directory
		* 
		* @param fileName - the name of the file
		* @param file - a pointer to store the created file
		*
		* @return 1 if the function is successful, 0 otherwise
		*/
		short AddFile(IN LPCWSTR fileName, OUT File*& file);
		/**
		* Function to remove current file and move to next handle
		*
		* @return 1 if the file was removed, 0 otherwise
		*/
		short RemoveFile();
		/**
		* Function to return all files matching some attributes 
		*
		* @param attribs - the attributes for returned files to match, NULL gets everything
		* @param recurse - whether or not to recursively search subdirectories
		* @param recurDepth - the depth to recursively search, -1 recurses infinitely 
		*
		* @return all files that match the given parameters
		*/
		std::vector<File*>* GetFiles(IN FileAttribs* attribs = NULL, IN int recurDepth = 0);
	};
}