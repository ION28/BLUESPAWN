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
#include <Shlwapi.h>
#include "common/wrappers.hpp"
#define BUFSIZE 1024
#define MD5LEN  16

using namespace std;
//namespace fs = std::experimental::filesystem::v1;
namespace FileSystem {
	bool CheckFileExists(std::wstring);
	
	struct FileAttribs {
		//long size;
		//long permissions;
		//bool hidden;
		wstring extension;
	};

	struct FileSearchAttribs {
		std::vector<wstring> extensions;
	};

	class File {
		//Whether or not this current file actually exists
		bool FileExists; 
		//Path to the file
		std::wstring FilePath;
		//Handle for the file
		HANDLE hFile;
		//Attributes of the file
		FileAttribs Attribs;
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
		* Function to get the file attributes
		*
		* @return the attributes struct
		*/
		FileAttribs GetFileAttribs();
		/**
		* Creates a file object with a given path
		* If the file already exists, opens a handle to it
		* 
		* @param path The path to the file to be opened
		*/
		File(IN const std::wstring path);

		/**
		* Return the path to the file
		*/
		std::wstring GetFilePath(){
			return FilePath;
		}

		/**
		* Function to check if a file exists
		*
		* return true if file exists, false otherwise
		*/
		bool GetFileExists() {
			return FileExists;
		}

		/**
		* Function to write to arbitrary offset in the file
		* 
		* @param value The value to be written
		* @param offset The offset to write to 
		* @param truncate If true truncate the file after the write
		* @param insert If true insert the value at the offset. If false, overwrite the bytes at that location in the file
		*
		* @return true if write successful, false if write unsuccessful
		*/
		bool Write(IN const LPVOID value, IN const long offset, IN const unsigned long length, IN const bool truncate = false, IN const bool insert = false);

		/**
		* Function to read from arbitrary offset in the file
		* 
		* @param buffer The buffer to read to
		* @param offset The offset to read from
		* @param amount	How many bytes to read. Amount should be less than or equal to the size of the buffer - 1
		* @param amountRead How many bytes were successfully read
		*
		* @return true if read successful, false if read unsuccessful
		*/
		bool Read(OUT LPVOID buffer, IN const long offset, IN const unsigned long amount, OUT DWORD& amountRead);

		/**
		* Function to compute the MD5 hash of the file
		* 
		* @param buffer The buffer to write the hash to
		*
		* @return true if hashing successful, false if hashing unsuccessful
		*/
		bool GetMD5Hash(OUT string& buffer);

		/**
		* Function to create the file if it doesn't exist
		* 
		* @return true if creation was successful, false if unsuccessful
		*/
		bool Create();

		/**
		* Function to delete the file
		*
		* @return true if deletion was successful, false if unsuccessful
		*/
		bool Delete();

		/**
		* Function to truncate or extend file length
		*
		* @param length - new length of the file in bytes
		*
		* @return true if trucation or extension was successful, false if unsuccessful
		*/
		bool ChangeFileLength(IN const long length);
	};

	class Folder {
		//Path to the current folder
		std::wstring FolderPath;
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
		Folder(std::wstring path);
		
		/**
		* Function to move to the next file
		*
		* @return true if successfully moved to next file false if no next file exists
		*/
		bool MoveToNextFile();
		/**
		* Function to move to the beginnning of the directory
		* 
		* @return true if successful, false otherwise
		*/
		bool MoveToBeginning();
		/**
		* Function to check if the folder exists
		* 
		* @return whether or not the folder exists.
		*/
		bool GetFolderExists() {
			return FolderExists;
		}
		/**
		* Function to check if current handle is directory or file
		*
		* @return true if current is a file, false otherwise. 
		*/
		bool GetCurIsFile() {
			return IsFile;
		}
		/**
		* Function to enter the current directory
		*
		* @return a folder object representing the currently pointed to directory if successful
		*/
		std::optional<Folder> EnterDir();
		/**
		* Function to open the current file for reading and writing
		*
		* @return The file if found, otherwise nothing
		*/
		std::optional<File> Open();
		/**
		* Function to add a file to the directory
		*
		* @return The file if successfully created
		*/
		std::optional<File> AddFile(IN std::wstring fileName);
		/**
		* Function to remove current file and move to next handle
		*
		* @return true if the file was removed, false otherwise
		* TODO: Add support for deleting folders
		*/
		bool RemoveFile();
		/**
		* Function to return all files matching some attributes 
		*
		* @param attribs - the attributes for returned files to match, NULL gets everything
		* @param recurse - whether or not to recursively search subdirectories
		* @param recurDepth - the depth to recursively search, -1 recurses infinitely 
		*
		* @return all files that match the given parameters
		*/
		std::vector<File> GetFiles(IN FileSearchAttribs* attribs = NULL, IN int recurDepth = 0);
	};
}