#pragma once

#include <Windows.h>

#include <string>
#include <vector>
#include <optional>

#include "util/log/Loggable.h"
#include "common/wrappers.hpp"

#define BUFSIZE 1024
#define MD5LEN  16

namespace FileSystem {
	bool CheckFileExists(std::wstring);
	
	struct FileAttribs {
		std::wstring extension;
	};

	struct FileSearchAttribs {
		std::vector<std::wstring> extensions;
	};

	class File : public Loggable {

		//Whether or not this current file actually exists on the filesystem
		bool bFileExists; 

		//Path to the file
		std::wstring FilePath;

		//Handle for the file
		HandleWrapper hFile;

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
		DWORD SetFilePointer(DWORD64 dwFilePointer) const;
	public:

		/**
		* Creates a file object with a given path
		* If the file already exists, opens a handle to it
		* 
		* @param path The path to the file to be opened
		*/
		File(IN const std::wstring& path);

		/**
		* Return the path to the file
		*/
		std::wstring GetFilePath() const {
			return FilePath;
		}

		/**
		* Function to get the file attributes
		*
		* @return the attributes struct for the file
		*/
		FileAttribs GetFileAttribs() const {
			return Attribs;
		}

		/**
		* Function to get whether the file exists
		*
		* return true if file exists, false otherwise
		*/
		bool GetFileExists() const {
			return bFileExists;
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
		bool Write(IN const LPVOID value, IN const long offset, IN const unsigned long length, __in_opt const bool truncate = false, 
			__in_opt const bool insert = false) const;

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
		bool Read(OUT LPVOID buffer, __in_opt const unsigned long amount, __in_opt const long offset = 0, __out_opt PDWORD amountRead = nullptr) const;

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
		AllocationWrapper Read(__in_opt unsigned long amount = -1, __in_opt long offset = 0, __out_opt PDWORD amountRead = nullptr) const;

		/**
		* Function to compute the MD5 hash of the file
		* 
		* @param buffer The buffer to write the hash to
		*
		* @return true if hashing successful, false if hashing unsuccessful
		*/
		std::optional<std::string> GetMD5Hash() const;

		/**
		* Function to see if a file matches a given set of search criteria
		*
		* @param searchAttribs - a FileSearchAttribs object
		*
		* @return a boolean indicating if the file matched the criteria
		*/
		bool MatchesAttributes(IN const FileSearchAttribs& searchAttribs) const;

		/**
		 * Returns whether or not the current file is signed.
		 *
		 * @return true if the file is properly signed; false if not signed or an error occured.
		 */
		bool GetFileSigned() const;

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
		bool ChangeFileLength(IN const long length) const;

		/**
		 * Gets the number of bytes in the referenced file
		 *
		 * @return The size of the referenced file
		 */
		DWORD64 GetFileSize() const;

		/**
		 * Gets the file path (and thus its name)
		 *
		 * @return The file path of the object
		 */
		virtual std::wstring ToString() const;
	};

	class Folder {

		//Path to the current folder
		std::wstring FolderPath;

		//Whether or not the current folder exists
		bool bFolderExists;

		//Handle to current file or directory
		FindWrapper hCurFile;

		//Is the current handle a file or directory
		bool bIsFile;

		//Information about found files
		WIN32_FIND_DATA ffd;
	public:

		/**
		* Constructor for the folder object
		* 
		* @param path - the path to the folder
		*/
		Folder(const std::wstring& path);

		/**
		* Return the path to the file
		*/
		std::wstring GetFolderPath() const {
			return FolderPath;
		}
		
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
		bool GetFolderExists() const {
			return bFolderExists;
		}

		/**
		* Function to check if current handle is directory or file
		*
		* @return true if current is a file, false otherwise. 
		*/
		bool GetCurIsFile() const {
			return bIsFile;
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
		std::optional<File> Open() const;

		/**
		* Function to add a file to the directory
		*
		* @return The file if successfully created
		*/

		std::optional<File> AddFile(IN const std::wstring& fileName) const;

		/**
		* Function to remove current file and move to next handle
		*
		* @return true if the file was removed, false otherwise
		* TODO: Add support for deleting folders
		*/
		bool RemoveFile() const;

		/**
		* Function to return all files matching some attributes
		*
		* @param attribs - the attributes for returned files to match, std::nullopt gets everything
		* @param recurDepth - the depth to recursively search, -1 recurses infinitely
		*
		* @return all files that match the given parameters
		*/
		std::vector<File> GetFiles(__in_opt std::optional<FileSearchAttribs> attribs = std::nullopt, __in_opt int recurDepth = 0);

		/**
		* Function to return all subdirectories in the current folder
		*
		* @param recurDepth - the depth to recursively search, -1 recurses infinitely
		*
		* @return all subfolders in the current folder
		*/
		std::vector<Folder> GetSubdirectories(__in_opt int recurDepth = 0);
	};
}