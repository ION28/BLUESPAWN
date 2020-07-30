#pragma once

#include <string>
#include <vector>
#include <optional>
#include <set>
#include <memory>

#include "util/log/Loggable.h"
#include "common/wrappers.hpp"
#include "util/permissions/permissions.h"
#include "common/DynamicLinker.h"
#include "util/linuxcompat.h"

#include <dirent.h>
#include <stdint.h>

#define BUFSIZE 1024
#define MD5LEN  16

#define SHA1LEN 20
#define SHA256LEN 32

enum class HashType {
	MD5_HASH,
	SHA1_HASH,
	SHA256_HASH
};

//TODO: Make sure all files are closed, or delete is called.
//NOTES: Linux filesystem api v1, in next iteration use fds when getting files from dirs
namespace FileSystem {
	//Just some forward declarations	
	class FileObject;
	class File;
	class Folder;


	/**
	* Function to check if a file path is valid
	*
	* @param path A string containing the path to check
	* 
	* @return true if the path points to a valid file, false otherwise
	*/
	bool CheckFileExists(const std::string& path);

	/**
	* Function to find a file named name.exe in a registry dependent search path
	*
	* @param name A string containing the name of the file for which to search
	* 
	* @return A string containing the full path to the file if found, or std::nullopt
	*	if the file wasn't found. 
	*/
	std::optional<std::string> SearchPathExecutable(const std::string& name);
	
	struct FileAttribs {
		std::string extension;
	};

	struct FileSearchAttribs {
		std::vector<std::string> extensions;
	};

		/**
	 * Represents a file or directory
	 */
	class FileObject{
	protected:
	    //The file descriptor of the directory or file
	    int hFile;

		//Does the file object exist as far as we know?
		bool bFileExists;

		//Path of file
		std::string FilePath;

		std::shared_ptr<void> handler;

		/**
		 * helper function to check for masks on a file
		 * @return true if the user would be able to access the file with one of the three masks provided
		 */ 
		bool HasPermHelper(const Permissions::Owner &user, unsigned int userMask, unsigned int groupMask, unsigned int otherMask);

	public:

		//NOTE: user refers to user or group
	    /**
		 * @return can the user execute file
		 */
	    bool CanExecute(const Permissions::Owner &user);

		/**
		 * @return can the file be read by user
		 */ 
		bool CanRead(const Permissions::Owner &user);

		/**
		 *@return can the file be written to by user
		 */ 
		bool CanWrite(const Permissions::Owner &user);

		/**
		 * @return can the file be written and read by the user
		 */
		bool CanReadWrite(const Permissions::Owner &user);

		/**
		 * @return can the file be deleted by user
		 */ 
		virtual bool CanDelete(const Permissions::Owner &user);

		/**
		 * @return the file path
		 */ 
		std::string GetFilePath() const;

		/**
		 *@return the file descriptor
		 */ 
		int GetFileDescriptor() const;

		/**
		 * @return bFileExists
		 */  
		bool GetFileExists() const;

		/**
		 * Set the owner of a file
		 * if the owner is a user, it will set the group owner as well.
		 * @return true if worked, false otherwise
		 */ 
		bool SetFileOwner(const Permissions::Owner& owner);

		/*
		 * Set the user and group owner to the bluespawn process
		 * @return true if successful, false otherwise
		 */ 
		bool TakeOwnership();

		/**
		 * Get the permissions for all users on the file 
		 * @return nullopt if unable to stat the file (execute permissions on parent dir) or the ACCESS_MASK (stat.st_mode)
		 */ 
		std::optional<ACCESS_MASK> GetPermissions() const;

		std::optional<Permissions::Owner> GetFileOwner(const Permissions::OwnerType type) const;

	    /**
		* Function to get the creation time of the file
		*
		* @return a FILETIME struct containing the creation time of the file. If an error,
		*     occurs the function returns std::nullopt and calls SetLastError with the error
		*/
		std::optional<struct statx_timestamp> GetCreationTime() const;

		/**
		* Function to get the last modified time of the file
		*
		* @return a FILETIME struct containing the last modified time of the file. If an error,
		*     occurs the function returns std::nullopt and calls SetLastError with the error
		*/
		std::optional<struct statx_timestamp> GetModifiedTime() const;

		/**
		* Function to get the last access time of the file
		*
		* @return a FILETIME struct containing the last access time of the file. If an error,
		*     occurs the function returns std::nullopt and calls SetLastError with the error
		*/
		std::optional<struct statx_timestamp> GetAccessTime() const;

		/**
		* Function to grant certain permissions to certain user or group
		*
		* @param owner The user or group to grant permissions to
		* @param amAccess The access to grant to owner
		*
		* @return true if the permissions were granted, false otherwise
		*/
		bool GrantPermissions(const ACCESS_MASK amAccess);

		/**
		* Function to deny certain permissions to certain user or group
		*
		* @param owner The user or group to deny permissions to
		* @param amAccess The access to deny the owner
		*
		* @return true if the permissions were denied, false otherwise
		*/
		bool DenyPermissions(const ACCESS_MASK amAccess);

		/**
		 * NOTE: the only time this will return nullopt is if the path is "/"
		 *@return the directory the file is in
		 */ 
		std::optional<Folder> GetDirectory() const;

	};

	class File : public Loggable, public FileObject{

		//Whether or not this current file actually exists on the filesystem
		bool bFileExists; 

		//Whether or not the program has write access to the file
		bool bWriteAccess;

		//Whether or not the program has read access to the file
		bool bReadAccess;

		//Attributes of the file
		FileAttribs Attribs;


		/**
		* Function to check if a file is signed in the system catalogs
		*
		* return true if the file is signed in the system catalogs, false if it isn't or on error
		*/
		bool GetFileInSystemCatalogs() const;

		/**
		* Function to assist in retrieving file hashes
		* 
		* @param HashType
		*
		* return std::string value of the requested hash type
		*/
		std::optional<std::string> CalculateHashType(HashType sHashType) const;

	public:
	//TODO: Support file attribute flags?

		/**
		* Creates a file object with a given path
		* If the file already exists, opens a handle to it
		* 
		* @param path The path to the file to be opened
		*/
		File(const std::string& path);

		/**
		 * Creates a file object using a dir file descriptor and a path for after dir
		 * If the file exists, a handle is opened
		 * 
		 * Just prototyped this out for now, planning on adding it to some of the Folder funcs
		 * NOTE: seems like fcntl doesnt have F_GETNAME, need to search for workaround before implementing
		 */
		File(const int dirfd, const std::string path);

		/*Getter for the Attribs field*/
		FileAttribs GetFileAttribs() const;

		/**
		* Function to check if program has write access to the file
		*
		* return true if program has write access, false otherwise
		*/
		bool HasWriteAccess() const;

		/**
		* Function to check if program has read access to the file
		*
		* return true if program has read access, false otherwise
		*/
		bool HasReadAccess() const;


        /**
		 *Sets the position of the file to pos if it exists 
		 * return true if worked, false otherwise
		 */
		bool SetFilePointer(unsigned int pos) const;

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
		bool Write(const void* value, const long offset, const unsigned long length, const bool truncate = false, 
			const bool insert = false) const;

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
		bool Read(void* buffer, const unsigned long amount = -1, const long offset = 0, unsigned int * amountRead = nullptr) const;

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
		AllocationWrapper Read(unsigned long amount = -1, long offset = 0, unsigned int * amountRead = nullptr) const;

		/**
		* Function to compute the MD5 hash of the file
		*
		* @return The MD5 hash of the object or an empty string if unable to calculate hash
		*/
		std::optional<std::string> GetMD5Hash() const;

		/**
		* Function to compute the SHA1 hash of the file
		*
		* @return The SHA1 hash of the object or an empty string if unable to calculate hash
		*/
		std::optional<std::string> GetSHA1Hash() const;

		/**
		* Function to compute the SHA256 hash of the file
		*
		* @return The SHA256 hash of the object or an empty string if unable to calculate hash
		*/
		std::optional<std::string> GetSHA256Hash() const;

		/**
		* Function to see if a file matches a given set of search criteria
		*
		* @param searchAttribs - a FileSearchAttribs object
		*
		* @return a boolean indicating if the file matched the criteria
		*/
		bool MatchesAttributes(const FileSearchAttribs& searchAttribs) const;

		/**
		 * Returns whether or not the current file is signed.
		 *
		 * @return true if the file is properly signed; false if not signed or an error occured.
		 */
		bool GetFileSigned() const;

		/**
		 * Indicates whether the file was signed by Microsoft.
		 *
		 * @return true if the file is properly signed by microsoft; false otherwise
		 */
		bool IsMicrosoftSigned() const;

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
		bool ChangeFileLength(const long length) const;

		/**
		 * Gets the number of bytes in the referenced file
		 *
		 * @return The size of the referenced file
		 */
		uint64_t GetFileSize() const;
		
		/**
		 * Gets the file path (and thus its name)
		 *
		 * @return The file path of the object
		 */
		virtual std::string ToString() const;

		/**
		* Function to quarantine file
		*
		* @return true if the file is quarantined, false otherwise
		*/
		bool Quarantine();
	};

	class Folder : public FileObject{

		//Handle to the directory itself
		DIR * hDirectory;

		//Handle to the current file or directory
		struct dirent * hCurFile;

		//Is the current handle a file or directory
		bool bIsFile;

	public:

		/**
		* Constructor for the folder object
		* 
		* @param path - the path to the folder
		*/
		Folder(const std::string& path);
		
		/**
		* Function to move to the next file
		* @deprecated: should not be used on linux.  Just returns false. WILL be removed.
		* @return false
		*/
		bool MoveToNextFile();

		/**
		* Function to move to the beginnning of the directory
		* 
		* @return true if successful, false otherwise
		*/

		bool MoveToBeginning();

		/**
		* Function to check if current handle is directory or file
		*
		* @return true if current is a file, false otherwise. 
		*/
		bool GetCurIsFile() const;

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

		std::optional<File> AddFile(const std::string& fileName) const;

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
		std::vector<File> GetFiles(std::optional<FileSearchAttribs> attribs = std::nullopt, int recurDepth = 0);

		/**
		* Function to return all subdirectories in the current folder
		*
		* @param recurDepth - the depth to recursively search, -1 recurses infinitely
		*
		* @return all subfolders in the current folder
		*/
		std::vector<Folder> GetSubdirectories(int recurDepth = 0);

		/**
		 *@return true if the contents of the file can be deleted by owner
		 */ 
		bool CanDeleteContents(const Permissions::Owner &owner);
	};
}