#pragma once

#include <Windows.h>

#include <optional>
#include <set>
#include <string>
#include <vector>

#include "util/DynamicLinker.h"
#include "util/log/Loggable.h"
#include "util/permissions/permissions.h"
#include "util/wrappers.hpp"

#define BUFSIZE 1024
#define MD5LEN 16

DEFINE_FUNCTION(NTSTATUS,
                NtCreateFile,
                __kernel_entry NTAPI,
                PHANDLE FileHandle,
                ACCESS_MASK DesiredAccess,
                POBJECT_ATTRIBUTES ObjectAttributes,
                PIO_STATUS_BLOCK IoStatusBlock,
                PLARGE_INTEGER AllocationSize,
                ULONG FileAttributes,
                ULONG ShareAccess,
                ULONG CreateDisposition,
                ULONG CreateOptions,
                PVOID EaBuffer,
                ULONG EaLength);

#define SHA1LEN 20
#define SHA256LEN 32

enum class HashType { MD5_HASH, SHA1_HASH, SHA256_HASH };

namespace FileSystem {
    /**
	* Function to check if a file path is valid
	*
	* @param path A wstring containing the path to check
	* 
	* @return true if the path points to a valid file, false otherwise
	*/
    bool CheckFileExists(const std::wstring& path);

    /**
	* Function to find a file named name.exe in a registry dependent search path
	*
	* @param name A wstring containing the name of the file for which to search
	* 
	* @return A wstring containing the full path to the file if found, or std::nullopt
	*	if the file wasn't found. 
	*/
    std::optional<std::wstring> SearchPathExecutable(const std::wstring& name);

    struct FileAttribs {
        std::wstring extension;
    };

    struct FileSearchAttribs {
        std::vector<std::wstring> extensions;
    };

    class File : public Loggable {
        //Whether or not this current file actually exists on the filesystem
        bool bFileExists;

        //Whether or not the program has write access to the file
        bool bWriteAccess;

        //Whether or not the program has read access to the file
        bool bReadAccess;

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
		* return std::wstring value of the requested hash type
		*/
        std::optional<std::wstring> CalculateHashType(HashType sHashType) const;

        public:
        /**
		* Creates a file object with a given path
		* If the file already exists, opens a handle to it
		*
		* @param path The path to the file to be opened
		*/
        File(IN const std::wstring& path);

        /*Getter for the FilePath field*/
        std::wstring GetFilePath() const;

        /*Getter for the Attribs field*/
        FileAttribs GetFileAttribs() const;

        /*Getter for the bFileExists field*/
        bool GetFileExists() const;

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
		* Function to write to arbitrary offset in the file
		*
		* @param value The value to be written
		* @param offset The offset to write to
		* @param truncate If true truncate the file after the write
		* @param insert If true insert the value at the offset. If false, overwrite the bytes at that location in the file
		*
		* @return true if write successful, false if write unsuccessful
		*/
    bool Write(IN const LPCVOID value, IN const long offset, IN const unsigned long length, __in_opt const bool truncate = false,
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
        bool Read(OUT LPVOID buffer,
                  __in_opt const unsigned long amount,
                  __in_opt const long offset = 0,
                  __out_opt PDWORD amountRead = nullptr) const;

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
        AllocationWrapper
        Read(__in_opt unsigned long amount = -1, __in_opt long offset = 0, __out_opt PDWORD amountRead = nullptr) const;

        /**
		* Function to compute the MD5 hash of the file
		*
		* @return The MD5 hash of the object or an empty string if unable to calculate hash
		*/
        std::optional<std::wstring> GetMD5Hash() const;

        /**
		* Function to compute the SHA1 hash of the file
		*
		* @return The SHA1 hash of the object or an empty string if unable to calculate hash
		*/
        std::optional<std::wstring> GetSHA1Hash() const;

        /**
		* Function to compute the SHA256 hash of the file
		*
		* @return The SHA256 hash of the object or an empty string if unable to calculate hash
		*/
        std::optional<std::wstring> GetSHA256Hash() const;

        /**
		* Function to see if a file matches a given set of search criteria
		*
		* @param searchAttribs - a FileSearchAttribs object
		*
		* @return a boolean indicating if the file matched the criteria
		*/
        bool MatchesAttributes(IN const FileSearchAttribs& searchAttribs) const;

        /**
		 * Finds the issuer of the certificate, if present
		 * 
		 * @return the issuer of the certificate, if present
		 */
        std::optional<std::wstring> File::GetCertificateIssuer() const;

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

        /**
		* Function to get the file owner
		*
		* @return an Owner object representing the owner of the file
		*/
        std::optional<Permissions::Owner> GetFileOwner() const;

        /**
		* Function to set a file owner
		*
		* @param owner An Owner object representing the new file owner
		* @return true if the file is now owned by the new user, false otherwise
		*/
        bool SetFileOwner(const Permissions::Owner& owner);

        /**
		* Function to get the permissions a user or group has on a file
		*
		* @param owner An Owner object to check permissions for
		* @return An ACCESS_MASK object 
		*/
        ACCESS_MASK GetAccessPermissions(const Permissions::Owner& owner);

        /**
		* Function to get permissions that the everyone group has
		*
		* @return the permissions granted to the everyone group
		*/
        ACCESS_MASK GetEveryonePermissions();

        /**
		* Function to set bluespawn's process owner as the owner of the file
		*
		* @return true if successful, false otherwise
		*/
        bool TakeOwnership();

        /**
		* Function to grant certain permissions to certain user or group
		*
		* @param owner The user or group to grant permissions to
		* @param amAccess The access to grant to owner
		*
		* @return true if the permissions were granted, false otherwise
		*/
        bool GrantPermissions(const Permissions::Owner& owner, const ACCESS_MASK& amAccess);

        /**
		* Function to deny certain permissions to certain user or group
		*
		* @param owner The user or group to deny permissions to
		* @param amAccess The access to deny the owner
		*
		* @return true if the permissions were denied, false otherwise
		*/
        bool DenyPermissions(const Permissions::Owner& owner, const ACCESS_MASK& amAccess);

        /**
		* Function to quarantine file
		*
		* @return true if the file is quarantined, false otherwise
		*/
        bool Quarantine();

        /**
		* Function to get the creation time of the file
		*
		* @return a FILETIME struct containing the creation time of the file. If an error,
		*     occurs the function returns std::nullopt and calls SetLastError with the error
		*/
        std::optional<FILETIME> GetCreationTime() const;

        /**
		* Function to get the last modified time of the file
		*
		* @return a FILETIME struct containing the last modified time of the file. If an error,
		*     occurs the function returns std::nullopt and calls SetLastError with the error
		*/
        std::optional<FILETIME> GetModifiedTime() const;

        /**
		* Function to get the last access time of the file
		*
		* @return a FILETIME struct containing the last access time of the file. If an error,
		*     occurs the function returns std::nullopt and calls SetLastError with the error
		*/
        std::optional<FILETIME> GetAccessTime() const;
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

        //Whether or not BLUESPAWN has write access to the folder
        bool bFolderWrite;

        //Information about found files
        WIN32_FIND_DATA ffd;

        public:
        /**
		* Constructor for the folder object
		*
		* @param path - the path to the folder
		*/
        Folder(const std::wstring& path);

        /*Getter for FolderPath field*/
        std::wstring GetFolderPath() const;

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

        /*Getter for the bFolderExists field*/
        bool GetFolderExists() const;

        /**
		* Function to check if current handle is directory or file
		*
		* @return true if current is a file, false otherwise.
		*/
        bool GetCurIsFile() const;

        /**
		* Function to check if BLUESPAWN has write access to the current folder
		* 
		* @return true if bFolderWrite is true, false otherwise
        */
        bool GetFolderWrite() const;

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
        std::vector<File> GetFiles(__in_opt std::optional<FileSearchAttribs> attribs = std::nullopt,
                                   __in_opt int recurDepth = 0);

        /**
		* Function to return all subdirectories in the current folder
		*
		* @param recurDepth - the depth to recursively search, -1 recurses infinitely
		*
		* @return all subfolders in the current folder
		*/
        std::vector<Folder> GetSubdirectories(__in_opt int recurDepth = 0);

        /**
		* Function to get the folder owner
		*
		* @return an Owner object representing the owner of the file
		*/
        std::optional<Permissions::Owner> GetFolderOwner() const;

        /**
		* Function to set a folder owner
		*
		* @param owner An Owner object representing the new folder owner
		* @return true if the folder is now owned by the new user, false otherwise
		*/
        bool SetFolderOwner(const Permissions::Owner& owner);

        /**
		* Function to get the permissions a user or group has on a folder
		*
		* @param owner An Owner object to check permissions for
		* @return An ACCESS_MASK object
		*/
        ACCESS_MASK GetAccessPermissions(const Permissions::Owner& owner);

        /**
		* Function to get permissions that the everyone group has
		*
		* @return the permissions granted to the everyone group
		*/
        ACCESS_MASK GetEveryonePermissions();

        /**
		* Function to set bluespawn's process owner as the owner of the folder
		*
		* @return true if successful, false otherwise
		*/
        bool TakeOwnership();
    };
}   // namespace FileSystem
