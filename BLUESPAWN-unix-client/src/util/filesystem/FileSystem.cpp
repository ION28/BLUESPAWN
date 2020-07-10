#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"
#include "common/StringUtils.h"
#include "util/linuxcompat.h"

//NOTE: added when porting
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <sys/types.h>
#include <fcntl.h>
#include <algorithm>
#include <grp.h>
#include <pwd.h>
//NOTE: end

#include <string>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <vector>
#include <optional>
#include "common/wrappers.hpp"
#include "common/StringUtils.h"

namespace FileSystem{
	bool CheckFileExists(const std::string& path) {
		auto exists = access(path.c_str(), F_OK);
		if(exists < 0){
			LOG_VERBOSE(3, "File " << path << " does not exist.");
			return false;
		}

		struct stat statbuf;

		if(stat(path.c_str(), &statbuf) < 0){
			LOG_ERROR("Unable to stat " << path << "."); //TODO: Check if this is correct syntax
		}

		if(S_ISDIR(statbuf.st_mode)){
			LOG_VERBOSE(3, "File " << path << " is a directory.");
			return false;
		}
		LOG_VERBOSE(3, "File " << path << " exists");
		return true;
	}

	//Will this function be fed full paths? - TDOO
	std::optional<std::string> SearchPathExecutable(const std::string& name){
		char * path = getenv("PATH");
		if(!path){
			LOG_ERROR("PATH envvar does not exist.");
			return std::nullopt;
		}else{
			char * token = strtok(path, ":");
			struct stat statbuf;
			do{
				if(access(token, F_OK) == 0 && stat(token, &statbuf) == 0){
					if(S_ISDIR(statbuf.st_mode)){
						DIR * dir = opendir(token);
						//no way this doesnt open but check anyway
						if(dir){
							struct dirent * entry = readdir(dir);
							while(entry != NULL){
								if(strcmp(entry->d_name, name.c_str()) == 0){
									//now check if its executable
									//assuming this is run as root, anything should be executable as long as the exe bit is set
									char buffer[PATH_MAX + 1];
									snprintf(path, PATH_MAX + 1, "%s/%s", token, entry->d_name);
									if(access(path, X_OK) == 0){
										return std::string(buffer);
									}

								}
							}
						}
					}
				}
			} while ((token = strtok(NULL, ":")) != NULL);
			
		}
		
		return std::nullopt;
	}

	void File::Close()
	{
		close(hFile);
	}

	std::optional<std::string> File::CalculateHashType(HashType sHashType) const {
		if (!bFileExists) {
			LOG_ERROR("Can't get hash of " << FilePath << ". File doesn't exist");
			//SetLastError(ERROR_FILE_NOT_FOUND);
			errno = ENOENT;
			return std::nullopt;
		}
		if (!bReadAccess) {
			LOG_ERROR("Can't get hash of " << FilePath << ". Insufficient permissions.");
			//SetLastError(ERROR_ACCESS_DENIED);
			errno = EPERM;
			return std::nullopt;
		}

		//first read in the buffer
		auto size = lseek(hFile, 0L, SEEK_END);
		if(size < 0){
			LOG_ERROR("Error getting file size of " << FilePath << ".");
		}

		lseek(hFile, 0L, SEEK_SET);
		//now that we have the size, read in the file
		char * fbuffer = (char*) malloc(sizeof(char) * size);
		if(!fbuffer){
			LOG_ERROR("Error allocating memory for file");
			return std::nullopt;
		}

		if(!Read(fbuffer)){
			LOG_ERROR("Error reading file");
			free(fbuffer);
			return std::nullopt;
		}
		
		unsigned char hashbuf[sHashType == HashType::MD5_HASH ? MD5_DIGEST_LENGTH + 1 : sHashType == HashType::SHA1_HASH ? SHA1LEN + 1 : SHA256LEN + 1];
		memset(hashbuf, 0x0, sizeof(hashbuf));
		if(sHashType == HashType::MD5_HASH){
			MD5_CTX ctx;
			if(MD5_Init(&ctx) != 1){
				LOG_ERROR("Error initiating md5 ctx");
				free(fbuffer);
				return std::nullopt;
			}

			if(MD5_Update(&ctx, fbuffer, size) != 1){
				LOG_ERROR("Error creating md5 hash");
				free(fbuffer);
				return std::nullopt;
			}

			if(MD5_Final(hashbuf, &ctx) != 1){
				LOG_ERROR("Error creating md5 hash");
				free(fbuffer);
				return std::nullopt;
			}
		}
		else if(sHashType == HashType::SHA1_HASH){
			SHA_CTX ctx;
			if(SHA1_Init(&ctx) != 1){
				LOG_ERROR("Error initiating sha1 ctx");
				free(fbuffer);
				return std::nullopt;
			}

			if(SHA1_Update(&ctx, fbuffer, size) != 1){
				LOG_ERROR("Error creating sha1 hash");
				free(fbuffer);
				return std::nullopt;
			}

			if(SHA1_Final(hashbuf, &ctx) != 1){
				LOG_ERROR("Error creating sha1 hash");
				free(fbuffer);
				return std::nullopt;
			}
		}
		else if(sHashType == HashType::SHA256_HASH){
			SHA256_CTX ctx;
			if(SHA256_Init(&ctx) != 1){
				LOG_ERROR("Error initiating sha256 ctx");
				free(fbuffer);
				return std::nullopt;
			}

			if(SHA256_Update(&ctx, fbuffer, size) != 1){
				LOG_ERROR("Error creating sha256 hash");
				free(fbuffer);
				return std::nullopt;
			}

			if(SHA256_Final(hashbuf, &ctx) != 1){
				LOG_ERROR("Error creating sha256 hash");
				free(fbuffer);
				return std::nullopt;
			}
		}

		free(fbuffer);
		return std::string((char*)hashbuf);
	}

    //TODO: make this api work better with really large files?
	File::File(const std::string& path) : bWriteAccess{false}, bReadAccess{false}{
		if(!path.length()){
			return;
		}
		FilePath = path;
		//first check if this is a directory - for the linux api going to make files and directories seperate

		struct stat statbuf;

		if(stat(path.c_str(), &statbuf) < 0){
			LOG_ERROR("Unable to stat file " << FilePath << ".");
			return;
		}

		if(S_ISDIR(statbuf.st_mode)){
			LOG_ERROR("Attempting to open dir " << FilePath << " as a file.");
			return;
		}

		LOG_VERBOSE(2, "Attempting to open file: " << FilePath << ".");

		hFile = open(path.c_str(), O_RDWR );

		if(hFile < 0){
			if(errno == ENOENT){
				LOG_ERROR("File " << FilePath << "does not exist!");
			}else if(errno == EPERM){
				bFileExists = true;
				if(access(FilePath.c_str(), W_OK) == 0){
					bWriteAccess = true;
					hFile = open(FilePath.c_str(), O_WRONLY | O_APPEND);
				}else if(access(FilePath.c_str(), R_OK) == 0){
					bReadAccess = true;
					hFile = open(FilePath.c_str(), O_RDONLY);
				}

			}
			//TODO: any other errors to account for?
		}else{
			bFileExists = true;
			bWriteAccess = true;
			bReadAccess = true;
		}

	}

	FileAttribs File::GetFileAttribs() const{
			return Attribs;
	}

	bool File::HasWriteAccess() const {
		return bWriteAccess;
	}

	bool File::HasReadAccess() const {
			return bReadAccess;
	}

	bool File::SetFilePointer(unsigned int pos) const{
		if(!bFileExists){
			LOG_ERROR("Cant set position of a nonexistant file");
			return false;
		}

		return lseek(hFile, pos, SEEK_SET);
	}

	bool File::Write(const void* value, const long offset, const unsigned long length, const bool truncate, const bool insert) const {
		SCOPE_LOCK(this->SetFilePointer(0), ResetFilePointer); //TODO: not sure how to fix this yet - SetFilePointer(0) should be lseek(hFile, 0L, SEEK_SET)
		LOG_VERBOSE(2, "Writing to file " << FilePath << " at " << offset << ". Insert = " << insert);

		unsigned int dwBytesIO{};

		if(!bFileExists) {
			LOG_ERROR("Can't write to file " << FilePath << ". File doesn't exist");
			//SetLastError(ERROR_FILE_NOT_FOUND);
			errno = ENOENT;
			return false;
		}

		if (!bWriteAccess) {
			LOG_ERROR("Can't write to file " << FilePath << ". Insufficient permissions.");
			//SetLastError(ERROR_ACCESS_DENIED);

			errno = EPERM;
			return false;
		}

		off_t oldsz = lseek(hFile, 0L, SEEK_END);
		lseek(hFile, 0L, SEEK_SET);

		if(truncate){
			if(!bReadAccess){
				LOG_ERROR("Truncating requires read access for file " << FilePath << ".");
				return false;
			}

			if(ftruncate(hFile, length + oldsz) < 0){
				LOG_ERROR("Error truncating file " << FilePath << ".");
			}

			//if its truncate, dont write over the file - move the contents first
			//buffer for old stuff
			char * buffer = (char*) malloc(sizeof(char) * (oldsz - offset)); //TODO: use AllocationWrapper
			lseek(hFile, offset, SEEK_SET);
			if(read(hFile, buffer,  oldsz - offset) < 0){
				LOG_ERROR("Error reading file for truncating");
				free(buffer);
				return false;
			}


			lseek(hFile, offset + length, SEEK_SET);
			if(write(hFile, buffer, oldsz - offset) != oldsz-offset){
				LOG_ERROR("Error writing to file " << FilePath << ".");
				return false;
			}

			free(buffer);
		}



		if(lseek(hFile, offset, SEEK_SET) >= 0){
			if(write(hFile, value, length) != length){
				LOG_ERROR("Write failed for file " << FilePath << ".");
				return false;
			}

			return true;
		}else{
			LOG_ERROR("Unable to set fd");
			return false;
		}

		LOG_VERBOSE(1, "Successfule wrote to " << FilePath << "at offset" << offset);
		return true;
	}

	bool File::Read(void* buffer, const unsigned long amount, const long offset, unsigned int * amountRead) const {
		SCOPE_LOCK(this->SetFilePointer(0), ResetFilePointer); //TODO: again - fix this
		LOG_VERBOSE(2, "Attempting to read " << amount << " bytes from " << FilePath << " at offset " << offset);
		if(!bFileExists) {
			LOG_ERROR("Can't read from " << FilePath << ". File doesn't exist.");
			errno = ENOENT;
			return false;
		}

		if (!bReadAccess) {
			LOG_ERROR("Can't read from " << FilePath << ". Insufficient permissions.");
			errno = EPERM;
			return false;
		}

		if(lseek(hFile, offset, SEEK_SET) != offset){
			LOG_ERROR("Can't set file pointer to " << offset << " in file " << FilePath << ".");
			return false;
		}

		int bytesRead = read(hFile, buffer, amount);

		if(bytesRead < 0){
			LOG_ERROR("Error reading file " << FilePath << ".");
			return false;
		}

		*amountRead = bytesRead;
		//NOTE: bug in the current repo - this was originally "wrote" instead of "read"
		LOG_VERBOSE(1, "Successfully read " << amount << " bytes to " << FilePath);
		return true;
	}

	AllocationWrapper File::Read(unsigned long amount, long offset, unsigned int * amountRead) const {
		if(amount == -1){
			amount = this->GetFileSize();
		}
		AllocationWrapper memory = { malloc(amount + 1), amount + 1, AllocationWrapper::MALLOC };
		bool success = Read(memory.GetAsPointer(), amount, offset, amountRead);
		return success ? memory : AllocationWrapper{ nullptr, 0 };
	}

	bool File::MatchesAttributes(const FileSearchAttribs& searchAttribs) const {
		if (searchAttribs.extensions.size() > 0) {
			std::string ext = ToLowerCaseA(GetFileAttribs().extension);
			if (std::count(searchAttribs.extensions.begin(), searchAttribs.extensions.end(), ext) == 0) {
				return false;
			}
		}

		return true;
	}

	bool File::GetFileSigned() const {
		//left off here
		/*if (!bFileExists) {
			LOG_ERROR("Can't check file signature for " << FilePath << ". File doesn't exist.");
			SetLastError(ERROR_FILE_NOT_FOUND);
			return false;
		}
		if (!bReadAccess) {
			LOG_ERROR("Can't check file signature for " << FilePath << ". Insufficient permissions.");
			SetLastError(ERROR_ACCESS_DENIED);
			return false;
		}
		WINTRUST_FILE_INFO FileData{};
		FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
		FileData.pcwszFilePath = FilePath.c_str();
		FileData.hFile = hFile;
		FileData.pgKnownSubject = NULL;

		GUID verification = WINTRUST_ACTION_GENERIC_VERIFY_V2;

		WINTRUST_DATA WinTrustData{};

		WinTrustData.cbStruct = sizeof(WinTrustData);
		WinTrustData.pPolicyCallbackData = NULL;
		WinTrustData.pSIPClientData = NULL;
		WinTrustData.dwUIChoice = WTD_UI_NONE;
		WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
		WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
		WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
		WinTrustData.hWVTStateData = NULL;
		WinTrustData.pwszURLReference = NULL;
		WinTrustData.dwUIContext = 0;
		WinTrustData.pFile = &FileData;

		LONG result = WinVerifyTrust((HWND) INVALID_HANDLE_VALUE, &verification, &WinTrustData);
		WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
		WinVerifyTrust(NULL, &verification, &WinTrustData);
		if(result == ERROR_SUCCESS){
			LOG_VERBOSE(1, FilePath << " is signed.");
			return true;
		}
		else {
			//Verify signature in system catalog
			bool bInCatalog = File::GetFileInSystemCatalogs();
			if (bInCatalog) {
				LOG_VERBOSE(1, FilePath << " signed in system catalogs.");
				return true;
			}
		}
		LOG_VERBOSE(1, FilePath << " not signed or located in system catalogs.");*/
		return false;
	}

	std::optional<std::string> GetCertificateIssuer(const std::string& wsFilePath){
		/*unsigned int dwEncoding{};
		unsigned int dwContentType{};
		unsigned int dwFormatType{};
		GenericWrapper<HCERTSTORE> hStore{ nullptr, [](HCERTSTORE store){ CertCloseStore(store, 0); }, INVALID_HANDLE_VALUE };
		GenericWrapper<HCRYPTMSG> hMsg{ nullptr, CryptMsgClose, INVALID_HANDLE_VALUE };
		auto status{ CryptQueryObject(CERT_QUERY_OBJECT_FILE, wsFilePath.c_str(), CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
			CERT_QUERY_FORMAT_FLAG_BINARY, 0, &dwEncoding, &dwContentType, &dwFormatType, &hStore, &hMsg, nullptr) };
		if(!status){
			LOG_ERROR("Failed to query signature for " << wsFilePath << ": " << SYSTEM_ERROR);
			return std::nullopt;
		}

		unsigned int dwSignerInfoSize{};
		status = CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &dwSignerInfoSize);
		if(!status){
			LOG_ERROR("Failed to query signer information size for " << wsFilePath << ": " << SYSTEM_ERROR);
			return std::nullopt;
		}

		std::vector<CHAR> info(dwSignerInfoSize);
		status = CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, info.data(), &dwSignerInfoSize);
		if(!status){
			LOG_ERROR("Failed to query signer information for " << wsFilePath << ": " << SYSTEM_ERROR);
			return std::nullopt;
		}
		
		auto signer{ reinterpret_cast<PCMSG_SIGNER_INFO>(info.data())->Issuer };
		unsigned int dwSize = CertNameToStrW(X509_ASN_ENCODING, &signer, CERT_SIMPLE_NAME_STR, nullptr, 0);

		std::vector<WCHAR> buffer(dwSize);
		CertNameToStrW(X509_ASN_ENCODING, &signer, CERT_SIMPLE_NAME_STR, buffer.data(), dwSize);

		return std::string{ buffer.data(), dwSize };*/
		return std::nullopt;
	}

	bool File::IsMicrosoftSigned() const{
		if(!bFileExists){
			LOG_ERROR("Can't check file signature for " << FilePath << ". File doesn't exist.");
			//SetLastError(ERROR_FILE_NOT_FOUND);
			errno = ENOENT;
			return false;
		}
		if(!bReadAccess){
			LOG_ERROR("Can't check file signature for " << FilePath << ". Insufficient permissions.");
			//SetLastError(ERROR_ACCESS_DENIED);
			errno = EPERM;
			return false;
		}

		if(!GetFileSigned()){
			return false;
		}

		/*if(File::GetFileInSystemCatalogs()){
			auto catalog{ GetCatalog(hFile) };
			if(catalog){
				auto signer{ GetCertificateIssuer(*catalog) };
				if(signer){
					return ToLowerCaseW(*signer).find("microsoft") != std::string::npos;
				} else{
					LOG_ERROR("Unable to get the certificate issuer for " << *catalog << ": " << SYSTEM_ERROR);
				}
			} else{
				LOG_ERROR("Unable to get the catalog for " << FilePath << ": " << SYSTEM_ERROR);
			}
		} else{
			auto signer{ GetCertificateIssuer(FilePath) };
			if(signer){
				return ToLowerCaseW(*signer).find("microsoft") != std::string::npos;
			} else{
				LOG_ERROR("Unable to get the certificate issuer for " << FilePath << ": " << SYSTEM_ERROR);
			}
		}*/
		return false;
	}

	std::optional<std::string> File::GetMD5Hash() const {
		LOG_VERBOSE(3, "Attempting to get MD5 hash of " << FilePath);
		return CalculateHashType(HashType::MD5_HASH);
	}

	std::optional<std::string> File::GetSHA1Hash() const {
		LOG_VERBOSE(3, "Attempting to get SHA1 hash of " << FilePath);
		return CalculateHashType(HashType::SHA1_HASH);
	}

	std::optional<std::string> File::GetSHA256Hash() const {
		LOG_VERBOSE(3, "Attempting to get SHA256 hash of " << FilePath);
		return CalculateHashType(HashType::SHA256_HASH);
	}

	bool File::Create() {
		//left off here
		LOG_VERBOSE(1, "Attempting to create file: " << FilePath);
		if(bFileExists) {
			LOG_ERROR("Can't create " << FilePath << ". File already exists.");
			return false;
		}

		//TODO: should this be able to create directories too? How to distinguish between them?

		if((hFile = open(FilePath.c_str(), O_RDWR | O_CREAT, S_IRWXU)) < 0){
			LOG_ERROR("Error creating file " << FilePath << ". Error code = " << errno);
			return false;
		}

		bFileExists = true;
		bWriteAccess = true;
		bReadAccess = true;
		
		LOG_VERBOSE(1, FilePath << "successfully created.");
		return true;
	}

	bool File::Delete() {
		LOG_VERBOSE(1, "Attempting to delete file " << FilePath);
		if(!bFileExists) {
			LOG_ERROR("Can't delete file " << FilePath << ". File doesn't exist");
			return false;
		}

		close(hFile);
		if(unlink(FilePath.c_str()) < 0){
			LOG_ERROR("Deleting file " << FilePath << " failed with error " << errno);
			return false;
		}

		LOG_VERBOSE(1, FilePath << "deleted.");
		bFileExists = false;
		return true;
	}

	bool File::ChangeFileLength(const long length) const {
		return ftruncate(hFile, length) == 0;
	}

	uint64_t File::GetFileSize() const {
		if(!bFileExists)
		    return 0;
		loff_t size = lseek64(hFile, 0L, SEEK_END);
		lseek(hFile, 0L, SEEK_SET);
		return size;
	}

	std::string File::ToString() const {
		return FilePath;
	}

	bool FileObject::SetFileOwner(const Permissions::Owner& owner) {
		if (!bFileExists) {
			LOG_ERROR("Can't set owner of nonexistent file " << FilePath);
			errno = ENOENT;
			return false;
		}

		if(!owner.Exists()){
			LOG_ERROR("Cant set file to owner that doesnt exist");
			return false;
		}
		
		if(owner.GetOwnerType() == Permissions::USER){

			if(fchown(hFile, owner.GetId(), -1) < 0){
				LOG_ERROR("Error changing file owner: " << errno);
				return false;
			}
		}else if(owner.GetOwnerType() == Permissions::GROUP){

			if(fchown(hFile, -1, owner.GetId()) < 0){
				LOG_ERROR("Error changing file owner: " << errno);
				return false;
			}
		}else{
			LOG_ERROR("Invalid usertype to change owner " << owner.GetOwnerType());
			return false;
		}
		LOG_VERBOSE(3, "Set the owner for file " << FilePath << " to " << owner.GetName() << ".");
		return true;
	}

	std::optional<ACCESS_MASK> FileObject::GetPermissions() const{
		if(!bFileExists){
			LOG_ERROR("Cant get permissions of nonexistant file " << FilePath << ".");
		    return std::nullopt;
		}
		struct stat statbuf;
		if(fstat(hFile, &statbuf) < 0){
			LOG_ERROR("Unable to stat file");
			return std::nullopt;
		}

		return statbuf.st_mode;
	}

	bool File::Quarantine() {
	    if (!bFileExists) {
			LOG_ERROR("Can't quarantine file " << FilePath << ". File doesn't exist");
			errno = ENOENT;
			return false;
		}

		return fchmod(hFile, 0) == 0;
	}

	Folder::Folder(const std::string& path) : hDirectory{NULL}, hCurFile {NULL}, bIsFile {false} {
		FilePath = path;
		hDirectory = opendir(path.c_str());
		bFileExists = true;

		if(hDirectory == NULL){
			if(errno == ENOENT){
				bFileExists = false;
			}
			
			LOG_ERROR("Unable to open directory " << FilePath << ": " << errno << ".");
		}else{
			//get the first file
			hFile = dirfd(hDirectory);
			this->MoveToBeginning();
		}


	}

	bool Folder::MoveToNextFile() {
		if(!hDirectory){
			LOG_ERROR("Cant move to new file: Directory isnt opened");
			return false;
		}

		hCurFile = readdir(hDirectory);
		if(!hCurFile){
			LOG_ERROR("Unable to move to next file: " << errno << ".");
			return false;
	    }
		//now set up booleans

		if(hCurFile->d_type == DT_UNKNOWN){
			LOG_ERROR("Unable to determine file type for file " << hCurFile->d_name);
			return false;
		}

		if(hCurFile->d_type == DT_DIR){
			bIsFile = false;
		}else{
			if(hCurFile->d_type == DT_LNK){
				char path[PATH_MAX + 1];
				memset(path, 0x0, PATH_MAX + 1);
				if(readlinkat(dirfd(hDirectory), hCurFile->d_name, path, PATH_MAX + 1) < 0){
					LOG_ERROR("error reading symbolic link");
					return false;
				}

				struct stat statbuf;

				if(fstatat(dirfd(hDirectory), path, &statbuf, 0) < 0){
					LOG_ERROR("Unable to stat file");
					return false;
				}

				bIsFile = !S_ISDIR(statbuf.st_mode);

				
			}else{
				bIsFile = true;
			}
		}
		return true;
	}

	bool Folder::MoveToBeginning() {

		if(!hDirectory){
			LOG_ERROR("Folder is not currently open");
			return false;
		}

		if(!bFileExists){
			LOG_ERROR("Filepath " << FilePath << "does not exist.");
			return false;
		}
		rewinddir(hDirectory);
		return this->MoveToNextFile();
	}

	bool Folder::GetCurIsFile() const {
		return bIsFile;
	}

	std::optional<File> Folder::Open() const {
		if(bIsFile && hCurFile) {
			std::string path = FilePath + "/" + hCurFile->d_name;
			return File(path);
		}
		return std::nullopt;
	}

	std::optional<Folder> Folder::EnterDir() {
		if(!bIsFile && hCurFile) {
			std::string path = FilePath + "/" + hCurFile->d_name;
			return Folder(path);
		}
		return std::nullopt;
	}

	std::optional<File> Folder::AddFile(const std::string& fileName) const {
		std::string path = FilePath + "/" + fileName;
		File file = File(path);
		if(file.GetFileExists()) {
			return file;
		}
		if(file.Create()) {
			return file;
		}
		return std::nullopt;
	}

	bool FileSystem::Folder::RemoveFile() const {
		if(GetCurIsFile()) {
			std::optional<File> f = Open();
			if(f && f->GetFileExists()) {
				if(f->Delete()){
					return true;
				}
			}
		}
		return false;
	}

	std::vector<File> Folder::GetFiles(std::optional<FileSearchAttribs> attribs, int recurDepth) {
		if(!MoveToBeginning()) {
			LOG_ERROR("Couldn't get to beginning of folder " << FilePath);
			return std::vector<File>();
		}
		std::vector<File> toRet = std::vector<File>();
		do {
			if(GetCurIsFile()) {
				std::optional<File> f = Open();
				if(f) {
					if(!attribs) {
						toRet.emplace_back(*f);
					}else {
						if (f->MatchesAttributes(attribs.value())) {
							toRet.emplace_back(*f);
						}
					}
				}
			} else if(recurDepth != 0 && hCurFile->d_name != std::string{ "." } && hCurFile->d_name != std::string{ ".." }){
				std::vector<File> temp;
				std::optional<Folder> f = EnterDir();
				if(f) {
					if(recurDepth == -1) {
						temp = f->GetFiles(attribs, recurDepth);
					} else {
						temp = f->GetFiles(attribs, recurDepth - 1);
					}
					while(!temp.empty()) {
						File file = temp.at(temp.size() - 1);
						temp.pop_back();
						toRet.emplace_back(file);
					}
				}
			}
		} while(MoveToNextFile());
		return toRet;
	}

	std::vector<Folder> Folder::GetSubdirectories(int recurDepth) {
		if(MoveToBeginning() == 0) {
			LOG_ERROR("Couldn't get to beginning of folder " << FilePath);
			return {};
		}
		std::vector<Folder> toRet = {};
		do {
			if(!GetCurIsFile() && recurDepth != 0 && hCurFile->d_name != std::string{ "." } && hCurFile->d_name != std::string{ ".." }){
				std::vector<Folder> temp;
				std::optional<Folder> f = EnterDir();
				if(f.has_value()) {
					toRet.emplace_back(f.value());
					if(recurDepth == -1) {
						temp = f->GetSubdirectories(recurDepth);
					} else {
						temp = f->GetSubdirectories(recurDepth - 1);
					}
					while(!temp.empty()) {
						auto folder = temp.at(temp.size() - 1);
						temp.pop_back();
						toRet.emplace_back(folder);
					}
				}
			}
		} while(MoveToNextFile());
		return toRet;
	}



	void Folder::Close(){
		closedir(hDirectory);
	}

	bool Folder::CanDeleteContents(const Permissions::Owner &user){
		return CanExecute(user) && CanWrite(user);
	}

	FileObject::~FileObject(){
		this->Close();
	}

	//NOTE: Make some sort of class heirarchy so that I dont have to reuse this method
	bool FileObject::HasPermHelper(const Permissions::Owner &user, unsigned int userMask, unsigned int groupMask, unsigned int otherMask){
		if(!bFileExists)
		    return false;
		std::optional<ACCESS_MASK> permissions = GetPermissions();

		if(!permissions.has_value()){
			return false;
		}

		if(user.GetOwnerType() == Permissions::USER && permissions.value() & userMask){
			std::optional<Permissions::Owner> userOwner = GetFileOwner(Permissions::USER);
			if(userOwner.has_value() && userOwner.value() == user){
				return true;
			}
		}

		if(permissions.value() & groupMask){
			std::optional<Permissions::Owner> groupOwner = GetFileOwner(Permissions::GROUP);

			if(groupOwner.has_value() && groupOwner.value() == user){
				return true;
			}

			//now check if the user is in the owning group
			if(groupOwner.has_value() && user.GetOwnerType() == Permissions::USER){
				const Permissions::User &userobj = reinterpret_cast<const Permissions::User&> (user);
				if(userobj.GetGroup() == groupOwner.value().GetId()){
					return true;
				}
			}
		}

		if(permissions.value() & otherMask){
			return true;
		}

		return false;
	}

	bool FileObject::CanRead(const Permissions::Owner &user){
		return HasPermHelper(user, S_IRUSR, S_IRGRP, S_IROTH);
	}

	bool FileObject::CanWrite(const Permissions::Owner &user){
		return HasPermHelper(user, S_IWUSR, S_IWGRP, S_IWOTH);
	}

	bool FileObject::CanExecute(const Permissions::Owner &user){
		return HasPermHelper(user, S_IXUSR, S_IXGRP, S_IXOTH);
	}

	bool FileObject::CanDelete(const Permissions::Owner &user){
		if(FilePath == "/" || !bFileExists){
			return false;
		}

		return GetDirectory().value().CanDeleteContents(user);
	}

	bool FileObject::CanReadWrite(const Permissions::Owner &user){
		return CanRead(user) && CanWrite(user);
	}

	std::optional<Folder> FileObject::GetDirectory() const{
		if(FilePath == "/"){
			return std::nullopt;
		}
		char buffer[PATH_MAX + 1];
		strncpy(buffer, FilePath.c_str(), PATH_MAX + 1);
		return Folder(std::string(dirname(buffer)));
	}

	int FileObject::GetFileDescriptor() const{
		return hFile;
	}

	std::string FileObject::GetFilePath() const{
		return FilePath;
	}

	bool FileObject::GetFileExists() const{
		return bFileExists;
	}

	std::optional<Permissions::Owner> FileObject::GetFileOwner(const Permissions::OwnerType type) const {
		//left off here
		if (!bFileExists) {
			LOG_ERROR("Can't get owner of nonexistent file " << FilePath);
			return std::nullopt;
		}

		if(type == Permissions::NONE){
			LOG_ERROR("invalid owner type");
			return std::nullopt;
		}

		struct stat statbuf;
		if(fstat(hFile, &statbuf) < 0){
			LOG_ERROR("Error stating file " << FilePath << ". errorno = " << errno);
			return std::nullopt;
		}

		if(type == Permissions::USER){
			return Permissions::User(statbuf.st_uid);
		}else if(type == Permissions::GROUP){
			return Permissions::Group(statbuf.st_gid);
		}

		return std::nullopt;
	}

	std::optional<struct statx_timestamp> FileObject::GetCreationTime() const {
		if (!bFileExists) {
			LOG_ERROR("Can't get creation time of " << FilePath << ", file doesn't exist");
			errno = ENOENT;
			return std::nullopt;
		}
		struct statx statbuf;
		if (statx(hFile, "", AT_EMPTY_PATH, STATX_BTIME, &statbuf) == 0) {
			return statbuf.stx_btime;
		}else {
			LOG_ERROR("Error getting creation time of " << FilePath << ". (Error: " << errno << ")");
			return std::nullopt;
		}
	}

	std::optional<struct statx_timestamp> FileObject::GetModifiedTime() const {
		if (!bFileExists) {
			LOG_ERROR("Can't get modification time of " << FilePath << ", file doesn't exist");
			errno = ENOENT;
			return std::nullopt;
		}
		struct statx statbuf;
		if (statx(hFile, "", AT_EMPTY_PATH, STATX_MTIME, &statbuf) == 0) {
			return statbuf.stx_mtime;
		}else {
			LOG_ERROR("Error getting modification time of " << FilePath << ". (Error: " << errno << ")");
			return std::nullopt;
		}
	}

	std::optional<struct statx_timestamp> FileObject::GetAccessTime() const {
		if (!bFileExists) {
			LOG_ERROR("Can't get access time of " << FilePath << ", file doesn't exist");
			errno = ENOENT;
			return std::nullopt;
		}
		struct statx statbuf;
		if (statx(hFile, "", AT_EMPTY_PATH, STATX_ATIME, &statbuf) == 0) {
			return statbuf.stx_atime;
		}else {
			LOG_ERROR("Error getting access time of " << FilePath << ". (Error: " << errno << ")");
			return std::nullopt;
		}
	}

	bool FileObject::GrantPermissions(const ACCESS_MASK amAccess) {
		//return Permissions::UpdateObjectACL(FilePath, SE_FILE_OBJECT, owner, amAccess);
		if(!bFileExists){
			LOG_ERROR("Cant get permissions of nonexistant file " << FilePath << ".");
		    return false;
		}
		std::optional<ACCESS_MASK> perms = this->GetPermissions();
		if(!perms.has_value()){
			return false;
		}

		return fchmod(hFile, perms.value() | amAccess) == 0;
	}

	bool FileObject::DenyPermissions(const ACCESS_MASK amAccess) 
	{	
		if(!bFileExists){
			LOG_ERROR("Cant get permissions of nonexistant file " << FilePath << ".");
		    return false;
		}
		std::optional<ACCESS_MASK> perms = this->GetPermissions();
		if(!perms.has_value()){
			return false;
		}

		return fchmod(hFile, perms.value() & ~amAccess) == 0;
	}

	bool FileObject::TakeOwnership() {
		if(!bFileExists){
			LOG_ERROR("Cant get permissions of nonexistant file " << FilePath << ".");
		    return false;
		}
		std::optional<Permissions::Owner> BluespawnOwner = Permissions::GetProcessOwner();
		if (BluespawnOwner == std::nullopt) {
			return false;
		}
		return this->SetFileOwner(*BluespawnOwner);
	}


}