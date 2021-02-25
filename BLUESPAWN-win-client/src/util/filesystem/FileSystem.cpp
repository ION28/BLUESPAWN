#include "util/filesystem/FileSystem.h"

#include <Shlwapi.h>
#include <SoftPub.h>
#include <Wincrypt.h>
#include <fileapi.h>
#include <mscat.h>
#include <windows.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "util/StringUtils.h"
#include "util/log/Log.h"
#include "util/permissions/permissions.h"
#include "util/wrappers.hpp"

#include "aclapi.h"

LINK_FUNCTION(NtCreateFile, ntdll.dll);

namespace FileSystem {
    bool CheckFileExists(const std::wstring& path) {
        auto attribs = GetFileAttributesW(path.c_str());
        if(INVALID_FILE_ATTRIBUTES == attribs && GetLastError() == ERROR_FILE_NOT_FOUND) {
            LOG_VERBOSE(3, "File " << path << " does not exist.");
            return false;
        }

        if(attribs & FILE_ATTRIBUTE_DIRECTORY) {
            LOG_VERBOSE(3, "File " << path << " is a directory.");
            return false;
        }
        LOG_VERBOSE(3, "File " << path << " exists");
        return true;
    }

    std::optional<std::wstring> SearchPathExecutable(const std::wstring& name) {
        std::wstring fullname = ExpandEnvStringsW(name);

        auto size = SearchPathW(nullptr, fullname.c_str(), L".exe", 0, nullptr, nullptr);
        if(!size) {
            return std::nullopt;
        }

        std::vector<WCHAR> buffer(static_cast<size_t>(size) + 1);
        WCHAR* filename{};
        if(!SearchPathW(nullptr, fullname.c_str(), L".exe", size + 1, buffer.data(), &filename)) {
            return std::nullopt;
        }

        return buffer.data();
    }

    DWORD File::SetFilePointer(DWORD64 val) const {
        //Calculate the offset into format needed for SetFilePointer
        long lowerMask = 0xFFFFFFFF;
        DWORD64 upperMask = static_cast<DWORD64>(0xFFFFFFFF) << 32;
        auto lowerVal = static_cast<DWORD>(val & lowerMask);
        auto upperVal = static_cast<DWORD>((val & upperMask) >> 32);
        return ::SetFilePointer(hFile, lowerVal, reinterpret_cast<PLONG>(&upperVal), 0);
    }

    std::vector<std::wstring> GetCatalog(const HandleWrapper& hFile) {
        if(!hFile) {
            return {};
        }

        HCATADMIN admin{};
        GUID gAction = DRIVER_ACTION_VERIFY;
        if(!CryptCATAdminAcquireContext(&admin, &gAction, 0)) {
            LOG_ERROR("Error acquiring catalog admin context " << SYSTEM_ERROR);
            return {};
        }
        GenericWrapper<HCATADMIN> hCatAdmin{ admin, [](auto val) { CryptCATAdminReleaseContext(&val, 0); },
                                             INVALID_HANDLE_VALUE };

        DWORD dwHashLength{ 0 };
        if(!CryptCATAdminCalcHashFromFileHandle(hFile, &dwHashLength, NULL, 0)) {
            LOG_ERROR("Error getting hash size " << SYSTEM_ERROR);
            return {};
        }

        std::vector<BYTE> pbHash(dwHashLength);
        if(!CryptCATAdminCalcHashFromFileHandle(hFile, &dwHashLength, pbHash.data(), 0)) {
            LOG_VERBOSE(2, "Error getting file hash for " << static_cast<HANDLE>(hFile) << " " << SYSTEM_ERROR);
            return {};
        }

        std::vector<std::wstring> catalogfiles{};
        GenericWrapper<HCATINFO> hCatInfo{
            CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash.data(), dwHashLength, 0, nullptr),
            [&hCatAdmin](auto val) { CryptCATAdminReleaseCatalogContext(&hCatAdmin, &val, 0); }, INVALID_HANDLE_VALUE
        };
        while(hCatInfo) {
            CATALOG_INFO ciCatalogInfo = {};
            ciCatalogInfo.cbStruct = sizeof(ciCatalogInfo);

            if(!CryptCATCatalogInfoFromContext(hCatInfo, &ciCatalogInfo, 0)) {
                LOG_ERROR("Couldn't get catalog info for catalog containing hash of file");
                break;
            }

            LOG_VERBOSE(3, "Hash for file found in catalog " << ciCatalogInfo.wszCatalogFile);
            catalogfiles.emplace_back(ciCatalogInfo.wszCatalogFile);
            hCatInfo.reassign(CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash.data(), dwHashLength, 0, &hCatInfo));
        }

        return catalogfiles;
    }

    bool File::GetFileInSystemCatalogs() const { return GetCatalog(hFile).size(); }

    std::optional<std::wstring> File::CalculateHashType(HashType hashType) const {
        // Adapted largely from https://stackoverflow.com/a/13259720/4815264
        auto data{ Read() };
        if(!data) {
            LOG_VERBOSE(2, "File " << FilePath << " cannot be hashed.");
        }

        HCRYPTPROV prov{};
        if(!CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            LOG_ERROR("Unable to create cryptography provider");
            return std::nullopt;
        }
        GenericWrapper<HCRYPTPROV> hProv{ prov, std::bind(CryptReleaseContext, std::placeholders::_1, 0) };

        bool success{ false };
        HCRYPTPROV hash{};
        switch(hashType) {
        case HashType::SHA1_HASH: success = CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hash); break;
        case HashType::MD5_HASH: success = CryptCreateHash(hProv, CALG_MD5, 0, 0, &hash); break;
        case HashType::SHA256_HASH: success = CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hash); break;
        }

        GenericWrapper<HCRYPTPROV> hHash{ hash, CryptDestroyHash };

        if(!success) {
            LOG_ERROR("Unable to create hash providers");
            return std::nullopt;
        }

        if(!CryptHashData(hHash, data.GetAsPointer<const BYTE>(), data.GetSize(), 0)) {
            LOG_ERROR("Failed to hash file " << FilePath << " (" << SYSTEM_ERROR << ")");
            return std::nullopt;
        }

        DWORD cbHashSize = 0, dwCount = sizeof(DWORD);
        if(!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*) &cbHashSize, &dwCount, 0)) {
            LOG_ERROR("Failed to read hash size for " << FilePath << " (" << SYSTEM_ERROR << ")");
            return std::nullopt;
        }

        std::vector<BYTE> buffer(cbHashSize);
        if(!CryptGetHashParam(hHash, HP_HASHVAL, reinterpret_cast<BYTE*>(buffer.data()), &cbHashSize, 0)) {
            LOG_ERROR("Failed to read hash for " << FilePath << " (" << SYSTEM_ERROR << ")");
            return std::nullopt;
        }

        std::wstringstream oss{};
        for(auto& byte : buffer) {
            oss.fill('0');
            oss.width(2);
            oss << std::hex << static_cast<const int>(byte);
        }

        return oss.str();
    }

    File::File(IN const std::wstring& path) : hFile{ nullptr } {
        if(!path.length()) {
            bFileExists = false;
            bWriteAccess = false;
            bReadAccess = false;
            return;
        }
        FilePath = ExpandEnvStringsW(path);
        LOG_VERBOSE(2, "Attempting to open file: " << FilePath << ".");
        if(FilePath.at(0) == L'\\') {
            UNICODE_STRING UnicodeName{ static_cast<USHORT>(FilePath.length() * 2),
                                        static_cast<USHORT>(FilePath.length() * 2),
                                        const_cast<PWCHAR>(FilePath.c_str()) };
            OBJECT_ATTRIBUTES attributes{};
            IO_STATUS_BLOCK IoStatus{};
            InitializeObjectAttributes(&attributes, &UnicodeName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr,
                                       nullptr);
            NTSTATUS Status{ Linker::NtCreateFile(
                &hFile, GENERIC_READ | GENERIC_WRITE, &attributes, &IoStatus, nullptr, FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, FILE_SEQUENTIAL_ONLY, nullptr, 0) };
            if(NT_SUCCESS(Status)) {
                this->hFile = hFile;
                bFileExists = true;
                bWriteAccess = true;
                bReadAccess = true;
            } else if(Status == 0xC0000022 || Status == 0xC0000043) {   //STATUS_ACCESS_DENIED, STATUS_SHARING_VIOLATION
                Status = Linker::NtCreateFile(&hFile, GENERIC_READ, &attributes, &IoStatus, nullptr,
                                              FILE_ATTRIBUTE_NORMAL,
                                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
                                              FILE_SEQUENTIAL_ONLY, nullptr, 0);
                if(NT_SUCCESS(Status)) {
                    this->hFile = hFile;
                    bFileExists = true;
                    bWriteAccess = false;
                    bReadAccess = true;
                } else {
                    LOG_ERROR("Unable to create a file handle for file " << FilePath << " (NTSTATUS " << Status << ")");
                    bFileExists = true;
                    bWriteAccess = false;
                    bReadAccess = false;
                }
            } else {
                LOG_VERBOSE(2, "Couldn't open file since file doesn't exist (" << FilePath << ").");
                bFileExists = false;
                bWriteAccess = false;
                bReadAccess = false;
            }
        } else {
            hFile = CreateFileW(FilePath.c_str(), GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                FILE_FLAG_SEQUENTIAL_SCAN | FILE_ATTRIBUTE_NORMAL, nullptr);
            if(!hFile && GetLastError() == ERROR_FILE_NOT_FOUND) {
                LOG_VERBOSE(2, "Couldn't open file, file doesn't exist " << FilePath << ".");
                bFileExists = false;
                bWriteAccess = false;
                bReadAccess = false;
            } else if(!hFile && (GetLastError() == ERROR_ACCESS_DENIED || GetLastError() == ERROR_SHARING_VIOLATION)) {
                bWriteAccess = false;
                hFile = CreateFileW(FilePath.c_str(), GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                    FILE_FLAG_SEQUENTIAL_SCAN | FILE_ATTRIBUTE_NORMAL, nullptr);
                if(!hFile && GetLastError() == ERROR_SHARING_VIOLATION) {
                    LOG_VERBOSE(2, "Couldn't open file, sharing violation " << FilePath << ".");
                    bFileExists = true;
                    bReadAccess = false;
                } else if(!hFile && GetLastError() == ERROR_ACCESS_DENIED) {
                    LOG_VERBOSE(2, "Couldn't open file, Access Denied" << FilePath << ".");
                    bFileExists = true;
                    bReadAccess = false;
                } else if(GetLastError() != ERROR_SUCCESS) {
                    LOG_VERBOSE(2, "Couldn't open file " << FilePath << ". " << SYSTEM_ERROR);
                    bFileExists = true;
                    bReadAccess = false;
                } else {
                    LOG_VERBOSE(2, "File " << FilePath << " opened.");
                    bFileExists = true;
                    bReadAccess = true;
                }
            } else if(ERROR_SUCCESS == GetLastError()) {
                LOG_VERBOSE(2, "File " << FilePath << " opened.");
                bFileExists = true;
                bWriteAccess = true;
                bReadAccess = true;
            } else {
                LOG_VERBOSE(2, "File " << FilePath << " failed to open with error " << GetLastError());
                bFileExists = false;
                bWriteAccess = false;
                bReadAccess = false;
            }
        }
        Attribs.extension = PathFindExtensionW(FilePath.c_str());
    }

    std::wstring File::GetFilePath() const { return FilePath; }

    FileAttribs File::GetFileAttribs() const { return Attribs; }

    bool File::GetFileExists() const { return bFileExists; }

    bool File::HasWriteAccess() const { return bWriteAccess; }

    bool File::HasReadAccess() const { return bReadAccess; }

    bool File::Write(IN const LPCVOID value,
                     IN const long offset,
                     IN const unsigned long length,
                     IN const bool truncate OPTIONAL,
                     IN const bool insert OPTIONAL) const {
        SCOPE_LOCK(SetFilePointer(0), ResetFilePointer);
        LOG_VERBOSE(2, "Writing to file " << FilePath << " at " << offset << ". Insert = " << insert);

        DWORD dwBytesIO{};

        if(!bFileExists) {
            LOG_VERBOSE(2, "Can't write to file " << FilePath << ". File doesn't exist");
            SetLastError(ERROR_FILE_NOT_FOUND);
            return false;
        }

        if(!bWriteAccess) {
            LOG_VERBOSE(2, "Can't write to file " << FilePath << ". Insufficient permissions.");
            SetLastError(ERROR_ACCESS_DENIED);
            return false;
        }

        //Insert value into file at specified offset
        if(insert && !truncate) {
            DWORD64 dwFileSize = GetFileSize();
            for(DWORD64 dwCopyOffset = 0; dwCopyOffset < length; dwCopyOffset += min(1 << 20, length - dwCopyOffset)) {
                DWORD dwCopySize = min(1 << 20, length - dwCopyOffset);
                AllocationWrapper buffer = { new char[dwCopySize], dwCopySize, AllocationWrapper::CPP_ARRAY_ALLOC };
                if(SetFilePointer(dwFileSize - dwCopyOffset - dwCopySize) == INVALID_SET_FILE_POINTER) {
                    LOG_ERROR("Can't set file pointer to " << offset << " in file " << FilePath << ".");
                    return false;
                }
                if(!ReadFile(hFile, buffer, dwCopySize, &dwBytesIO, nullptr)) {
                    LOG_ERROR("Unable to read " << FilePath << " at offset " << dwFileSize - dwCopyOffset - dwCopySize
                                                << " " << SYSTEM_ERROR);
                    return false;
                }
                if(SetFilePointer(dwFileSize - dwCopyOffset) == INVALID_SET_FILE_POINTER) {
                    LOG_ERROR("Can't set file pointer to " << offset << " in file " << FilePath << ".");
                    return false;
                }
                if(!WriteFile(hFile, buffer, dwCopySize, &dwBytesIO, nullptr)) {
                    LOG_ERROR("Unable to write to " << FilePath << " at offset " << dwFileSize - dwCopyOffset << " "
                                                    << SYSTEM_ERROR);
                    return false;
                }
            }
        }
        //Write value over file at specified offset
        if(SetFilePointer(offset) == INVALID_SET_FILE_POINTER) {
            LOG_ERROR("Can't set file pointer to " << offset << " in file " << FilePath << ".");
            return false;
        }

        if(!WriteFile(hFile, value, length, &dwBytesIO, nullptr)) {
            LOG_ERROR("Failed to write to " << FilePath << " at offset " << offset << " with " << SYSTEM_ERROR);
            return false;
        }

        if(truncate) {
            if(!SetEndOfFile(hFile)) {
                LOG_ERROR("Couldn't truncate file " << FilePath);
                return false;
            }
        }
        LOG_VERBOSE(1, "Successfule wrote to " << FilePath << "at offset" << offset);
        return true;
    }

    bool File::Read(OUT LPVOID buffer,
                    IN const unsigned long amount OPTIONAL,
                    IN const long offset OPTIONAL,
                    OUT PDWORD amountRead OPTIONAL) const {
        SCOPE_LOCK(SetFilePointer(0), ResetFilePointer);
        LOG_VERBOSE(2, "Attempting to read " << amount << " bytes from " << FilePath << " at offset " << offset);
        if(!bFileExists) {
            LOG_VERBOSE(2, "Can't read from " << FilePath << ". File doesn't exist.");
            SetLastError(ERROR_FILE_NOT_FOUND);
            return false;
        }

        if(!bReadAccess) {
            LOG_VERBOSE(2, "Can't read from " << FilePath << ". Insufficient permissions.");
            SetLastError(ERROR_ACCESS_DENIED);
            return false;
        }

        if(SetFilePointer(offset) == INVALID_SET_FILE_POINTER) {
            LOG_ERROR("Can't set file pointer to " << offset << " in file " << FilePath << ".");
            return false;
        }

        DWORD dwBytesRead{};
        if(!amountRead) {
            amountRead = &dwBytesRead;
        }

        if(!ReadFile(hFile, buffer, amount, amountRead, NULL)) {
            LOG_ERROR("Failed to read from " << FilePath << " at offset " << offset << " with error "
                                             << GetLastError());
            return false;
        }
        LOG_VERBOSE(1, "Successfully wrote " << amount << " bytes to " << FilePath);
        return true;
    }

    AllocationWrapper
    File::Read(__in_opt unsigned long amount, __in_opt long offset, __out_opt PDWORD amountRead) const {
        if(amount == -1) {
            amount = GetFileSize();
        }
        AllocationWrapper memory = { HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, amount + 1), amount + 1,
                                     AllocationWrapper::HEAP_ALLOC };
        bool success = Read(memory, amount, offset, amountRead);
        return success ? memory : AllocationWrapper{ nullptr, 0 };
    }

    bool File::MatchesAttributes(IN const FileSearchAttribs& searchAttribs) const {
        if(searchAttribs.extensions.size() > 0) {
            std::wstring ext = ToLowerCaseW(GetFileAttribs().extension);
            if(std::count(searchAttribs.extensions.begin(), searchAttribs.extensions.end(), ext) == 0) {
                return false;
            }
        }

        return true;
    }

    bool File::GetFileSigned() const {
        if(!bFileExists) {
            LOG_VERBOSE(2, "Can't check file signature for " << FilePath << ". File doesn't exist.");
            SetLastError(ERROR_FILE_NOT_FOUND);
            return false;
        }
        if(!bReadAccess) {
            LOG_VERBOSE(2, "Can't check file signature for " << FilePath << ". Insufficient permissions.");
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
        if(result == ERROR_SUCCESS) {
            LOG_VERBOSE(1, FilePath << " is signed.");
            return true;
        } else {
            //Verify signature in system catalog
            bool bInCatalog = File::GetFileInSystemCatalogs();
            if(bInCatalog) {
                LOG_VERBOSE(1, FilePath << " signed in system catalogs.");
                return true;
            }
        }
        LOG_VERBOSE(1, FilePath << " not signed or located in system catalogs.");
        return false;
    }

    std::optional<std::wstring> File::GetCertificateIssuer() const {
        if(!bFileExists) {
            LOG_VERBOSE(2, "Can't check file signature for " << FilePath << ". File doesn't exist.");
            SetLastError(ERROR_FILE_NOT_FOUND);
            return std::nullopt;
        }

        if(!bReadAccess) {
            LOG_VERBOSE(2, "Can't check file signature for " << FilePath << ". Insufficient permissions.");
            SetLastError(ERROR_ACCESS_DENIED);
            return std::nullopt;
        }

        if(!GetFileSigned()) {
            return std::nullopt;
        }

        if(File::GetFileInSystemCatalogs()) {
            auto catalogs{ GetCatalog(hFile) };
            if(catalogs.size()) {
                return FileSystem::File{ catalogs[0] }.GetCertificateIssuer();
            } else {
                LOG_ERROR("Unable to get the catalog for " << FilePath << ": " << SYSTEM_ERROR);
            }
        } else {
            DWORD dwEncoding{};
            DWORD dwContentType{};
            DWORD dwFormatType{};
            HCERTSTORE store;
            HCRYPTMSG msg;
            auto status{ CryptQueryObject(CERT_QUERY_OBJECT_FILE, FilePath.c_str(),
                                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY, 0,
                                          &dwEncoding, &dwContentType, &dwFormatType, &store, &msg, nullptr) };
            if(!status) {
                LOG_ERROR("Failed to query signature for " << FilePath << ": " << SYSTEM_ERROR);
                return std::nullopt;
            }
            GenericWrapper<HCERTSTORE> hStore{ store, [](HCERTSTORE store) { CertCloseStore(store, 0); },
                                               INVALID_HANDLE_VALUE };
            GenericWrapper<HCRYPTMSG> hMsg{ msg, CryptMsgClose, INVALID_HANDLE_VALUE };

            DWORD dwSignerInfoSize{};
            status = CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &dwSignerInfoSize);
            if(!status) {
                LOG_ERROR("Failed to query signer information size for " << FilePath << ": " << SYSTEM_ERROR);
                return std::nullopt;
            }

            std::vector<CHAR> info(dwSignerInfoSize);
            status = CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, info.data(), &dwSignerInfoSize);
            if(!status) {
                LOG_ERROR("Failed to query signer information for " << FilePath << ": " << SYSTEM_ERROR);
                return std::nullopt;
            }

            auto signer{ reinterpret_cast<PCMSG_SIGNER_INFO>(info.data())->Issuer };
            DWORD dwSize = CertNameToStrW(X509_ASN_ENCODING, &signer, CERT_SIMPLE_NAME_STR, nullptr, 0);

            std::vector<WCHAR> buffer(dwSize);
            CertNameToStrW(X509_ASN_ENCODING, &signer, CERT_SIMPLE_NAME_STR, buffer.data(), dwSize);

            return std::wstring{ buffer.data(), dwSize };
        }

        return std::nullopt;
    }

    bool File::IsMicrosoftSigned() const {
        auto issuer{ GetCertificateIssuer() };
        return issuer && ToLowerCaseW(*issuer).find(L"microsoft") != std::wstring::npos;
    }

    std::optional<std::wstring> File::GetMD5Hash() const {
        LOG_VERBOSE(3, "Attempting to get MD5 hash of " << FilePath);
        return CalculateHashType(HashType::MD5_HASH);
    }

    std::optional<std::wstring> File::GetSHA1Hash() const {
        LOG_VERBOSE(3, "Attempting to get SHA1 hash of " << FilePath);
        return CalculateHashType(HashType::SHA1_HASH);
    }

    std::optional<std::wstring> File::GetSHA256Hash() const {
        LOG_VERBOSE(3, "Attempting to get SHA256 hash of " << FilePath);
        return CalculateHashType(HashType::SHA256_HASH);
    }

    bool File::Create() {
        LOG_VERBOSE(1, "Attempting to create file: " << FilePath);
        if(bFileExists) {
            LOG_ERROR("Can't create " << FilePath << ". File already exists.");
            return false;
        }
        hFile = CreateFileW(FilePath.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW,
                            FILE_FLAG_SEQUENTIAL_SCAN | FILE_ATTRIBUTE_NORMAL, NULL);
        if(INVALID_HANDLE_VALUE == hFile) {
            LOG_ERROR("Error creating file " << FilePath << ". " << SYSTEM_ERROR);
            bFileExists = false;
            return false;
        }
        LOG_VERBOSE(1, FilePath << " successfully created.");
        bFileExists = true;
        bReadAccess = true;
        bWriteAccess = true;
        return true;
    }

    bool File::Delete() {
        LOG_VERBOSE(1, "Attempting to delete file " << FilePath);
        if(!bFileExists) {
            LOG_VERBOSE(2, "Can't delete file " << FilePath << ". File doesn't exist");
            return false;
        }
        CloseHandle(hFile);
        if(!DeleteFileW(FilePath.c_str())) {
            LOG_ERROR("Deleting file " << FilePath << " failed with " << SYSTEM_ERROR);
            hFile = CreateFileW(FilePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW,
                                FILE_FLAG_SEQUENTIAL_SCAN | FILE_ATTRIBUTE_NORMAL, NULL);
            if(INVALID_HANDLE_VALUE == hFile) {
                DWORD dwStatus = GetLastError();
                LOG_ERROR("Couldn't reopen " << FilePath << ". Error = " << dwStatus);
                bFileExists = false;
                return false;
            }
            bFileExists = true;
            return false;
        }
        LOG_VERBOSE(1, FilePath << "deleted.");
        bFileExists = false;
        return true;
    }

    bool FileSystem::File::ChangeFileLength(IN const long length) const {
        SCOPE_LOCK(SetFilePointer(0), ResetFilePointer);
        if(bFileExists) {
            LOG_VERBOSE(2, "Attempting to change length of " << FilePath << " to " << length);

            if(!SetFilePointer(length)) {
                LOG_ERROR("Couldn't change file pointer to " << length << " in file " << FilePath);
                return false;
            }

            if(!SetEndOfFile(hFile)) {
                LOG_ERROR("Couldn't change the length of file " << FilePath);
                return false;
            }
            LOG_VERBOSE(2, "Changed length of " << FilePath << " to " << length);
            return true;
        } else
            return false;
    }

    DWORD64 File::GetFileSize() const {
        DWORD high = {};
        auto size = ::GetFileSize(hFile, &high);
        return (static_cast<DWORD64>(high) << 32) + size;
    }

    std::wstring File::ToString() const { return FilePath; }

    std::optional<Permissions::Owner> File::GetFileOwner() const {
        if(!bFileExists) {
            LOG_VERBOSE(2, "Can't get owner of nonexistent file " << FilePath);
            return std::nullopt;
        }
        PSID psOwnerSID = NULL;
        PISECURITY_DESCRIPTOR pDesc = NULL;
        if(GetSecurityInfo(hFile, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &psOwnerSID, nullptr, nullptr, nullptr,
                           reinterpret_cast<PSECURITY_DESCRIPTOR*>(&pDesc)) != ERROR_SUCCESS) {
            LOG_ERROR("Error getting file owner for file " << FilePath << ". " << SYSTEM_ERROR);
            return std::nullopt;
        }
        pDesc->Owner = psOwnerSID;

        Permissions::SecurityDescriptor secDesc(pDesc);
        return Permissions::Owner(secDesc);
    }

    bool File::SetFileOwner(const Permissions::Owner& owner) {
        if(!bFileExists) {
            LOG_VERBOSE(2, "Can't get owner of nonexistent file " << FilePath);
            SetLastError(ERROR_FILE_NOT_FOUND);
            return false;
        }
        if(!this->bWriteAccess) {
            LOG_WARNING("Can't write owner of file " << FilePath << ". Lack permissions");
            SetLastError(ERROR_ACCESS_DENIED);
            return false;
        }
        if(SetSecurityInfo(hFile, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, owner.GetSID(), nullptr, nullptr,
                           nullptr) != ERROR_SUCCESS) {
            LOG_ERROR("Error setting the file owner for file " << FilePath << " to " << owner << ". " << SYSTEM_ERROR);
            return false;
        }
        LOG_VERBOSE(3, "Set the owner for file " << FilePath << " to " << owner << ".");
        return true;
    }

    ACCESS_MASK File::GetAccessPermissions(const Permissions::Owner& owner) {
        if(!bFileExists) {
            LOG_VERBOSE(2, "Can't get permissions of nonexistent file " << FilePath);
            SetLastError(ERROR_FILE_NOT_FOUND);
            return 0;
        }
        PACL paDACL = NULL;
        PISECURITY_DESCRIPTOR pDesc = NULL;
        if(GetSecurityInfo(hFile, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &paDACL, nullptr,
                           reinterpret_cast<PSECURITY_DESCRIPTOR*>(&pDesc)) != ERROR_SUCCESS) {
            LOG_ERROR("Error getting permissions on file " << FilePath << " for owner " << owner << ". "
                                                           << SYSTEM_ERROR);
            return 0;
        }

        //Correct positional memory of the ACL is weird and doesn't naturally work with the SecurityDescriptor class.
        //This gets the right data to the right place
        Permissions::SecurityDescriptor secDesc = Permissions::SecurityDescriptor::CreateDACL(paDACL->AclSize);
        memcpy(secDesc.GetDACL(), paDACL, paDACL->AclSize);
        LocalFree(pDesc);
        return Permissions::GetOwnerRightsFromACL(owner, secDesc);
    }

    ACCESS_MASK File::GetEveryonePermissions() {
        Permissions::Owner everyone(L"Everyone");
        return this->GetAccessPermissions(everyone);
    }

    bool File::TakeOwnership() {
        std::optional<Permissions::Owner> BluespawnOwner = Permissions::GetProcessOwner();
        if(BluespawnOwner == std::nullopt) {
            return false;
        }
        return this->SetFileOwner(*BluespawnOwner);
    }

    bool File::GrantPermissions(const Permissions::Owner& owner, const ACCESS_MASK& amAccess) {
        return Permissions::UpdateObjectACL(FilePath, SE_FILE_OBJECT, owner, amAccess);
    }

    bool File::DenyPermissions(const Permissions::Owner& owner, const ACCESS_MASK& amAccess) {
        return Permissions::UpdateObjectACL(FilePath, SE_FILE_OBJECT, owner, amAccess, true);
    }

    bool File::Quarantine() {
        if(!bFileExists) {
            LOG_VERBOSE(2, "Can't quarantine file " << FilePath << ". File doesn't exist");
            SetLastError(ERROR_FILE_NOT_FOUND);
            return false;
        }
        ACCESS_MASK amEveryoneDeniedAccess{ 0 };
        Permissions::AccessAddAll(amEveryoneDeniedAccess);
        return DenyPermissions(Permissions::Owner(L"Everyone"), amEveryoneDeniedAccess);
    }

    std::optional<FILETIME> File::GetCreationTime() const {
        if(!bFileExists || !bReadAccess) {
            LOG_VERBOSE(2, "Can't get creation time of " << FilePath << ", file doesn't exist or no read access");
            SetLastError(ERROR_FILE_NOT_FOUND);
            return std::nullopt;
        }
        FILETIME fReturnInfo;
        if(GetFileTime(hFile, &fReturnInfo, nullptr, nullptr)) {
            return fReturnInfo;
        } else {
            LOG_ERROR("Error getting creation time of " << FilePath << ". (Error: " << GetLastError() << ")");
            return std::nullopt;
        }
    }

    std::optional<FILETIME> File::GetModifiedTime() const {
        if(!bFileExists || !bReadAccess) {
            LOG_VERBOSE(2, "Can't get last modified time of " << FilePath << ", file doesn't exist or no read access");
            SetLastError(ERROR_FILE_NOT_FOUND);
            return std::nullopt;
        }
        FILETIME fReturnInfo;
        if(GetFileTime(hFile, nullptr, nullptr, &fReturnInfo)) {
            return fReturnInfo;
        } else {
            LOG_ERROR("Error getting last modified time of " << FilePath << ". " << SYSTEM_ERROR);
            return std::nullopt;
        }
    }

    std::optional<FILETIME> File::GetAccessTime() const {
        if(!bFileExists || !bReadAccess) {
            LOG_VERBOSE(2, "Can't get last access time of " << FilePath << ", file doesn't exist or no read access");
            SetLastError(ERROR_FILE_NOT_FOUND);
            return std::nullopt;
        }
        FILETIME fReturnInfo;
        if(GetFileTime(hFile, nullptr, &fReturnInfo, nullptr)) {
            return fReturnInfo;
        } else {
            LOG_ERROR("Error getting last access time of " << FilePath << ". " << SYSTEM_ERROR);
            return std::nullopt;
        }
    }

    Folder::Folder(const std::wstring& path) : hCurFile{ nullptr } {
        FolderPath = ExpandEnvStringsW(path);
        std::wstring searchName = FolderPath;
        searchName += L"\\*";
        bFolderExists = true;
        bFolderWrite = false;
        auto f = FindFirstFileW(searchName.c_str(), &ffd);
        hCurFile = { f };
        if(hCurFile == INVALID_HANDLE_VALUE) {
            LOG_VERBOSE(2, "Couldn't find folder " << FolderPath);
            bFolderExists = false;
        }
        else{
            if(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY){
                bIsFile = false;
                PSECURITY_DESCRIPTOR pDesc{ nullptr };
                PACL paDACL{ NULL };
                auto status = GetNamedSecurityInfoW(reinterpret_cast<LPCWSTR>(FolderPath.c_str()), SE_FILE_OBJECT,
                                                    DACL_SECURITY_INFORMATION, nullptr, nullptr, &paDACL, nullptr, &pDesc);
                if(status == ERROR_SUCCESS){
                    auto owner = Permissions::GetProcessOwner();
                    Permissions::SecurityDescriptor secDesc = Permissions::SecurityDescriptor::CreateDACL(paDACL->AclSize);
                    memcpy(secDesc.GetDACL(), paDACL, paDACL->AclSize);
                    LocalFree(pDesc);
                    ACCESS_MASK mask = Permissions::GetOwnerRightsFromACL(owner.value(), secDesc);
                    if(Permissions::AccessIncludesWrite(mask)){
                        bFolderWrite = true;
                    }
                }
            } else{
                bIsFile = true;
            }
        }
    }

    std::wstring Folder::GetFolderPath() const { return FolderPath; }

    bool Folder::MoveToNextFile() {
        if(FindNextFileW(hCurFile, &ffd) != 0) {
            if(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                bIsFile = false;
            } else {
                bIsFile = true;
            }
            return true;
        }
        return false;
    }

    bool Folder::MoveToBeginning() {
        std::wstring searchName = FolderPath;
        searchName += L"\\*";
        hCurFile = FindFirstFileW(searchName.c_str(), &ffd);
        if(hCurFile == INVALID_HANDLE_VALUE) {
            LOG_VERBOSE(3, "Cannot move to beginning of nonexistent folder " << FolderPath);
            return false;
        }
        if(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            bIsFile = false;
        } else {
            bIsFile = true;
        }
        return true;
    }

    bool Folder::GetFolderExists() const { return bFolderExists; }

    bool Folder::GetCurIsFile() const { return bIsFile; }

    bool Folder::GetFolderWrite() const { return bFolderWrite; }

    std::optional<File> Folder::Open() const {
        if(bIsFile) {
            std::wstring fileName(ffd.cFileName);
            std::wstring filePath(FolderPath);
            filePath += std::wstring(L"\\") + fileName;
            std::wstring out = filePath.c_str();
            File file = FileSystem::File(out);
            if(file.GetFileExists()) {
                return std::optional<File>{ file };
            }
        }
        return std::nullopt;
    }

    std::optional<Folder> Folder::EnterDir() {
        if(!bIsFile) {
            std::wstring folderName = FolderPath;
            folderName += L"\\";
            folderName += ffd.cFileName;
            Folder folder = Folder(folderName.c_str());
            if(folder.GetFolderExists())
                return folder;
        }
        return std::nullopt;
    }

    std::optional<File> Folder::AddFile(IN const std::wstring& fileName) const {
        std::wstring filePath = FolderPath;
        std::wstring fName = fileName;
        filePath += L"\\" + fName;
        File file = File(filePath.c_str());
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
                if(f->Delete()) {
                    return true;
                }
            }
        }
        return false;
    }

    std::vector<File> Folder::GetFiles(__in_opt std::optional<FileSearchAttribs> attribs, __in_opt int recurDepth) {
        if(MoveToBeginning() == 0) {
            LOG_VERBOSE(2, "Couldn't iterate subfolders of nonexistent folder " << FolderPath);
            return std::vector<File>();
        }
        std::vector<File> toRet = std::vector<File>();
        do {
            if(GetCurIsFile()) {
                std::optional<File> f = Open();
                if(f) {
                    if(!attribs) {
                        toRet.emplace_back(*f);
                    } else {
                        if(f->MatchesAttributes(attribs.value())) {
                            toRet.emplace_back(*f);
                        }
                    }
                }
            } else if(recurDepth != 0 && ffd.cFileName != std::wstring{ L"." } &&
                      ffd.cFileName != std::wstring{ L".." }) {
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

    std::vector<Folder> Folder::GetSubdirectories(__in_opt int recurDepth) {
        if(MoveToBeginning() == 0) {
            LOG_VERBOSE(2, "Couldn't iterate subfolders of nonexistent folder " << FolderPath);
            return {};
        }
        std::vector<Folder> toRet = {};
        do {
            if(!GetCurIsFile() && recurDepth != 0 && ffd.cFileName != std::wstring{ L"." } &&
               ffd.cFileName != std::wstring{ L".." }) {
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

    std::optional<Permissions::Owner> Folder::GetFolderOwner() const {
        if(!bFolderExists) {
            LOG_VERBOSE(2, "Couldn't find owner of nonexistent folder " << FolderPath);
            return std::nullopt;
        }
        PSID psOwnerSID = NULL;
        PISECURITY_DESCRIPTOR pDesc = NULL;
        if(GetNamedSecurityInfoW((LPWSTR) FolderPath.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &psOwnerSID,
                                 nullptr, nullptr, nullptr,
                                 reinterpret_cast<PSECURITY_DESCRIPTOR*>(&pDesc)) != ERROR_SUCCESS) {
            LOG_WARNING("Error getting file owner for folder " << FolderPath << ". " << SYSTEM_ERROR);
            return std::nullopt;
        }
        pDesc->Owner = psOwnerSID;

        Permissions::SecurityDescriptor secDesc(pDesc);
        return Permissions::Owner(secDesc);
    }

    bool Folder::SetFolderOwner(const Permissions::Owner& owner) {
        if(!bFolderExists) {
            LOG_VERBOSE(2, "Couldn't set owner of nonexistent folder " << FolderPath);
            return false;
        }
        if(SetNamedSecurityInfoW((LPWSTR) FolderPath.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
                                 owner.GetSID(), nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            LOG_WARNING("Error setting the folder owner for folder " << FolderPath << " to " << owner << ". "
                                                                     << SYSTEM_ERROR);
            return false;
        }
        LOG_VERBOSE(3, "Set the owner for folder " << FolderPath << " to " << owner << ".");
        return true;
    }

    ACCESS_MASK Folder::GetAccessPermissions(const Permissions::Owner& owner) {
        if(!bFolderExists) {
            LOG_VERBOSE(2, "Couldn't find permissions for nonexistent folder " << FolderPath);
            return 0;
        }
        PACL paDACL = NULL;
        PISECURITY_DESCRIPTOR pDesc = NULL;
        if(GetNamedSecurityInfoW((LPWSTR) FolderPath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr,
                                 nullptr, &paDACL, nullptr,
                                 reinterpret_cast<PSECURITY_DESCRIPTOR*>(&pDesc)) != ERROR_SUCCESS) {
            LOG_WARNING("Error getting permissions on file " << FolderPath << " for owner " << owner
                                                             << ". Error: " << SYSTEM_ERROR);
            return 0;
        }
        //Correct positional memory of the ACL is weird and doesn't naturally work with the SecurityDescriptor class.
        //This gets the right data to the right place
        Permissions::SecurityDescriptor secDesc = Permissions::SecurityDescriptor::CreateDACL(paDACL->AclSize);
        memcpy(secDesc.GetDACL(), paDACL, paDACL->AclSize);
        LocalFree(pDesc);
        return Permissions::GetOwnerRightsFromACL(owner, secDesc);
    }

    ACCESS_MASK Folder::GetEveryonePermissions() {
        Permissions::Owner everyone(L"Everyone");
        return this->GetAccessPermissions(everyone);
    }

    bool Folder::TakeOwnership() {
        std::optional<Permissions::Owner> BluespawnOwner = Permissions::GetProcessOwner();
        if(BluespawnOwner == std::nullopt) {
            return false;
        }
        return this->SetFolderOwner(*BluespawnOwner);
    }
}   // namespace FileSystem
