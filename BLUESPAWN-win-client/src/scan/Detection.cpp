#include <sstream>

#include "util/StringUtils.h"
#include "util/Utils.h"

#include "util/processes/ProcessUtils.h"

#include "scan/Detections.h"

size_t ComputeHash(IN CONST std::map<std::wstring, std::wstring>& map) {
    size_t hash{ 0 };

    std::hash<std::wstring> hasher{};
    for(auto& pair : map) {
        auto first{ hasher(pair.first) };
        auto second{ hasher(pair.second) };
#ifdef _WIN64
        hash = ((hash << 35) | (hash >> 29)) ^ ((first >> 32) | ((first << 32) >> 32)) ^
               ((second << 32) | ((second >> 32) << 32));
#else
        hash = ((hash << 19) | (hash >> 13)) ^ ((first >> 16) | ((first << 16) >> 16)) ^
            ((second << 16) | ((second >> 16) << 16));
#endif
    }

    return hash;
}

size_t ComputeHash(IN CONST std::vector<std::wstring>& values){
    size_t hash{ 0 };

    std::hash<std::wstring> hasher{};
    for(auto& val : values){
        auto first{ hasher(val) };
#ifdef _WIN64
        hash = ((hash << 35) | (hash >> 29)) ^ ((first >> 32) | ((first << 32) >> 32));
#else
        hash = ((hash << 19) | (hash >> 14)) ^ ((first >> 16) | ((first << 16) >> 16));
#endif
    }

    return hash;
}

ProcessDetectionData
ProcessDetectionData::CreateImageDetectionData(IN DWORD PID,
                                               IN CONST std::wstring& ProcessName,
                                               IN CONST std::wstring& ImageName,
                                               IN CONST std::optional<PVOID64>& BaseAddress OPTIONAL,
                                               IN CONST std::optional<DWORD>& MemorySize OPTIONAL,
                                               IN CONST std::optional<std::wstring>& ProcessPath OPTIONAL,
                                               IN CONST std::optional<std::wstring>& ProcessCommand OPTIONAL,
                                               IN std::unique_ptr<ProcessDetectionData>&& ParentProcess OPTIONAL) {
    HandleWrapper hProcess{ OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, PID) };
    if(hProcess) {
        return CreateImageDetectionData(hProcess, ProcessName, ImageName, BaseAddress, MemorySize, ProcessPath,
                                        ProcessCommand, std::move(ParentProcess));
    } else {
        return ProcessDetectionData{
            ProcessDetectionType::MaliciousMemory,
            PID,                        // PID
            std::nullopt,               // TID
            std::nullopt,               // ProcessHandle
            ProcessName,                // ProcessName
            ProcessPath,                // ProcessPath
            ProcessCommand,             // ProcessCommand
            std::move(ParentProcess),   // ParentProcess
            BaseAddress,                // BaseAddress
            MemorySize,                 // MemorySize
            ImageName                   // ImageName
        };
    }
}

ProcessDetectionData
ProcessDetectionData::CreateImageDetectionData(IN CONST HandleWrapper& ProcessHandle,
                                               IN CONST std::wstring& ProcessName,
                                               IN CONST std::wstring& ImageName,
                                               IN CONST std::optional<PVOID64>& BaseAddress OPTIONAL,
                                               IN CONST std::optional<DWORD>& MemorySize OPTIONAL,
                                               IN CONST std::optional<std::wstring>& ProcessPath OPTIONAL,
                                               IN CONST std::optional<std::wstring>& ProcessCommand OPTIONAL,
                                               IN std::unique_ptr<ProcessDetectionData>&& ParentProcess OPTIONAL) {
    auto addr{ BaseAddress ? *BaseAddress : GetModuleAddress(ProcessHandle, ImageName) };

    return ProcessDetectionData{
        ProcessDetectionType::MaliciousImage,                                     // type
        GetProcessId(ProcessHandle),                                              // PID
        std::nullopt,                                                             // TID
        ProcessHandle,                                                            // ProcessHandle
        ProcessName,                                                              // ProcessName
        ProcessPath ? ProcessPath : GetProcessImage(ProcessHandle),               // ProcessPath
        ProcessCommand ? ProcessCommand : GetProcessCommandline(ProcessHandle),   // ProcessCommand
        std::move(ParentProcess),                                                 // ParentProcess
        addr,                                                                     // BaseAddress
        MemorySize ? MemorySize : GetRegionSize(ProcessHandle, addr),             // MemorySize
        ImageName                                                                 // ImageName
    };
}

ProcessDetectionData
ProcessDetectionData::CreateProcessDetectionData(IN DWORD PID,
                                                 IN CONST std::wstring& ProcessName,
                                                 IN CONST std::optional<std::wstring>& ProcessPath OPTIONAL,
                                                 IN CONST std::optional<std::wstring>& ProcessCommand OPTIONAL,
                                                 IN std::unique_ptr<ProcessDetectionData>&& ParentProcess OPTIONAL) {
    HandleWrapper hProcess{ OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, PID) };
    if(hProcess) {
        return CreateProcessDetectionData(hProcess, ProcessName, ProcessPath, ProcessCommand, std::move(ParentProcess));
    } else {
        return ProcessDetectionData{
            ProcessDetectionType::MaliciousProcess,
            PID,                        // PID
            std::nullopt,               // TID
            std::nullopt,               // ProcessHandle
            ProcessName,                // ProcessName
            ProcessPath,                // ProcessPath
            ProcessCommand,             // ProcessCommand
            std::move(ParentProcess),   // ParentProcess
            std::nullopt,               // BaseAddress
            std::nullopt,               // MemorySize
            std::nullopt                // ImageName
        };
    }
}

ProcessDetectionData ProcessDetectionData::CreateCommandDetectionData(IN CONST std::wstring& ProcessCommand) {
    return ProcessDetectionData{
        ProcessDetectionType::MaliciousCommand,
        std::nullopt,     // PID
        std::nullopt,     // TID
        std::nullopt,     // ProcessHandle
        std::nullopt,     // ProcessName
        std::nullopt,     // ProcessPath
        ProcessCommand,   // ProcessCommand
        nullptr,          // ParentProcess
        std::nullopt,     // MemorySize
        std::nullopt,     // BaseAddress
        std::nullopt      // ImageName
    };
}

ProcessDetectionData
ProcessDetectionData::CreateProcessDetectionData(IN CONST HandleWrapper& ProcessHandle,
                                                 IN CONST std::wstring& ProcessName,
                                                 IN CONST std::optional<std::wstring>& ProcessPath OPTIONAL,
                                                 IN CONST std::optional<std::wstring>& ProcessCommand OPTIONAL,
                                                 IN std::unique_ptr<ProcessDetectionData>&& ParentProcess OPTIONAL) {
    return ProcessDetectionData{
        ProcessDetectionType::MaliciousProcess,                                   // type
        GetProcessId(ProcessHandle),                                              // PID
        std::nullopt,                                                             // TID
        ProcessHandle,                                                            // ProcessHandle
        ProcessName,                                                              // ProcessName
        ProcessPath ? ProcessPath : GetProcessImage(ProcessHandle),               // ProcessPath
        ProcessCommand ? ProcessCommand : GetProcessCommandline(ProcessHandle),   // ProcessCommand
        std::move(ParentProcess),                                                 // ParentProcess
        std::nullopt,                                                             // BaseAddress
        std::nullopt,                                                             // MemorySize
        std::nullopt                                                              // ImageName
    };
}

ProcessDetectionData
ProcessDetectionData::CreateMemoryDetectionData(IN DWORD PID,
                                                IN CONST std::wstring& ProcessName,
                                                IN PVOID64 BaseAddress,
                                                IN DWORD MemorySize,
                                                IN CONST std::optional<std::wstring>& ImageName OPTIONAL,
                                                IN CONST std::optional<std::wstring>& ProcessPath OPTIONAL,
                                                IN CONST std::optional<std::wstring>& ProcessCommand OPTIONAL,
                                                IN std::unique_ptr<ProcessDetectionData>&& ParentProcess OPTIONAL) {
    HandleWrapper hProcess{ OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, PID) };
    if(hProcess) {
        return CreateMemoryDetectionData(hProcess, ProcessName, BaseAddress, MemorySize, ImageName, ProcessPath,
                                         ProcessCommand, std::move(ParentProcess));
    } else {
        auto image{ ImageName };
        if(image && !image->length()){
            image = std::nullopt;
        }
        return ProcessDetectionData{
            ProcessDetectionType::MaliciousMemory,
            PID,                        // PID
            std::nullopt,               // TID
            std::nullopt,               // ProcessHandle
            ProcessName,                // ProcessName
            ProcessPath,                // ProcessPath
            ProcessCommand,             // ProcessCommand
            std::move(ParentProcess),   // ParentProcess
            BaseAddress,                // BaseAddress
            MemorySize,                 // MemorySize
            image                       // ImageName
        };
    }
}

ProcessDetectionData
ProcessDetectionData::CreateMemoryDetectionData(IN CONST HandleWrapper& ProcessHandle,
                                                IN CONST std::wstring& ProcessName,
                                                IN PVOID64 BaseAddress,
                                                IN DWORD MemorySize,
                                                IN CONST std::optional<std::wstring>& ImageName OPTIONAL,
                                                IN CONST std::optional<std::wstring>& ProcessPath OPTIONAL,
                                                IN CONST std::optional<std::wstring>& ProcessCommand OPTIONAL,
                                                IN std::unique_ptr<ProcessDetectionData>&& ParentProcess OPTIONAL) {
    std::optional<std::wstring> image{ ImageName };
    if(!image) {
        auto mapped{ GetMappedFile(ProcessHandle, BaseAddress) };
        if(mapped) { image = mapped->GetFilePath(); }
    }
    if(image && !image->length()){
        image = std::nullopt;
    }

    return ProcessDetectionData{
        ProcessDetectionType::MaliciousMemory,                                    // type
        GetProcessId(ProcessHandle),                                              // PID
        std::nullopt,                                                             // TID
        ProcessHandle,                                                            // ProcessHandle
        ProcessName,                                                              // ProcessName
        ProcessPath ? ProcessPath : GetProcessImage(ProcessHandle),               // ProcessPath
        ProcessCommand ? ProcessCommand : GetProcessCommandline(ProcessHandle),   // ProcessCommand
        std::move(ParentProcess),                                                 // ParentProcess
        BaseAddress,                                                              // BaseAddress
        MemorySize,                                                               // MemorySize
        image                                                                     // ImageName
    };
}

ProcessDetectionData::ProcessDetectionData(IN ProcessDetectionType type,
                                           IN CONST std::optional<DWORD> PID,
                                           IN CONST std::optional<DWORD>& TID,
                                           IN CONST std::optional<HandleWrapper>& ProcessHandle,
                                           IN CONST std::optional<std::wstring>& ProcessName,
                                           IN CONST std::optional<std::wstring>& ProcessPath,
                                           IN CONST std::optional<std::wstring>& ProcessCommand,
                                           IN std::unique_ptr<ProcessDetectionData>&& ParentProcess,
                                           IN CONST std::optional<PVOID64>& BaseAddress,
                                           IN CONST std::optional<DWORD>& MemorySize,
                                           IN CONST std::optional<std::wstring>& ImageName) :
    type{ type },
    PID{ PID }, TID{ TID }, ProcessHandle{ ProcessHandle }, ProcessName{ ProcessName }, ProcessPath{ ProcessPath },
    ProcessCommand{ ProcessCommand }, ParentProcess{ std::move(ParentProcess) }, BaseAddress{ BaseAddress },
    MemorySize{ MemorySize }, ImageName{ ImageName } {
    auto tied{ std::tie(type, PID, TID, ProcessHandle, ProcessName, ProcessPath, ProcessCommand, ParentProcess,
                        BaseAddress, MemorySize, ImageName) };

    serialization = std::map<std::wstring, std::wstring>{
        { L"Type", type == ProcessDetectionType::MaliciousImage ?
                       L"Image" :
                       type == ProcessDetectionType::MaliciousMemory ?
                       L"Memory" :
                       type == ProcessDetectionType::MaliciousProcess ? L"Process" : L"Command" },
    };
    if(PID) serialization.emplace(L"PID", std::to_wstring(*PID));
    if(TID) serialization.emplace(L"TID", std::to_wstring(*TID));
    if(ProcessName) serialization.emplace(L"Process Name", *ProcessName);
    if(ProcessPath) serialization.emplace(L"Process Path", *ProcessPath);
    if(ProcessCommand) serialization.emplace(L"Process Command", *ProcessCommand);
    if(ParentProcess && ParentProcess->PID) serialization.emplace(L"Parent PID", std::to_wstring(*ParentProcess->PID));
    if(BaseAddress) {
        std::wstringstream wss{};
        wss << std::hex << *BaseAddress;
        serialization.emplace(L"Base Address", wss.str());
    }
    if(MemorySize) serialization.emplace(L"Memory Size", std::to_wstring(*MemorySize));
    if(ImageName) serialization.emplace(L"Image Name", *ImageName);

    hash = ComputeHash(serialization);
}

const std::map<std::wstring, std::wstring>& ProcessDetectionData::Serialize() CONST {
    return serialization;
}

size_t ProcessDetectionData::Hash() CONST {
    return hash;
}

bool ProcessDetectionData::operator==(IN CONST ProcessDetectionData& data) CONST {
    if(type != data.type){
        return false;
    }
    if(type == ProcessDetectionType::MaliciousCommand){
        return *ProcessCommand == *data.ProcessCommand;
    } else if(type == ProcessDetectionType::MaliciousImage){
        return *PID == *data.PID && *ImageName == *data.ImageName;
    } else if(type == ProcessDetectionType::MaliciousMemory){
        return *PID == *data.PID && *BaseAddress == *data.BaseAddress;
    } else{
        return *PID == *data.PID;
    }
}

FileDetectionData::FileDetectionData(IN CONST FileSystem::File& file,
                                     IN CONST std::optional<YaraScanResult>& scan OPTIONAL) :
    FileFound{ file.GetFileExists() },
    FilePath{ file.GetFilePath() }, FileName{ FilePath.find(L"\\/") == std::wstring::npos ?
                                                  FilePath :
                                                  FilePath.substr(FilePath.find_last_of(L"\\/")) },
    FileExtension{ file.GetFileAttribs().extension },
    FileHandle{ file }, MD5{ file.GetMD5Hash() }, SHA1{ file.GetSHA1Hash() }, SHA256{ file.GetSHA256Hash() },
    LastOpened{ file.GetAccessTime() }, FileCreated{ file.GetCreationTime() },
    yara{ scan ?
              scan :
              (FileFound ? std::optional<YaraScanResult>(YaraScanner::GetInstance().ScanFile(file)) : std::nullopt) },
    FileSigned{ FileFound ? std::optional<bool>(file.GetFileSigned()) : std::nullopt }, Signer{
        FileSigned && *FileSigned ? file.GetCertificateIssuer() : std::nullopt
    } {
    if(FileExtension) {
        Registry::RegistryKey FileExtClass{ HKEY_CLASSES_ROOT, *FileExtension };
        if(FileExtClass.Exists() && FileExtClass.ValueExists(L"")) {
            FileType = FileExtClass.GetValue<std::wstring>(L"");
            if(FileType) {
                Registry::RegistryKey FileClass{ HKEY_CLASSES_ROOT, *FileType };
                if(FileClass.Exists()) {
                    Registry::RegistryKey shell{ FileClass, L"shell\\open\\command" };
                    auto command{ shell.GetValue<std::wstring>(L"") };
                    if(command) { 
                        Executor = StringReplaceW(StringReplaceW(*command, L"%1", FilePath), L"%*", L"");
                    }
                }
            }
        }
    }

    serialization = std::map<std::wstring, std::wstring>{
        { L"Path", FilePath },
        { L"Name", FileName },
        { L"Exists", FileFound ? L"true" : L"false" },
    };
    if(FileExtension) serialization.emplace(L"Extension", *FileExtension);
    if(FileType) serialization.emplace(L"File Type", *FileType);
    if(Executor) serialization.emplace(L"File Executor", *Executor);
    if(MD5) serialization.emplace(L"MD5 Hash", *MD5);
    if(SHA1) serialization.emplace(L"SHA1 Hash", *SHA1);
    if(SHA256) serialization.emplace(L"SHA256 Hash", *SHA256);
    if(LastOpened) serialization.emplace(L"Last Opened", FormatWindowsTime(*LastOpened));
    if(FileCreated) serialization.emplace(L"Date Created", FormatWindowsTime(*FileCreated));
    if(yara) {
        std::wstring malicious{};
        for(auto& mal : yara->vKnownBadRules) {
            if(malicious.length()) malicious += L", ";
            malicious += mal;
        }
        std::wstring identifier{};
        for(auto& id : yara->vIndicatorRules) {
            if(identifier.length()) identifier += L", ";
            identifier += id;
        }
        serialization.emplace(L"Malicious Yara Rules", malicious);
        serialization.emplace(L"Other Yara Rules", identifier);
    }
    if(FileSigned) serialization.emplace(L"Signed", *FileSigned ? L"true" : L"false");
    if(Signer) serialization.emplace(L"Signer", *Signer);

    hash = ComputeHash(std::vector<std::wstring>{ FilePath, SHA256 ? *SHA256 : L"" });
}

FileDetectionData::FileDetectionData(IN CONST std::wstring& path) :
    FileDetectionData(FileSystem::File{ path }, std::nullopt) {}

const std::map<std::wstring, std::wstring>& FileDetectionData::Serialize() CONST {
    return serialization;
}

size_t FileDetectionData::Hash() CONST {
    return hash;
}

bool FileDetectionData::operator==(IN CONST FileDetectionData& data) const {
    if(data.SHA256 != SHA256) { return false; }
    return FilePath == data.FilePath;
}

RegistryDetectionData::RegistryDetectionData(IN CONST Registry::RegistryKey& key,
                                             IN CONST std::optional<Registry::RegistryValue>& value OPTIONAL,
                                             IN RegistryDetectionType type OPTIONAL,
                                             IN CONST std::optional<AllocationWrapper>& data OPTIONAL) :
    KeyPath{ key.GetName() },
    key{ key }, value{ value }, type{ type }, data{ data } {
    serialization = std::map<std::wstring, std::wstring>{
        { L"Key Path", key.GetName() },
        { L"Registry Entry Type", type == RegistryDetectionType::CommandReference ?
                                      L"Command" :
                                      type == RegistryDetectionType::Configuration ?
                                      L"Configuration" :
                                      type == RegistryDetectionType::FileReference ?
                                      L"File" :
                                      type == RegistryDetectionType::FolderReference ?
                                      L"Folder" :
                                      type == RegistryDetectionType::PipeReference ?
                                      L"Pipe" :
                                      type == RegistryDetectionType::ShareReference ?
                                      L"Share" :
                                      type == RegistryDetectionType::UserReference ? L"User" : L"Unknown" }
    };
    if(value) {
        serialization.emplace(L"Key Value Name", value->wValueName);
        serialization.emplace(L"Key Value Data", value->ToString());
    }

    hash = ComputeHash(std::vector<std::wstring>{ KeyPath, value ? value->wValueName : L"" });
}

RegistryDetectionData::RegistryDetectionData(IN CONST Registry::RegistryValue& value,
                                             IN RegistryDetectionType type OPTIONAL) :
    RegistryDetectionData{ value.key, value, type, value.key.GetRawValue(value.wValueName) } {}

const std::map<std::wstring, std::wstring>& RegistryDetectionData::Serialize() CONST {
    return serialization;
}

size_t RegistryDetectionData::Hash() CONST {
    return hash;
}

bool RegistryDetectionData::operator==(IN CONST RegistryDetectionData& data) CONST {
    return KeyPath == data.KeyPath && value->wValueName == data.value->wValueName;
}

ServiceDetectionData::ServiceDetectionData(IN CONST std::optional<std::wstring>& ServiceName OPTIONAL,
                                           IN CONST std::optional<std::wstring>& DisplayName OPTIONAL,
                                           IN CONST std::optional<std::wstring>& FilePath OPTIONAL,
                                           IN CONST std::optional<std::wstring>& Description OPTIONAL) :
    ServiceName{ ServiceName },
    DisplayName{ DisplayName }, FilePath{ FilePath }, Description{ Description } {
    serialization = std::map<std::wstring, std::wstring>{};
    if(ServiceName) { serialization.emplace(L"Service Name", *ServiceName); }
    if(FilePath) { serialization.emplace(L"Service Executable", *FilePath); }
    if(DisplayName) { serialization.emplace(L"Display Name", *DisplayName); }
    if(Description) { serialization.emplace(L"Description", *Description); }

    hash = ComputeHash(serialization);
}

const std::map<std::wstring, std::wstring>& ServiceDetectionData::Serialize() CONST {
    return serialization;
}

size_t ServiceDetectionData::Hash() CONST {
    return hash;
}

OtherDetectionData::OtherDetectionData(IN CONST std::wstring& DetectionType,
                                       IN CONST std::map<std::wstring, std::wstring>& DetectionProperties) :
    DetectionType{ DetectionType },
    DetectionProperties{ DetectionProperties }, serialization(DetectionProperties.begin(), DetectionProperties.end()) {
    serialization.emplace(L"Detection Type", DetectionType);
    hash = ComputeHash(serialization);
}

const std::map<std::wstring, std::wstring>& OtherDetectionData::Serialize() CONST {
    return serialization;
}

size_t OtherDetectionData::Hash() CONST {
    return hash;
}

DetectionContext::DetectionContext(IN CONST std::optional<std::wstring>& hunt OPTIONAL,
                                   IN CONST std::optional<FILETIME>& FirstEvidenceTime OPTIONAL,
                                   IN CONST std::optional<std::wstring>& note OPTIONAL) :
    FirstEvidenceTime{ FirstEvidenceTime },
    note{ note } {
    if(hunt) hunts.emplace(*hunt);

    GetSystemTimeAsFileTime(&DetectionCreatedTime);
}

decltype(Detection::serializer) Detection::serializer{};
decltype(Detection::hasher) Detection::hasher{};

Detection::Detection(IN CONST DetectionData& data,
                     IN CONST std::optional<DetectionContext>& context OPTIONAL,
                     IN CONST std::optional<std::function<void()>>& remediator OPTIONAL,
                     IN bool DetectionStale OPTIONAL) :
    data{ data },
    DetectionStale{ DetectionStale }, type{ DetectionType::OtherDetection }, dwID{ IDCounter++ },
    remediator{ remediator }, context{ context ? *context : DetectionContext{} } {
    if(data.index() == 0) {
        type = DetectionType::ProcessDetection;
    } else if(data.index() == 1) {
        type = DetectionType::FileDetection;
    } else if(data.index() == 2) {
        type = DetectionType::RegistryDetection;
    } else if(data.index() == 3) {
        type = DetectionType::ServiceDetection;
    }

    hash = std::visit(hasher, data);
    auto tmp{ std::visit(serializer, data) };
    serialization = std::map<std::wstring, std::wstring>(tmp.begin(), tmp.end());
}

Detection::Detection(IN CONST Detection& detection) :
    data{ detection.data }, DetectionStale{ detection.DetectionStale }, type{ detection.type }, dwID{ detection.dwID },
    remediator{ detection.remediator }, context{ detection.context }, hash{ detection.hash }, 
    serialization{ detection.serialization } {
    info.associations = std::make_unique<std::unordered_map<std::shared_ptr<Detection>, Association>>(
        *detection.info.associations);
    info.bAssociativeStale = detection.info.bAssociativeStale;
    info.cAssociativeCertainty = detection.info.cAssociativeCertainty;
    info.certainty = detection.info.certainty;
}

Detection& Detection::operator=(IN CONST Detection& detection) {
    data = detection.data;
    DetectionStale = detection.DetectionStale;
    type = detection.type;
    dwID = detection.dwID;
    remediator = detection.remediator;
    context = detection.context;
    hash = detection.hash;
    serialization = detection.serialization;
    info = {};
    info.associations = std::make_unique<std::unordered_map<std::shared_ptr<Detection>, Association>>(
        *detection.info.associations);
    info.bAssociativeStale = detection.info.bAssociativeStale;
    info.cAssociativeCertainty = detection.info.cAssociativeCertainty;
    info.certainty = detection.info.certainty;
    return *this;
}

bool Detection::operator==(IN CONST Detection& detection) CONST {
    if(type != detection.type) { return false; }

    if(type == DetectionType::ProcessDetection) {
        return std::get<ProcessDetectionData>(data) == std::get<ProcessDetectionData>(detection.data);
    } else if(type == DetectionType::ServiceDetection) {
        return std::get<ServiceDetectionData>(data) == std::get<ServiceDetectionData>(detection.data);
    } else if(type == DetectionType::RegistryDetection) {
        return std::get<RegistryDetectionData>(data) == std::get<RegistryDetectionData>(detection.data);
    } else if(type == DetectionType::FileDetection) {
        return std::get<FileDetectionData>(data) == std::get<FileDetectionData>(detection.data);
    } else {
        return std::get<OtherDetectionData>(data) == std::get<OtherDetectionData>(detection.data);
    }
}

Detection::operator PCRITICAL_SECTION() {
    return hGuard;
}

Detection::operator CriticalSection(){
    return hGuard;
}

const std::map<std::wstring, std::wstring>& Detection::Serialize() CONST {
    return serialization;
};

size_t std::hash<Detection>::operator()(IN CONST Detection& detection) CONST {
    return detection.hash;
}

size_t
std::hash<std::shared_ptr<Detection>>::operator()(IN CONST std::shared_ptr<Detection>& detection) CONST {
    return detection->hash;
}

bool std::equal_to<std::shared_ptr<Detection>>::operator()(
    IN CONST std::shared_ptr<Detection>& _Left, IN CONST std::shared_ptr<Detection>& _Right) CONST {
    return *_Left == *_Right;
}
