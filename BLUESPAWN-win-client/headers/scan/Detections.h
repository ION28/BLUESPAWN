#pragma once

#include <Windows.h>

#include <string>
#include <functional>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <atomic>

#include "util/configurations/RegistryValue.h"
#include "util/configurations/Registry.h"
#include "util/filesystem/FileSystem.h"
#include "scan/YaraScanner.h"
#include "scan/ScanInfo.h"

/// Identifies the type of detection a Detection object represents
enum class DetectionType {
	ProcessDetection,
	RegistryDetection,
	FileDetection,
	ServiceDetection,
	OtherDetection,
};

/// Describes the type of registry entry associated with a RegistryDetectionData object
enum class RegistryDetectionType {
	CommandReference, // The associated value is either a REG_SZ or REG_EXPAND_SZ that references a command used to run
	                  // a program
	FileReference,    // The associated value is either a REG_SZ or REG_EXPAND_SZ that references a file
	FolderReference,  // The associated value is either a REG_SZ or REG_EXPAND_SZ that references a folder
	PipeReference,    // The associated value is either a REG_SZ that references a named pipe
	ShareReference,   // The associated value is either a REG_SZ that references a share
	UserReference,    // The associated value is either a REG_SZ that references a user
	Configuration,    // The associated value references a configuration for the operating system
	Unknown,          // The associated value is assumed malicious, though its usage is unknown
};

/// Describes the type of detection is associated with a ProcessDetectionData object
enum class ProcessDetectionType {
	MaliciousProcess, // Refers to the process itself rather than something within it
	MaliciousImage,   // Refers to a specific image within the process
	MaliciousMemory,  // Refers to a location in memory of the process
	MaliciousCommand, // Refers to a command to be used to spawn a process. If a specific process is identified,
	                  // the type should be MaliciousProcess instead
};

/**
 * Stores information about a process or memory location identified as possibly malicious
 */
struct ProcessDetectionData {

	/// Describes the type of detection is associated with this
	ProcessDetectionType type;

	/// The process ID of the process
	std::optional<DWORD> PID;

	/// The thread IDs of the threads within the process that triggered the detection. 
	/// This will rarely be used.
	std::optional<DWORD> TID;

	/// An open handle to the process
	std::optional<HandleWrapper> ProcessHandle;

	/// The name of the process
	std::optional<std::wstring> ProcessName;

	/// The path to the executable image of the process
	std::optional<std::wstring> ProcessPath;

	/// The command used to spawn the process
	std::optional<std::wstring> ProcessCommand;

	/// The parent of the process
	std::optional<std::shared_ptr<ProcessDetectionData>> ParentProcess;

	/// The base address of the potentially malicious memory segment inside the process
	std::optional<PVOID64> BaseAddress;

	/// The size of the potentially malicious memory segment
	std::optional<DWORD> MemorySize;

	/// The name of the image in memory being referenced by the detection. 
	std::optional<std::wstring> ImageName;

	/**
	 * Instantiates a ProcessDetectionData object representing a malicious image loaded in
	 * to a process. This constructor is intended to be used primarily when a handle to the
	 * process is infeasible to obtain. Note that this constructor is intended to be used 
	 * when a loaded libary is determined to be malicious, not when the library is infected,
	 * hooked, stomped, hollowed, doppelganged, or similar. No arguments will be deduced
	 * when using this constructor.
	 * 
	 * @param PID The process ID of the process
	 * @param ProcessName The name of the process
	 * @param ImageName The name of the image in memory being referenced by the detection
	 * @param BaseAddress The base address of the image in memory
	 * @param MemorySize The size of the image in memory
	 * @param ProcessPath The path to the executable image of the process
	 * @param ProcessCommand The command used to spawn the process
	 * @param ParentProcess An pointer to a ProcessDetectionData struct containing information
	 *        on the parent process.
	 */
	static ProcessDetectionData CreateImageDetectionData(
		IN DWORD PID,
		IN CONST std::wstring& ProcessName,
		IN CONST std::wstring& ImageName,
		IN CONST std::optional<PVOID64>& BaseAddress = std::nullopt OPTIONAL,
		IN CONST std::optional<DWORD>& MemorySize = std::nullopt OPTIONAL,
		IN CONST std::optional<std::wstring>& ProcessPath = std::nullopt OPTIONAL,
		IN CONST std::optional<std::wstring>& ProcessCommand = std::nullopt OPTIONAL,
		IN std::unique_ptr<ProcessDetectionData>&& ParentProcess = nullptr OPTIONAL
	);

	/**
	 * Instantiates a ProcessDetectionData object representing a malicious image loaded in
	 * to a process. This constructor is intended to be used whenever a handle is available.
	 * Most of the arguments can be calculated, though if they are available, passing them
	 * improves efficiency. Note that this constructor is intended to be used when a loaded
	 * libary is determined to be malicious, not when the library is infected, hooked, stomped, 
	 * hollowed, doppelganged, or similar.
	 *
	 * @param PID The process ID of the process
	 * @param ProcessName The name of the process
	 * @param ImageName The name of the image in memory being referenced by the detection
	 * @param BaseAddress The base address of the image in memory. If skipped, this will be 
     *		  automatically deduced
	 * @param MemorySize The size of the image in memory. If skipped, this will be automatically
     *		  deduced
	 * @param ProcessPath The path to the executable image of the process. If skipped, this will 
     *		  be automatically deduced
	 * @param ProcessCommand The command used to spawn the process. If skipped, this will be 
     *		  automatically deduced
	 * @param ParentProcess An pointer to a ProcessDetectionData struct containing information
	 *        on the parent process. If skipped, this will be automatically deduced
	 */
	static ProcessDetectionData CreateImageDetectionData(
		IN CONST HandleWrapper& ProcessHandle,
		IN CONST std::wstring& ProcessName,
		IN CONST std::wstring& ImageName,
		IN CONST std::optional<PVOID64>& BaseAddress = std::nullopt OPTIONAL,
		IN CONST std::optional<DWORD>& MemorySize = std::nullopt OPTIONAL,
		IN CONST std::optional<std::wstring>& ProcessPath = std::nullopt OPTIONAL,
		IN CONST std::optional<std::wstring>& ProcessCommand = std::nullopt OPTIONAL,
		IN std::unique_ptr<ProcessDetectionData>&& ParentProcess = nullptr OPTIONAL
	);

	/**
	 * 
	 * This constructor is intended to be used primarily when a handle to the process is
	 * infeasible to obtain. This constructor generally will be used when there is little other
	 * information available as to what specifically is malicious or when the process is
	 * achieving a malicious purpose even though each image inside is benign (as with powershell).
	 *
	 * @param PID The process ID of the process
	 * @param ProcessName The name of the process
	 * @param ProcessPath The path to the executable image of the process
	 * @param ProcessCommand The command used to spawn the process
	 * @param ParentProcess An pointer to a ProcessDetectionData struct containing information
	 *        on the parent process.
	 */
	static ProcessDetectionData CreateProcessDetectionData(
		IN DWORD PID,
		IN CONST std::wstring& ProcessName,
		IN CONST std::optional<std::wstring>& ProcessPath = std::nullopt OPTIONAL,
		IN CONST std::optional<std::wstring>& ProcessCommand = std::nullopt OPTIONAL,
		IN std::unique_ptr<ProcessDetectionData>&& ParentProcess = nullptr OPTIONAL
	);

	/**
	 * Instantiates a ProcessDetectionData object representing a process which may be malicious. 
	 * This constructor is intended to be used whenever a handle is available. Most of the 
	 * arguments can be calculated, though if they are available, passing them improves efficiency. 
	 * This constructor generally will be used when there is little other information available as 
	 * to what specifically is malicious or when the process is achieving a malicious purpose even 
	 * though each image inside is benign (as with powershell).
	 *
	 * @param PID The process ID of the process
	 * @param ProcessName The name of the process
	 * @param ProcessPath The path to the executable image of the process. If skipped, this will
	 *		  be automatically deduced
	 * @param ProcessCommand The command used to spawn the process. If skipped, this will be
	 *		  automatically deduced
	 * @param ParentProcess An pointer to a ProcessDetectionData struct containing information
	 *        on the parent process. If skipped, this will be automatically deduced
	 */
	static ProcessDetectionData CreateProcessDetectionData(
		IN CONST HandleWrapper& ProcessHandle,
		IN CONST std::wstring& ProcessName,
		IN CONST std::optional<std::wstring>& ProcessPath = std::nullopt OPTIONAL,
		IN CONST std::optional<std::wstring>& ProcessCommand = std::nullopt OPTIONAL,
		IN std::unique_ptr<ProcessDetectionData>&& ParentProcess = nullptr OPTIONAL
	);

	/**
	 * Instantiates a ProcessDetectionData object representing a malicious memory section loaded in to a process. This 
	 * constructor is intended to be used primarily when a handle to the process is infeasible to obtain. Note that 
	 * this constructor is intended to be used when the library is infected, hooked, stomped, hollowed, doppelganged, 
	 * or similar, not when a loaded libary is determined to be malicious. No arguments will be deduced when using this
	 * constructor.
	 *
	 * @param PID The process ID of the process
	 * @param ProcessName The name of the process
	 * @param BaseAddress The base address of the memory section
	 * @param MemorySize The size of the memory section
	 * @param ImageName The name of the image in memory being referenced by the detection
	 * @param ProcessPath The path to the executable image of the process
	 * @param ProcessCommand The command used to spawn the process
	 * @param ParentProcess An pointer to a ProcessDetectionData struct containing information on the parent process
	 */
	static ProcessDetectionData CreateMemoryDetectionData(
		IN DWORD PID,
		IN CONST std::wstring& ProcessName,
		IN PVOID64 BaseAddress,
		IN DWORD MemorySize,
		IN CONST std::optional<std::wstring>& ImageName = std::nullopt OPTIONAL,
		IN CONST std::optional<std::wstring>& ProcessPath = std::nullopt OPTIONAL,
		IN CONST std::optional<std::wstring>& ProcessCommand = std::nullopt OPTIONAL,
		IN std::unique_ptr<ProcessDetectionData>&& ParentProcess = nullptr OPTIONAL
	);

	/**
	 * Instantiates a ProcessDetectionData object representing a malicious memory section loaded in to a process. This 
	 * constructor is intended to be used whenever a handle is available. Most of the arguments can be calculated, 
	 * though if they are available, passing them improves efficiency. Note that this constructor is intended to be 
	 * used when the library is infected, hooked, stomped, hollowed, doppelganged, or similar, not when a loaded libary
	 * is determined to be malicious.
	 *
	 * @param ProcessHandle An open handle to the process
	 * @param ProcessName The name of the process
	 * @param BaseAddress The base address of the memory section
	 * @param MemorySize The size of the memory section
	 * @param ImageName The name of the image in memory being referenced by the detection. If skipped, this will be 
	 *        automatically deduced if possible.
	 * @param ProcessPath The path to the executable image of the process. If skipped, this will be automatically 
	 *        deduced
	 * @param ProcessCommand The command used to spawn the process. If skipped, this will be automatically deduced
	 * @param ParentProcess An pointer to a ProcessDetectionData struct containing information on the parent process. 
	 *        If skipped, this will be automatically deduced
	 */
	static ProcessDetectionData CreateMemoryDetectionData(
		IN CONST HandleWrapper& ProcessHandle,
		IN CONST std::wstring& ProcessName,
		IN PVOID64 BaseAddress,
		IN DWORD MemorySize,
		IN CONST std::optional<std::wstring>& ImageName = std::nullopt OPTIONAL,
		IN CONST std::optional<std::wstring>& ProcessPath = std::nullopt OPTIONAL,
		IN CONST std::optional<std::wstring>& ProcessCommand = std::nullopt OPTIONAL,
		IN std::unique_ptr<ProcessDetectionData>&& ParentProcess = nullptr OPTIONAL
	);

	/**
	 * Instantiates a ProcessDetectionData object representing a malicious command used to spawn a process.
	 *
	 * @param ProcessCommand The command used to spawn a process
	 */
	static ProcessDetectionData CreateCommandDetectionData(
		IN CONST std::wstring& ProcessCommand
	);

	/**
	 * Serialize the detection data in to a mapping of values. Note this should not include any internal representations
	 * but rather only include values that have meaning outside of BLUESPAWN's running.
	 *
	 * @return A mapping of properties to human-readable values
	 */
	const std::map<std::wstring, std::wstring>& Serialize() CONST;

	/**
	 * Compute a hash for this detection data
	 *
	 * @return A hash for this detection data
	 */
	size_t Hash() CONST;

	/**
	 * Override comparison operator
	 *
	 * @param detection The data to compare
	 *
	 * @return True if the data is equal to this; false otherwise
	 */
	bool operator==(const ProcessDetectionData& detection) CONST;

private:

	/// Record the hash of the data
	size_t hash = 0;

	/// Record the serialization of the data
	std::map<std::wstring, std::wstring> serialization = {};

	/// Raw constructor for a ProcessDetectionData
	ProcessDetectionData(
		IN ProcessDetectionType type,
		IN CONST std::optional<DWORD> PID,
		IN CONST std::optional<DWORD> & TID,
		IN CONST std::optional<HandleWrapper>& ProcessHandle,
		IN CONST std::optional<std::wstring> & ProcessName,
		IN CONST std::optional<std::wstring>& ProcessPath,
		IN CONST std::optional<std::wstring>& ProcessCommand,
		IN std::unique_ptr<ProcessDetectionData>&& ParentProcess,
		IN CONST std::optional<PVOID64>& BaseAddress,
		IN CONST std::optional<DWORD>& MemorySize,
		IN CONST std::optional<std::wstring>& ImageName
	);
};

/**
 * Stores information about a file identified as possibly malicious
 */
struct FileDetectionData {

	/// Indicates whether the file was found on the filesystem
	bool FileFound;

	/// Information about the directory listing for the file
	std::wstring FilePath;
	std::wstring FileName;
	std::optional<std::wstring> FileExtension;

	/// The type of the file. This differs from extensions in that mutliple different
	/// file extensions may correspond to the same filetype. 
	std::optional<std::wstring> FileType;

	/// Command run to open the file. Stored in HKCR\<File Type>\shell\open\command
	std::optional<std::wstring> Executor;

	/// A handle for the file
	std::optional<FileSystem::File> FileHandle;

	/// Hashes of the file
	std::optional<std::wstring> MD5;
	std::optional<std::wstring> SHA1;
	std::optional<std::wstring> SHA256;

	/// Timestamps associated with the file
	std::optional<FILETIME> LastOpened;
	std::optional<FILETIME> FileCreated;

	/// Information about a yara scan performed on the file
	std::optional<YaraScanResult> yara;

	/// Indicates whether the file is properly signed and the signature is trusted
	std::optional<bool> FileSigned;

	/// The title of the signer of this file, given that the file is signed
	std::optional<std::wstring> Signer;

	/**
	 * Creates a FileDetectionData using an open handle to the file. This works under the assumption that the 
	 * detection matches the file found on disk. If generating this detection from event logs or other records this 
	 * may not be the case. If the file has already been scanned with yara, it is recommended that the result be passed
	 * in to the constructor so that it doesn't have to be scanned a second time.
	 * 
	 * @param file A File object representing the file.
	 * @param scan The result of a yara scan performed on a file. This parameter is optional, but providing the result 
	 * will avoid the need for the scan to be repeated.
	 */
	FileDetectionData(
		IN CONST FileSystem::File& file,
		IN CONST std::optional<YaraScanResult>& scan = std::nullopt OPTIONAL
	);

	/**
	 * Creates a FileDetectionData using the file's path on disk. This constructor is best used when the file could not
	 * be found or it is infeasible to construct a File object representing the underlying file. If a File object is 
	 * available, using the other constructor will be more efficient.
	 *
	 * @param FilePath The path of the file
	 */
	FileDetectionData(
		IN CONST std::wstring& FilePath
	);

	/**
	 * Serialize the detection data in to a mapping of values. Note this should not include any internal representations
	 * but rather only include values that have meaning outside of BLUESPAWN's running.
	 *
	 * @return A mapping of properties to human-readable values
	 */
	const std::map<std::wstring, std::wstring>& Serialize() CONST;

	/**
	 * Compute a hash for this detection data
	 *
	 * @return A hash for this detection data
	 */
	size_t Hash() CONST;

	/**
	 * Override comparison operator
	 *
	 * @param detection The data to compare
	 *
	 * @return True if the data is equal to this; false otherwise
	 */
	bool operator==(const FileDetectionData& detection) const;

private:

	/// Record the hash of the data
	size_t hash = 0;

	/// Record the serialization of the data
	std::map<std::wstring, std::wstring> serialization = {};
};

/**
 * Stores information about a registry entry identified as possibly malicious. This entry may be a whole registry key,
 * a registry value, or just part of a registry value.
 *
 * If a registry value is detected on and it is a REG_MULTI_SZ, rather than creating one detection for the value as a 
 * whole, create a separate detection for each potentially malicious entry in the value as a REG_SZ.
 */
struct RegistryDetectionData {

	/// The path of the registry key associated with the registry entry
	std::wstring KeyPath;

	/// The key associated with the registry entry.
	Registry::RegistryKey key;

	/// An optional value under the key associated with the registry entry
	std::optional<Registry::RegistryValue> value;

	/// The raw data contained in the registry entry.
	std::optional<AllocationWrapper> data;

	/// The type of data in this registry detection
	RegistryDetectionType type;

	/**
	 * Creates a RegistryDetectionData, referencing either a registry key, a registry value, or part of a registry 
	 * value. If a registry value is detected on and it is a REG_MULTI_SZ, rather than creating one detection for the 
	 * value as a whole, create a separate detection for each potentially malicious entry in the value as a REG_SZ.
	 *
	 * @param key The associated with the registry entry.
	 * @param value An optional value under the key associated with the registry entry
	 * @param type The type of data referenced by this registry value. This defaults to Unknown
	 * @param data An optional allocation wrapper storing the raw data associated with the registry entry. If `value` 
	 *        represents only part of a registry value's data, this should not be set.
	 */
	RegistryDetectionData(
		IN CONST Registry::RegistryKey& key,
		IN CONST std::optional<Registry::RegistryValue>& value = std::nullopt OPTIONAL,
		IN RegistryDetectionType type = RegistryDetectionType::Unknown OPTIONAL,
		IN CONST std::optional<AllocationWrapper>& data = std::nullopt OPTIONAL
	);

	/**
	 * Creates a RegistryDetectionData, referencing either a registry key, a registry value, or part of a registry
	 * value. If a registry value is detected on and it is a REG_MULTI_SZ, rather than creating one detection for the
	 * value as a whole, create a separate detection for each potentially malicious entry in the value as a REG_SZ.
	 *
	 * @param value A RegistryValue object containing information about the value
	 * @param type The type of data referenced by this registry value. This defaults to Unknown.
	 */
	RegistryDetectionData(
		IN CONST Registry::RegistryValue& value,
		IN RegistryDetectionType type = RegistryDetectionType::Unknown OPTIONAL
	);

	/**
	 * Serialize the detection data in to a mapping of values. Note this should not include any internal representations
	 * but rather only include values that have meaning outside of BLUESPAWN's running.
	 *
	 * @return A mapping of properties to human-readable values
	 */
	const std::map<std::wstring, std::wstring>& Serialize() CONST;

	/**
	 * Compute a hash for this detection data
	 *
	 * @return A hash for this detection data
	 */
	size_t Hash() CONST;

	/**
	 * Override comparison operator
	 *
	 * @param detection The data to compare
	 *
	 * @return True if the data is equal to this; false otherwise
	 */
	bool operator==(const RegistryDetectionData& detection) const;

private:

	/// Record the hash of the data
	size_t hash = 0;

	/// Record the serialization of the data
	std::map<std::wstring, std::wstring> serialization = {};
};

/**
 * Stores information about a service identified as possibly malicious. Note that when creating a service detection 
 * object, it is recommended that the registry keys and files associated with the service should have separate 
 * detection objects.
 */
struct ServiceDetectionData {

	/// The name of the service
	std::optional<std::wstring> ServiceName;

	/// The display name of the service
	std::optional<std::wstring> DisplayName;

	/// The description of the service
	std::optional<std::wstring> Description;

	/// The service path
	std::optional<std::wstring> FilePath;

	/**
	 * Creates a ServiceDetectionData object, referencing a windows service that may be malicious. Either DisplayName
	 * or ServiceName is required.
	 * 
	 * @param ServiceName The name of the service
	 * @param DisplayName The display name of the service
	 * @param FilePath The path the the service executable
	 * @param Description The description of the service
	 */
	ServiceDetectionData(
		IN CONST std::optional<std::wstring>& ServiceName = std::nullopt OPTIONAL,
		IN CONST std::optional<std::wstring>& DisplayName = std::nullopt OPTIONAL,
		IN CONST std::optional<std::wstring>& FilePath = std::nullopt OPTIONAL,
		IN CONST std::optional<std::wstring>& Description = std::nullopt OPTIONAL
	);

	/**
	 * Serialize the detection data in to a mapping of values. Note this should not include any internal representations
	 * but rather only include values that have meaning outside of BLUESPAWN's running.
	 *
	 * @return A mapping of properties to human-readable values
	 */
	const std::map<std::wstring, std::wstring>& Serialize() CONST;

	/**
	 * Compute a hash for this detection data
	 *
	 * @return A hash for this detection data
	 */
	size_t Hash() CONST;

	/**
	 * Override comparison operator
	 *
	 * @param detection The data to compare
	 *
	 * @return True if the data is equal to this; false otherwise
	 */
	bool operator==(const ServiceDetectionData& detection) const = default;

private:

	/// Record the hash of the data
	size_t hash = 0;

	/// Record the serialization of the data
	std::map<std::wstring, std::wstring> serialization = {};
};

/**
 * Stores information about something not covered by other detection types identified as possibly malicious. This 
 * includes things such as users, groups, shares, pipes, and more.
 */
struct OtherDetectionData {
	
	/// A string describing the type of detection associated with this object.
	std::wstring DetectionType;

	/// Stores data about the detection
	std::map<std::wstring, std::wstring> DetectionProperties;

	/**
	 * Creates an OtherDetectionData object, referencing something on the system identified as possibly malicious. 
	 * OtherDetectionData objects consist of a type and a map of properties and their values, represented as strings.
	 *
	 * @param DetectionType A string describing the type of detection associated with this object
	 * @param DetectionProperties A mapping of property to value describing what's being referenced by this.
	 */
	OtherDetectionData(
		IN CONST std::wstring& DetectionType,
		IN CONST std::map<std::wstring, std::wstring>& DetectionProperties
	);

	/**
	 * Serialize the detection data in to a mapping of values. Note this should not include any internal representations 
	 * but rather only include values that have meaning outside of BLUESPAWN's running.
	 *
	 * @return A mapping of properties to human-readable values
	 */
	const std::map<std::wstring, std::wstring>& Serialize() CONST;

	/**
	 * Compute a hash for this detection data
	 *
	 * @return A hash for this detection data
	 */
	size_t Hash() CONST;

	/**
	 * Override comparison operator
	 *
	 * @param detection The data to compare
	 *
	 * @return True if the data is equal to this; false otherwise
	 */
	bool operator==(const OtherDetectionData& detection) const = default;

private:

	/// Record the hash of the data
	size_t hash = 0;

	/// Record the serialization of the data
	std::map<std::wstring, std::wstring> serialization = {};
};

/// Stores contextual information around a detection
struct DetectionContext {
	
	/// A set of the hunts that identified the detection
	std::set<std::wstring> hunts;
	
	/// The time at which the first evidence of the detection was created
	std::optional<FILETIME> FirstEvidenceTime;

	/// The time at which the detection was created
	FILETIME DetectionCreatedTime;

	/// An optional note describing why this detection was marked as potentially malicious
	std::optional<std::wstring> note;

	/**
	 * Creates a DetectionContext for a detection. 
	 *
	 * @param DetectionCreatedTime The time at which the detection was created
	 * @param hunt If the associated detection is created by a hunt, this is the hunt responsible for creating it
	 * @param FirstEvidenceTime The time at which the first evidence of this detection was created
	 */
	DetectionContext(
		IN CONST std::optional<std::wstring>& hunt = std::nullopt OPTIONAL,
		IN CONST std::optional<FILETIME>& FirstEvidenceTime = std::nullopt OPTIONAL,
		IN CONST std::optional<std::wstring>& note = std::nullopt OPTIONAL
	);
};

/// A container for the various type of detection data a Detection object may reference
typedef std::variant<
	ProcessDetectionData,
	FileDetectionData,
	RegistryDetectionData,
	ServiceDetectionData,
	OtherDetectionData
> DetectionData;

/**
 * Represents something that has been identified as potentially malicious. Each detection object can be further broken 
 * down in to the types laid out in the DetectionType enum. Each type of detection then has an associated DetectionData
 * object providing information on the details of what was detected. Each detection also may hold a remediator, which 
 * will handle the detection, either removing it, fixing it, or mitigating it. This remediator can be used by a 
 * reaction and should be set when the detection is created if possible. Finally, the the detection will hold a 
 * DetectionContext object, which holds information about the detection itself, such as the hunts that generated it, 
 * when it was generated, and when the thing being detected was first identified.
 */
class Detection {
private:

	/// Record the hash of the data
	size_t hash;

	/// Record the serialization of the data
	std::map<std::wstring, std::wstring> serialization;

	/// A shared counter to keep track of detection IDs and ensure each new detection gets assigned
	/// a unique identifier.
	static volatile std::atomic<DWORD> IDCounter;

	/// A struct used to serialize detection data
	static struct {
		std::map<std::wstring, std::wstring> operator()(ProcessDetectionData data){
			return data.Serialize();
		}
		std::map<std::wstring, std::wstring> operator()(FileDetectionData data){
			return data.Serialize(); 
		}
		std::map<std::wstring, std::wstring> operator()(RegistryDetectionData data){
			return data.Serialize();
		}
		std::map<std::wstring, std::wstring> operator()(ServiceDetectionData data){
			return data.Serialize();
		}
		std::map<std::wstring, std::wstring> operator()(OtherDetectionData data){
			return data.Serialize(); 
		}
	} serializer;

	/// A struct used to hash detection data
	static struct {
		size_t operator()(ProcessDetectionData data){ return data.Hash(); }
		size_t operator()(FileDetectionData data){ return data.Hash(); }
		size_t operator()(RegistryDetectionData data){ return data.Hash(); }
		size_t operator()(ServiceDetectionData data){ return data.Hash(); }
		size_t operator()(OtherDetectionData data){ return data.Hash(); }
	} hasher;

	/// Declare related hash classes to be friends
	friend class std::hash<Detection>;
	friend class std::hash<std::shared_ptr<Detection>>;

public:

	/// A unique identifier for this detection
	DWORD dwID;

	/// Indicates whether the data represented by this detection is consistent with the current state of the operating
	/// system.
	bool DetectionStale;

	/// Indicates the type of this detection
	DetectionType type;

	/// Describes what this detection object is representing
	DetectionData data;

	/// Information related to the scans performed on this detection
	ScanInfo info;

	/// A function that when run will remediate the detection, either removing it, fixing it, or  mitigating it.
	std::optional<std::function<void()>> remediator;

	/// Describes the context surrounding the detection such as when the first evidence of the detection was created, 
	/// the hunts generating this detection, and the time the detection was generated.
	DetectionContext context;

	/// A critical section guarding access to members of this class
	CriticalSection hGuard;

	/**
	 * Creates a Detection object, given associated data, optional context, an optional remediator, and an optional 
	 * indicator as to whether the detection is stale.
	 *
	 * @param data The data associated with the detection to be created. The type will be deduced.
	 * @param context The context surrounding the detection. If not provided, this will default to only include the 
	 *        time.
	 * @param remediator A function that can be used to remediate the detection if it is determined to be malicious. 
	 *        By default, there is no remediator.
	 * @param DetectionStale A boolean indicating whether the data represented by this detection is consistent with 
	 *        the current state of the operating system. This defaults to false.
	 */
	Detection(
		IN CONST DetectionData& data,
		IN CONST std::optional<DetectionContext>& context = std::nullopt OPTIONAL,
		IN CONST std::optional<std::function<void()>>& remediator = std::nullopt OPTIONAL,
		IN bool DetectionStale = false OPTIONAL
	);

	/// Define a copy constructor
	Detection(
		IN CONST Detection& detection
	);
	
	/// Define assignment operator
	Detection& operator=(
		IN CONST Detection& detection
	);

	/**
	 * Override for equality comparison operator. This checks if the data matches, ignoring other fields.
	 *
	 * @param detection The detection to compare
	 * 
	 * @return True if the detection is equal to this; false otherwise
	 */
	bool operator==(
		IN CONST Detection& detection
	) const;

	/**
	 * Serialize the detection data in to a mapping of values. Note this should not include any internal 
	 * representations but rather only include values that have meaning outside of BLUESPAWN's running.
	 *
	 * @return A mapping of properties to human-readable values
	 */
	const std::map<std::wstring, std::wstring>& Serialize() const;

	/**
	 * Implicit cast to a CRITICAL_SECTION pointer for use in synchronization functions
	 *
	 * @return hGuard
	 */
	operator LPCRITICAL_SECTION();

	/**
	 * Implicit cast to a CriticalSection pointer for use in synchronization functions
	 *
	 * @return hGuard
	 */
	operator CriticalSection();
};

/// Template specialization defining how hashes of Detection objects should be calculated
template<>
struct std::hash<Detection> {

	/// Hashes a detection using its data
	size_t operator()(
		IN CONST Detection& detection
	) const;
};

/// Template specialization defining how hashes of reference wrappers for Detection objects should be calculated
template<>
struct std::hash<std::shared_ptr<Detection>> {

	/// Hashes a detection using its data
	size_t operator()(
		IN CONST std::shared_ptr<Detection>& detection
	) const;
};

/// Template specialization defining how equality of reference wrappers for Detection objects should be calculated
template<>
struct std::equal_to<std::shared_ptr<Detection>> {

	/// Compares reference wrappers by comparing their wrapped value
	bool operator()(
		IN CONST std::shared_ptr<Detection>& _Left,
		IN CONST std::shared_ptr<Detection>& _Right
	) const;
};