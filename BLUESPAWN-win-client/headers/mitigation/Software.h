#pragma once

#include <string>
#include <optional>
#include <vector>

/**
 * \brief Represents the version of a program
 */
struct Version {

	/// A vector of 32 bit unsigned integers representing the version. The first index represents the major version,
	/// the second represents the minor version, and so on. 
	std::vector<uint32_t> version;

	/**
	 * \brief Construct a Version object given a list of version numbers
	 */
	Version(std::initializer_list<uint32_t> versionNumbers);

	/**
	 * \brief Construct a Version object from a version string
	 */
	Version(const std::wstring& versionString);

	/// Comparison operators for comparing versions
	bool operator<(const Version& version) const;
	bool operator<=(const Version& version) const;
	bool operator>(const Version& version) const;
	bool operator>=(const Version& version) const;
	bool operator==(const Version& version) const;
	bool operator!=(const Version& version) const;
};

/**
 * \brief Represents a software package used by a mitigation.
 */
class Software {
protected:

	/// The name of the software (i.e. Filezilla)
	std::wstring name;

	/// A description for the software (i.e. Free FTP Server)
	std::wstring description;

	/// The installation directory for the software
	std::optional<Version> version;

	/// Indicates whether the software is present on the system
	bool present;

public:

	/** 
	 * \brief Constructor for a software object
	 * 
	 * \note By default, this checks if the program has registered itself with Windows. Some cases may require
	 *       a derived class to override this method.
	 * 
	 * \param name The name of the software. This must match the installation record exactly.
	 * \param description A description for the software
	 */
	Software(const std::wstring& name, const std::wstring& description);

	/**
	 * \brief Checks if the software is present on the system.
	 *
	 * \return True if the software is present; false otherwise.
	 */
	bool IsPresent() const;


	/**
	 * \brief Checks if the software is present on the system.
	 *
	 * \return The version of the software if found; nullopt otherwise.
	 */
	std::optional<Version> GetVersion() const;
};

class WindowsOS : public Software {
public:
	WindowsOS();
};