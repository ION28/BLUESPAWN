#pragma once

#include <Windows.h>
#include <winnt.h>
#include <AclAPI.h>
#include <sddl.h>
#include <string>
#define PSTRING __PSTRING
#define STRING __STRING
#define UNICODE_STRING __UNICODE_STRING
#define PUNICODE_STRING __PUNICODE_STRING
#include <NTSecAPI.h>
#undef PSTRING
#undef STRING
#undef UNICODE_STRING
#undef PUNICODE_STRING

#include "util/log/Loggable.h"
#include "util/wrappers.hpp"

namespace Permissions{
	/**
	* Functions to check if an access mask includes a permission
	*
	* @param access - the access mask to check
	* @return true if the access mask includes the permission or ALL, false otherwise
	*/
	bool AccessIncludesAll(const ACCESS_MASK& access);
	bool AccessIncludesWrite(const ACCESS_MASK& access);
	bool AccessIncludesRead(const ACCESS_MASK& access);
	bool AccessIncludesExecute(const ACCESS_MASK& access);
	bool AccessIncludesWriteOwner(const ACCESS_MASK& access);
	bool AccessIncludesDelete(const ACCESS_MASK& access);

	/**
	* Function to add an access to an access mask
	*
	* @param access - the access mask to be changed
	*/
	void AccessAddAll(ACCESS_MASK& access);
	void AccessAddWrite(ACCESS_MASK& access);
	void AccessAddRead(ACCESS_MASK& access);
	void AccessAddExecute(ACCESS_MASK& access);
	void AccessAddWriteOwner(ACCESS_MASK& access);
	void AccessAddDelete(ACCESS_MASK& access);

	class SecurityDescriptor : public GenericWrapper<PISECURITY_DESCRIPTOR> {
		PSID lpUserSID;
		PSID lpGroupSID;
		PACL dacl;
		PACL sacl;

	protected:
		enum class SecurityDataType {
			USER_SID, GROUP_SID, DACL, SACL
		};

		SecurityDescriptor(DWORD dwSize, SecurityDataType type);

	public:
		/**
		* Create a SecurityDescriptor to hold a UserSID
		*
		* @param dwSize The size in bytes of the SID
		*
		* @return a SecurityDescriptor with the lpUserSID value set to a pointer to dwSize
		*	bytes of memory
		*/
		static SecurityDescriptor CreateUserSID(DWORD dwSize);
		/**
		* Create a SecurityDescriptor to hold a GroupSID
		*
		* @param dwSize The size in bytes of the SID
		*
		* @return a SecurityDescriptor with the lpGroupSID value set to a pointer to dwSize
		*	bytes of memory
		*/
		static SecurityDescriptor CreateGroupSID(DWORD dwSize);
		/**
		* Create a SecurityDescriptor to hold a DACL
		*
		* @param dwSize The size in bytes of the dacl
		*
		* @return a SecurityDescriptor with the dacl value set to a pointer to dwSize
		*	bytes of memory
		*/
		static SecurityDescriptor CreateDACL(DWORD dwSize);
		/**
		* Create a SecurityDescriptor to hold a sacl
		*
		* @param dwSize The size in bytes of the sacl
		*
		* @return a SecurityDescriptor with the sacl value set to a pointer to dwSize
		*	bytes of memory
		*/
		static SecurityDescriptor CreateSACL(DWORD dwSize);

		/**
		* Constructor to create a security descriptor from a PISECURITY_DESCRIPTOR
		*
		* @param lpSecurity A PISECURITY_DESCRIPTOR object. All valid fields in lpSecurity
		*	will be copied to the corresponding field in the SecurityDescriptor object, if
		*	such a field exists
		*/
		SecurityDescriptor(PISECURITY_DESCRIPTOR lpSecurity = nullptr);

		/*Getter for the lpUserSID field*/
		PSID GetUserSID() const;
		/*Getter for the lpGroupSID field*/
		PSID GetGroupSID() const;
		/*Getter for the dacl field*/
		PACL GetDACL() const;
		/*Getter for the sacl field*/
		PACL GetSACL() const;
	};

	/*Enum for storing type of Owner an Owner object is*/
	enum OwnerType {
		NONE, USER, GROUP
	};

	class LsaHandleWrapper : public GenericWrapper<LSA_HANDLE> {
	public:
		LsaHandleWrapper(LSA_HANDLE handle);
		LsaHandleWrapper(LSA_HANDLE handle, std::function<void(LSA_HANDLE)> fSafeClose);
		static void SafeCloseLsaHandle(LSA_HANDLE handle);
	};

	class Owner : public Loggable {
		//Policy Handler for User Rights Assignment Tracking
		static LsaHandleWrapper lPolicyHandle;

		//Boolean to track if the handle wrapper is initialized
		static bool bPolicyInitialized;

		//List of super user privileges
		static const std::vector<std::wstring> vSuperUserPrivs;

		/**
		* Function to initialize lPolicyHandle and set bPolicyInitialized
		* to true if initialization succeeded.
		*/
		static void InitializePolicy();

		/**
		* Function de-initialize lPolicyHandle
		* param handle - the handle to de initialize
		*/
		static void DeinitializePolicy(LSA_HANDLE handle);
	protected:
		//Whether or not this owner is on the system
		bool bExists;

		//The user's SID structure
		SecurityDescriptor sdSID;

		//Owner's qualified name
		std::wstring wName;

		//Domain to which the user belongs
		std::wstring wDomainName;

		//The type of the owner
		OwnerType otType;

		/**
		* Function to convert a wstring to an LSA_UNICODE_STRING
		* 
		* @param str the wstring to convert
		*
		* @return an LSA_UNICODE_STRING corresponding to the given wstring
		*/
		static std::shared_ptr<LSA_UNICODE_STRING> Owner::WStringToLsaUnicodeString(IN const std::wstring& str);

		/**
		* Constructor for an owner object based off sid
		*
		* @param sid A SecurityDescriptor with lpUserSID set to the sid of the owner. Other
		*	fields will be filled in if an owner of that sid exists.
		*/
		static std::wstring Owner::LsaUnicodeStringToWString(IN const LSA_UNICODE_STRING& str);

		/**
		* Constructor for an owner object that sets wName, bExists, and otOwnerType, but no other fields
		*
		* @param name A wstring containing value to be copied to wName
		* @param exists A boolean containing value to be copied ot bExists
		* @param t An OwnerType containing value to be copied to otOwnerType
		*/
		Owner(IN const std::wstring& name, IN bool exists, IN OwnerType t);

		/**
		* Constructor for an owner object that sets sdSID, bExists, and otOwnerType, but no other fields
		*
		* @param sid A SecurityDescriptor containing value to be copied to sdSID. Should have lpUserSID set
		*	to valid PSID if t is USER, and lpGroupSID set to valid PSID if t is GROUP.
		* @param exists A boolean containing value to be copied ot bExists
		* @param t An OwnerType containing value to be copied to otOwnerType
		*/
		Owner(IN const SecurityDescriptor& sid, IN bool exists, IN OwnerType t);

		/**
		* Constructor for an owner object that sets all fields to given values. Performs no checking
		* that given name and sid line up.
		*
		* @param name A wstring containing value to be copied to wName
		* @ param domain A wstring containing value to be copied to wDomain
		* @param sid A SecurityDescriptor containing value to be copied to sdSID. Should have lpUserSID set
		*	to valid PSID if t is USER, and lpGroupSID set to valid PSID if t is GROUP.
		* @param exists A boolean containing value to be copied ot bExists
		* @param t An OwnerType containing value to be copied to otOwnerType
		*/
		Owner(IN const std::wstring& name, IN const std::wstring& domain, IN const SecurityDescriptor& sid, IN bool exists, IN OwnerType t);


	public:
		/**
		* Constructor for an owner object based off name
		*
		* @param name A wstring containing the name of an object. Other fields will
		*	be filled in if an owner of that name exists.
		*/
		Owner(IN const std::wstring& name);
		
		/**
		* Constructor for an owner object based off sid
		* 
		* @param sid A SecurityDescriptor with lpUserSID set to the sid of the owner. Other
		*	fields will be filled in if an owner of that sid exists. 
		*/
		Owner(IN const SecurityDescriptor& sid);
		
		/**
		* Function to get whether or not the owner exists on the system
		*
		* @return true if the owner exists, false otherwise
		*/
		bool Exists() const;
		/**
		* Function to get the name of a user
		*
		* @return wstring containing the name of the owner in form
		*/
		std::wstring GetName() const;


		/**
		* Function to get the name of the domain the owner belongs to
		*
		* @return wstring containing the domain name that the owner belongs to
		*/
		std::wstring GetDomainName() const;

		/**
		* Function to get the SID of the owner
		*
		* @return SID structure with the owner's SID
		*/
		PSID GetSID() const;

		/**
		* Function to get the owner type
		*
		* @return OwnerType value of GROUP, USER, or NONE
		*/
		OwnerType GetOwnerType() const;

		/**
		 * Gets the owner's name
		 *
		 * @return The name of the owner
		 */
		virtual std::wstring ToString() const;

		/**
		* Function to get a list of privileges the owner has
		*
		* @return the list of privileges an owner explicity has, and if they 
		*     are a user, includes the privileges granted to them by the
		*     groups they're in.
		*/
		std::vector<std::wstring> GetPrivileges();

		/**
		* Function to check if the owner has a certain privilege
		*
		* @param wPriv the name of the privilege to check for. Names should
		*    be given as constants listed here: https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
		* 
		* @return true if the owner has the privilege, false otherwise
		*/
		bool HasPrivilege(IN const std::wstring& wPriv);

		/**
		* Function to enumerate all owners with a given privilege
		* 
		* @param wPriv a wstring containing the privilege to check for.
		*     Names should be from: https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
		*
		* @return a vector of Owner objects containing all owners with the given privilege.
		*     If the function fails, the vector will be empty and GetLastError() will contain
		*     the failure reason. If GetLastError() returns ERROR_SUCCESS, the function succeeded
		*     but there were no Owners with the given privilege. 
		*/
		static std::vector<Owner> GetOwnersWithPrivilege(IN const std::wstring& wPriv);

		/**
		* Function to remove a privilege from an owner object
		* 
		* @param wPriv a wstring containing the name of the privilege to remove
		*
		* @return true if the function succeeded, false otherwise. If the function fails,
		*     GetLastError() will return the reason for failure.
		*/
		bool RemovePrivilege(IN const std::wstring& wPriv);

		/**
		* Function to check if an owner has a superuser privilege.
		*
		* @return true if the user has any of these privileges, false otherwise
		*/
		bool HasSuperUserPrivs();

		/**
		* Function to remove all super user privileges from an owner
		*
		* @return true if function succeeds, false otherwise. If the function
		*     fails, GetLastError() will contain the reason for failure
		*/
		bool RemoveSuperUserPrivs();

		/**
		* Function to delete an owner from the system
		*
		* @return true if the user was deleted, false otherwise
		*/
		bool Delete();
	};

	class User : public Owner {


	public:

		/**
		* Creates a User object based off a qualified user name
		*
		* @param uName The qualified username of the user
		*/
		User(IN const std::wstring& uName);

		/**
		* Create a User object based off an SID
		*
		* @param sid SecurityDescriptor with UserSID set to SID of the user
		*/
		User(IN const SecurityDescriptor& sid);
	};

	class Group : public Owner {
	public:

		/**
		* Create a group based off of group name
		*
		* @param name The name of the group
		*/
		Group(IN const std::wstring& name);

		/**
		* Create a group based off of a user name
		*
		* @param sid SecurityDesicrptor with group SID set to the SID of the group
		*/
		Group(IN const SecurityDescriptor& sid);
	};

	/**
	* Gets the rights a specific owner object has under a given acl
	*
	* @param owner The owner object for whom to check rights
	* @param acl The acl from which to read rights
	*
	* @return ACCESS_MASK containing the rights the owner object has
	*/
	ACCESS_MASK GetOwnerRightsFromACL(const Owner& owner, const SecurityDescriptor& acl);

	/**
	* Get the owner of the Bluespawn process
	*
	* @return An Owner object representing the owner of the Bluespawn process,
	*	or std::nullopt if the function failed
	*/
	std::optional<Owner> GetProcessOwner();

	/**
	* Function to update the ACL of an object
	* @param wsObjectName A wstring containing the name of the object for which to update permissions
	* @param seObjectType An SE_OBJECT_TYPE desciribing the type of the object for which to update permissions
	* @param oOwner An Owner object representing the owner for whom to update permissions
	* @param amDesiredAccess An ACCESS_MASK containing the permissions to grant or deny to oOwner
	* @param bDeny If false, grant access to amDesiredAccess, if true deny access. Defaults to false
	*
	* @return true if the objects ACL was updated. False otherwise. If false, GetLastError will contain the error.
	*/
	bool UpdateObjectACL(const std::wstring& wsObjectName, SE_OBJECT_TYPE seObjectType, const Owner& oOwner, ACCESS_MASK amDesiredAccess, bool bDeny = false);
}