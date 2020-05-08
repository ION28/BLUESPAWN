#pragma once

#include <Windows.h>
#include <winnt.h>
#include <AclAPI.h>
#include <sddl.h>
#include <string>

#include "util/log/Loggable.h"
#include "common/wrappers.hpp"

namespace Permissions {
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

	class SecurityDescriptor : public GenericWrapper<PISECURITY_DESCRIPTOR> {
		PSID lpUserSid;
		PSID lpGroupSid;
		PACL dacl;
		PACL sacl;
		
	protected:
		enum class SecurityDataType {
			USER_SID, GROUP_SID, DACL, SACL
		};

		SecurityDescriptor(DWORD dwSize, SecurityDataType type);

	public:
		static SecurityDescriptor CreateUserSID(DWORD dwSize);
		static SecurityDescriptor CreateGroupSID(DWORD dwSize);
		static SecurityDescriptor CreateDACL(DWORD dwSize);
		static SecurityDescriptor CreateSACL(DWORD dwSize);

		SecurityDescriptor(PISECURITY_DESCRIPTOR lpSecurity = nullptr);
		
		PSID GetUserSID() const;
		PSID GetGroupSID() const;
		PACL GetDACL() const;
		PACL GetSACL() const;
	};

	enum OwnerType {
		NONE, USER, GROUP 
	};

	class Owner : public Loggable {
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

	public:
		Owner(IN const std::wstring& name);
		Owner(IN const SecurityDescriptor& sid);
		Owner(IN const std::wstring& name, IN const bool& exists, IN const OwnerType& t);
		Owner(IN const SecurityDescriptor& sid, IN const bool& exists, IN const OwnerType& t);
		Owner(IN const std::wstring& name, IN const std::wstring& domain, IN const SecurityDescriptor& sid, IN const bool& exists, IN const OwnerType& t);
		/**
		* Function to get whether or not the owner exists on the system
		*
		* @return true if the owner exists, false otherwise
		*/
		bool GetExists() const {
			return bExists;
		}

		/**
		* Function to get the name of a user
		*
		* @return wstring containing the name of the owner in form
		*/
		std::wstring GetName() const {
			return wName;
		}


		/**
		* Function to get the name of the domain the owner belongs to
		*
		* @return wstring containing the domain name that the owner belongs to
		*/
		std::wstring GetDomainName() const {
			return wDomainName;
		}

		/**
		* Function to get the SID of the owner
		*
		* @return SID structure with the owner's SID
		*/
		PSID GetSID() const {
			if(otType == OwnerType::USER) return sdSID.GetUserSID();
			return sdSID.GetGroupSID();
		}

		/**
		* Function to get the owner type
		* 
		* @return OwnerType value of GROUP, USER, or NONE
		*/
		OwnerType GetOwnerType() const {
			return otType;
		}

		/**
		 * Gets the owner's name
		 *
		 * @return The name of the owner
		 */
		virtual std::wstring ToString() const;
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

	ACCESS_MASK GetOwnerRightsFromACL(const Owner& owner, const SecurityDescriptor& acl);
}