#pragma once

#include <Windows.h>
#include <winnt.h>
#include <AclAPI.h>

#include <string>

#include "util/log/Loggable.h"
#include "common/wrappers.hpp"

namespace Permissions {

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

	class User : public Loggable{
		//Whether or not this user is on the system
		bool bUserExists;

		//The user's SID structure
		SecurityDescriptor sUserSID;

		//User's qualified name
		std::wstring Username;

		//Domain to which the user belongs
		std::wstring DomainName;

	public: 

		/**
		* Creates a User object based off a qualified user name
		*
		* @param uName The qualified username of the user given as DOMAIN\USERNAME
		*/
		User(IN const std::wstring& uName);

		/**
		* Create a User object based off an SID
		*
		* @param sid The SID of the user
		*/
		User(IN const SecurityDescriptor& sid);

		/**
		* Function to get whether or not the user existed
		*
		* @return true if the user exists, false otherwise
		*/
		bool getUserExists() const {
			return bUserExists;
		}

		/**
		* Function to get the username of a user
		*
		* @return string containing the username of the user in DOMAIN\USERNAME form
		*/
		std::wstring getUsername() const {
			return Username;
		}


		/**
		* Function to get the name of the domain the user belonged to
		*
		* @return string containing the domain name that the user belongs to
		*/
		std::wstring getDomainName() const {
			return DomainName;
		}

		/**
		* Function to get the SID the user belongs to
		*
		* @return SID structure with the users SID
		*/
		PSID getSID() const {
			return sUserSID;
		}

		/**
		 * Gets the user's username
		 *
		 * @return The username of the user
		 */
		virtual std::wstring ToString() const;
	};
}