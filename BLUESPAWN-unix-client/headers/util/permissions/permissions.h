#pragma once

#include <sys/stat.h>

#include <string>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include "util/linuxcompat.h"
#include "util/log/Loggable.h"
#include "common/wrappers.hpp"

typedef mode_t ACCESS_MASK;
namespace Permissions{


	/*Enum for storing type of Owner an Owner object is*/
	enum OwnerType {
		NONE, USER, GROUP 
	};

	/**
	* Function to add an access to an access mask
	*
	* @param access - the access mask to be changed
	*/
	void AccessAddAll(unsigned int &access);
	void AccessAddWrite(unsigned int& access, const OwnerType type);
	void AccessAddRead(unsigned int& access, const OwnerType type);
	void AccessAddExecute(unsigned int& access, const OwnerType type);
	void AccessAddWriteOwner(unsigned int& access, const OwnerType type);
	void AccessAddDelete(unsigned int& access, const OwnerType type);


	class Owner : public Loggable {
	protected:
		//Whether or not this owner is on the system
		bool bExists;

		//The user's SID structure - NOTE: not sure yet how to replace this
		//SecurityDescriptor sdSID;

		//Owner's qualified name
		std::string wName;

		//The type of the owner
		OwnerType otType;

		//the identifier of the user or group
		//NOTE: uid_t and gid_t are typedefs of the same base
		uid_t id;

		//A blank constructor - the superclass files in everything
		Owner();

		//NOTE: Some of these are soon to be deprecated

		/**
		* Constructor for an owner object based off name
		*
		* @param name A wstring containing the name of an object. Other fields will
		*	be filled in if an owner of that name exists.
		*/
		Owner(const std::string& name);
		/**
		* Constructor for an owner object that sets wName, bExists, and otOwnerType, but no other fields
		*
		* @param name A wstring containing value to be copied to wName
		* @param exists A boolean containing value to be copied ot bExists
		* @param t An OwnerType containing value to be copied to otOwnerType
		*/
		Owner(const std::string& name, const bool& exists, const OwnerType& t);
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
		Owner(const std::string& name, const bool& exists, const OwnerType& t, uid_t id);

		/**
		 * Constructor for an owner object that sets all members
		 * 
		 * @param id uid_t or gid_t for the owner
		 * @param type type of owner (USER or GROUP)
		 */ 
		Owner(const uid_t id, const OwnerType type);


	public:


		bool operator==(const Owner &b) const;

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
		std::string GetName() const;

		/**
		 *  @return the uid_t or gid_t of the owner
		 */
		uid_t GetId() const;

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
		virtual std::string ToString() const;

		//virtual bool Delete() const;
	};

	class User : public Owner {
	private:
	    gid_t gid; //Id of the group the user belongs to
		std::string homeDir;
		void SetupClass(const struct passwd * user);
	public: 

		/**
		* Creates a User object based off a qualified user name
		*
		* @param uName The qualified username of the user
		*/
		User(const std::string& uName);

		/**
		 * @param the user id of the user
		 */ 
		User(const uid_t uid);

		/**
		 * @param user the struct passwd for a user
		 */
		User(const struct passwd * user);

		/**
		 * @return the group of the user
		 */
		gid_t GetGroup() const;

		//virtual bool Delete() const;

		std::string GetHomeDir() const;
	};

	class Group : public Owner {
	private:
	    std::vector<std::string> members; //members of the group
		void SetupClass(const struct group * group);
	public:

		/**
		* Create a group based off of group name
		*
		* @param name The name of the group
		*/
		Group(const std::string& name);

		/**
		 * @param gid gid of the group
		 */ 
		Group(const gid_t gid);

		/**
		 * @param group the struct group for the group
		 */ 
		Group(const struct group * group);

		/**
		 * @return a list of the members of the group
		 */ 
		std::vector<std::string> GetMembers() const;

		//virtual bool Delete() const;
	};

	/**
	* Get the owner of the Bluespawn process
	*
	* @return An Owner object representing the owner of the Bluespawn process, 
	*	or std::nullopt if the function failed
	*   NOTE: wont ever fail - update
	*/
	std::optional<Owner> GetProcessOwner();

}