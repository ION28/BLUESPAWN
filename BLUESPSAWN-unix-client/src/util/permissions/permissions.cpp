#include "util/permissions/permissions.h"
#include "util/log/Log.h"

namespace Permissions {

	bool AccessIncludesAll(FileSystem::File& file) {
		std::optional<ACCESS_MASK> perms = file.GetPermissions();
		return perms.has_value() && perms.value() & (S_IRWXU | S_IRWXO | S_IRWXG);
	}

	bool AccessIncludesWrite(FileSystem::File& file, const Owner &user) {
		std::optional<ACCESS_MASK> perms = file.GetPermissions();
		if(perms.has_value())
		{
			OwnerType type = user.GetOwnerType();
			std::optional<Owner> owner = file.GetFileOwner(type);
			if(owner.has_value() && type == NONE && user == owner.value())
			{
				switch (type)
				{
				case USER:
					return perms.value() & S_IWUSR;
				case GROUP:
			    	return perms.value() & S_IWGRP;
				}
			}
		}

		return false;
	}
	
	bool AccessIncludesRead(FileSystem::File& file, const Owner &user) {
		std::optional<ACCESS_MASK> perms = file.GetPermissions();
		if(perms.has_value())
		{
			OwnerType type = user.GetOwnerType();

			switch (type)
			{
			case USER:
				return perms.value() & S_IRUSR;
			case GROUP:
			    return perms.value() & S_IRGRP;
			default:
				return perms.value() & S_IROTH;
			}
		}

		return false;
	}
	
	bool AccessIncludesExecute(FileSystem::File& file, const Owner &user) {
		std::optional<ACCESS_MASK> perms = file.GetPermissions();
		if(perms.has_value())
		{
			OwnerType type = user.GetOwnerType();

			switch (type)
			{
			case USER:
				return perms.value() & S_IXUSR;
			case GROUP:
			    return perms.value() & S_IXGRP;
			default:
				return perms.value() & S_IXOTH;
			}
		}

		return false;
	}

	bool AccessIncludesWriteOwner(FileSystem::File &file, const Owner &user) {
		return AccessIncludesWrite(file, user);
	}

	//TODO: delete requires checking the directory
	bool AccessContainsDelete(FileSystem::File &file, const Owner &user) {
		return false;
	}

	void AccessAddAll(DWORD& access) {
		access |= S_IRWXU | S_IRWXG | S_IRWXO;
	}

	void AccessAddWrite(DWORD& access, const OwnerType type) {
		access |= type == USER ? S_IWUSR : type == GROUP ? S_IWGRP : S_IWOTH;
	}

	void AccessAddRead(DWORD& access, const OwnerType type) {
		access |= type == USER ? S_IRUSR : type == GROUP ? S_IRGRP : S_IROTH;
	}

	void AccessAddExecute(DWORD& access, const OwnerType type) {
		access |= type == USER ? S_IXUSR : type == GROUP ? S_IXGRP : S_IXOTH;
	}

	void AccessAddWriteOwner(DWORD& access, const OwnerType type) {
		AccessAddWrite(access, type);
	}

	//NOTE: constructor probably shouldnt be used
	Owner::Owner(const std::string& name) : wName{ name }, bExists{ true } {
		struct passwd * user = getpwnam(name.c_str());
		if(user){
			otType = OwnerType::USER;
			id = user->pw_uid;	
		}else{
			struct group * group = getgrnam(name.c_str());
			if(group){
				otType = OwnerType::GROUP;
				id = group->gr_gid;
			}else{
				otType = OwnerType::NONE;
				bExists = false;
				LOG_ERROR("No user or group with name " << name << " exists.");
			}
		}
	}

	Owner::Owner(const uid_t id, const OwnerType type) : id{id}, otType { type }{
		if(type == OwnerType::USER){
			struct passwd * user = getpwuid(id);
			if(!user){
				LOG_VERBOSE(2, "User with id " << id << " does not exist.");
				otType = OwnerType::NONE;
				bExists = false;
			}else{
				bExists = true;
				wName = std::string(user->pw_name);
			}
		}else if(type == OwnerType::GROUP){
			struct group * group = getgrgid(id);
			if(!group){
				LOG_VERBOSE(2, "group with id " << id << " does not exist");
				otType = OwnerType::NONE;
				bExists = false;
			}else{
				bExists = true;
				wName = std::string(group->gr_name);
			}
		}else{
			LOG_ERROR("Invalid owner type");
		}
	}

	Owner::Owner(const std::string& name, const bool& exists, const OwnerType& type, const uid_t id) : wName{ name }, bExists{ exists }, otType{ type }, id{ id } {}

	bool Owner::operator==(const Owner& b) const{
		return this->GetOwnerType() == b.GetOwnerType() && this->GetId() == b.GetId();
	}

	bool Owner::Exists() const {
		return bExists;
	}

	std::string Owner::GetName() const {
		return wName;
	}

	uid_t Owner::GetId() const {
		return id;
	}

	OwnerType Owner::GetOwnerType() const {
		return otType;
	}

	std::string Owner::ToString() const {
		return wName;
	}

	User::User(const std::string& uName) : Owner{ uName , true, OwnerType::USER} {

		struct passwd * user = getpwnam(uName.c_str());

		if(!user){
			LOG_VERBOSE(2, "User with name " << wName << " does not exist.");
			return;
		}

		id = user->pw_uid;
		gid = user->pw_gid;

		LOG_VERBOSE(3, "User with name " << uName << " found.");
	}

	User::User(const uid_t uid) {
		struct passwd * user = getpwuid(uid);
		if(!user){
			otType = OwnerType::NONE;
			bExists = false;
			return;
		}

		SetupClass(user);
	}

	User::User(const struct passwd * user){
		SetupClass(user);
	}

	void User::SetupClass(const struct passwd * user){
		otType = OwnerType::USER;
		wName = std::string(user->pw_name);
		id = user->pw_uid;
		gid = user->pw_gid;
		bExists = true;
	}

	Group::Group(const std::string& name) {
		struct group * group = getgrnam(name.c_str());
		if(group){
			int index = 0;
			members = std::vector<std::string>();
			while(group->gr_mem[index] != NULL){
				members.emplace_back(std::string(group->gr_mem[index]));
				index++;
			}

			otType = OwnerType::GROUP;
			wName = std::string(group->gr_name);
			id = group->gr_gid;
			bExists = true;
		}else{
			otType = OwnerType::NONE;
			bExists = false;
		}
	}

	Group::Group(const gid_t gid){
		struct group * group = getgrgid(gid);
		if(!group){
			otType = OwnerType::NONE;
			bExists = false;
			return;
		}

		SetupClass(group);
	}

	Group::Group(const struct group * group){
		SetupClass(group);
	}

	void Group::SetupClass(const group * group){
		otType = OwnerType::GROUP;
		id = group->gr_gid;
		bExists = true;
		wName = std::string(group->gr_name);
		int index = 0;
		members = std::vector<std::string>();
		while(group->gr_mem[index] != NULL){
			members.emplace_back(std::string(group->gr_mem[index]));
			index++;
		}
	}

	std::optional<Owner> GetProcessOwner() {
		/**
		 * NOTE: theres a distinction between effective user id and real user id
		 * for the purposes of this program, going to use real id because some checks
		 * dont use effective id and use real id
		 */
		
		return User(getuid());
	}
}