#pragma once

#include "mitigation/policy/MitigationPolicy.h"
#include "nlohmann/json.hpp"
#include "util/filesystem/FileSystem.h"
#include <variant>

using json = nlohmann::json;

/**
 * \brief Represents an IP address, either in IPv4 or IPv6 
 */
struct IP {

	enum class Version {
		IPv4, IPv6
	};

	/// The version of IP address stored in this object
	Version type;

	/// Holds the value of the IP (in big endian)
	std::variant<uint32_t, uint16_t[8]> ip;

	/**
	 * \brief Instantiates an IP from the string representation of the IP address
	 * 
	 * \param ip The string representation of the IP address
	 */
	IP(const std::wstring& ip);

	/**
	 * \brief Instantiates an IP from an IPv4 address encoded in little endian as a 32 bit unsigned integer
	 * 
	 * \param ip The IPv4 address encoded in big endian as a 32 bit unsigned integer
	 */
	IP(uint32_t ip);

	/**
	 * \brief Instantiates an IP from an IPv6 address encoded in 8 little 16 bit unsigned integers
	 *
	 * \param ip The IPv6 address encoded in 8 big endian 16 bit unsigned integers
	 */
	IP(uint16_t ip[8]);

	/**
	 * \brief Produces a string representation of the IP address referenced by this object.
	 * 
	 * \return The string representation of the IP address referenced by this object.
	 */
	std::wstring ToString() const;
};

/**
 * \brief Refers to a range of IP addresses
 */
struct IPRange {

	/// Minimum and maximum IP included in this range, inclusive
	IP minIP, maxIP;

	/**
	 * \brief Construct an IP range holding a single IP that is given
	 * 
	 * \param singleIP The single IP to be contained within this IP range
	 */
	IPRange(const IP& singleIP);

	/**
	 * \brief Construct an IP range with a minimum IP and maximum IP.
	 * 
	 * \note Throws an exception if both IPs are not in the same version of IP
	 * 
	 * \param minIP The minimum IP in this range
	 * \param maxIP The maximum IP in this range
	 */
	IPRange(const IP& minIP, const IP& maxIP);

	/**
	 * \brief Checks if a given IP is contained within the range referenced by this. Returns false if they aren't using
	 *        the same version of IP (IPv4, IPv6)
	 * 
	 * \param ip The IP to check
	 * 
	 * \return True if the given IP is contained within the range referenced by this; false otherwise.
	 */
	bool IPInRange(const IP& ip) const;

	/**
	 * \brief Converts the IP range to its string representation
	 */
	std::wstring ToString() const;
};

/// Specify whether the type of connection should be allowed
enum class FirewallAction {
	ALLOW, // Connections matching the conditions specified should be allowed
	BLOCK  // Connections matching the conditions specified should be blocked
};

/**
 * \brief Implements a FirewallRulePolicy for ensuring types of connections are or are not allowed.
 * 
 * \note FirewallRulePolicy objects enforcing that some connections be allowed *require* that the connection
 *       described be able to pass through the firewall. This may result in allow rules being added or block 
 *       rules being modified to meet this requirement. Inconsistent FirewallRulePolicies will result in an 
 *       error.
 * 
 * \note All firewall rule policies should only be listed as rules under a firewall base policy
 */
class FirewallRulePolicy : public MitigationPolicy {
public:

	/// Specifies the direction the connection originates from
	enum class Dir {
		In, Out
	};

	/// The protocol used by the connection
	enum class Protocol {
		TCP,    // TCP protocol
		UDP,    // UDP protocol
		TCPUDP, // Either TCP or UDP
		ICMP,   // ICMP "ping" protocol
	};

protected:

	/// The direction from which the connection originates
	Dir direction;

	/// The action to be taken on the connections matching the conditions specified here
	FirewallAction action;

	/// The protocol in consideration
	Protocol protocol = Protocol::TCPUDP;

	/// The destination ports in consideration, if any. If none are specified, all ports apply
	std::vector<uint16_t> ports;

	/// The programs for which this rule should apply, if any. If none are specified, all programs apply
	std::vector<FileSystem::File> scopedPrograms;

	/// The services for which this rule should apply, if any. If none are specified, all services apply
	std::vector<SC_HANDLE> scopedServices; // TODO: Add services utility module and replace with wrapped service

	/// The ranges of connection source IPs for which this rule should apply, if any. If none are specified, then all
	/// source IPs apply.
	std::vector<IPRange> connectionSourceRanges;

	/// The ranges of connection destination IPs for which this rule should apply, if any. If none are specified, then 
	/// all destination IPs apply.
	std::vector<IPRange> connectionDestinationRanges;

public:

	/**
	 * \brief Instantiates a FirewallRulePolicy object from a json configuration. This may throw exceptions.
	 *
	 * \param config The json object storing information about how the policy should be created.
	 */
	FirewallRulePolicy(json config);

	/**
	 * \brief Enforces the mitgiation policy, applying the change to the system.
	 *
	 * \return True if the system has the mitigation policy enforced; false otherwise.
	 */
	virtual bool Enforce() const override;

	/**
	 * \brief Checks if the changes specified by the mitigation policy match the current state of the
	 *        system.
	 *
	 * \return True if the system has the changes specified by the mitigation policy enforced; false
	 *         otherwise.
	 */
	virtual bool MatchesSystem() const override;
};

class FirewallBasePolicy : public MitigationPolicy {

	/// Specifies the default action for packets not matching any FirewallRulePolicy
	FirewallAction defaultAction;

	/// Specifies whether preexisting allow or block rules without an associated FirewallRulePolicy should be allowed
	/// to remain in effect, overriding the default action 
	bool allowPreexisting;

	/// A list of firewall rule policies to be enforced
	std::vector<FirewallRulePolicy> rules;

	/**
	 * \brief Instantiates a FirewallRulePolicy object from a json configuration. This may throw exceptions.
	 *
	 * \param config The json object storing information about how the policy should be created.
	 */
	FirewallBasePolicy(json config);

	/**
	 * \brief Enforces the mitgiation policy, applying the change to the system.
	 *
	 * \return True if the system has the mitigation policy enforced; false otherwise.
	 */
	virtual bool Enforce() const override;

	/**
	 * \brief Checks if the changes specified by the mitigation policy match the current state of the
	 *        system.
	 *
	 * \return True if the system has the changes specified by the mitigation policy enforced; false
	 *         otherwise.
	 */
	virtual bool MatchesSystem() const override;
};