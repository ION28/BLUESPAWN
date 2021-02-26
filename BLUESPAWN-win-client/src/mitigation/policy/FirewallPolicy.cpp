#include "mitigation/policy/FirewallRulePolicy.h"
#include "util/StringUtils.h"

#include <sstream>

IP::IP(const std::wstring& ip){
	if(ip.find(L'.') != ip.npos && ip.find(L':') != ip.npos){
		throw std::exception("Malformed IP!");
	}

	if(ip.find(L'.') != ip.npos){
		type = Version::IPv4;
		auto parts{ SplitStringW(ip, L".") };
		assert(parts.size() <= 4 && parts.size() >= 2);
		long numbers[4]{ 
			std::stol(parts[0]), 
			parts.size() > 2 ? std::stol(parts[1]) : 0,
			parts.size() > 3 ? std::stol(parts[2]) : 0,
			std::stol(parts[parts.size() - 1]),
		};
		this->ip = 0;
		for(int i = 0; i < 4; i++){
			if(numbers[i] >= 0 && numbers[i] <= 255){
				this->ip = (std::get<uint32_t>(this->ip) << 8) | numbers[i];
			} else{
				throw std::exception("Invalid IP!");
			}
		}
	} else if(ip.find(L':') != ip.npos){
		type = Version::IPv6;
		if(ip.find(L"::") != ip.npos){
			auto halves{ SplitStringW(ip, L"::") };
			assert(halves.size() == 2);

			for(int i = 0; i < 8; i++){
				std::get<uint16_t[8]>(this->ip)[i] = 0;
			}

			int total = 0;
			for(int i = 0; i < 2; i++){
				auto parts{ SplitStringW(ip, L":") };
				total += parts.size();

				auto idx{ i == 0 ? 0 : 8 - parts.size()};
				for(auto& part : parts){
					auto val{ std::stol(part, nullptr, 16) };
					if(val >= 0 && val <= 0xFFFF){
						std::get<uint16_t[8]>(this->ip)[idx++] = val;
					} else{
						throw std::exception("Invalid IP!");
					}
				}
			}
			assert(total <= 8);
		} else{
			auto parts{ SplitStringW(ip, L":") };
			assert(parts.size() == 8);

			auto idx{ 0ul };
			for(auto& part : parts){
				auto val{ std::stol(part, nullptr, 16) };
				if(val >= 0 && val <= 0xFFFF){
					std::get<uint16_t[8]>(this->ip)[idx++] = val;
				} else{
					throw std::exception("Invalid IP!");
				}
			}
		}
	} else{
		throw std::exception("Malformed IP!");
	}
}

IP::IP(uint32_t ip) : type{ Version::IPv4 }, ip{ ip }{}
IP::IP(uint16_t ip[8]) : type{ Version::IPv6 }{
	for(int i = 0; i < 8; i++){
		std::get<uint16_t[8]>(this->ip)[i] = ip[i];
	}
}
std::wstring IP::ToString() const {
	if(type == Version::IPv4){
		auto ip{ std::get<uint32_t>(this->ip) };
		return std::to_wstring(ip >> 24) + L"." + std::to_wstring((ip >> 16) & 0xFF) + L"." + 
			std::to_wstring((ip >> 8) & 0xFF) + L"." + std::to_wstring(ip & 0xFF);
	} else{
		std::pair<int, int> best;
		int start = 0;
		for(int i = 0; i < 8; i++){
			if(std::get<uint16_t[8]>(ip)[i] != 0){
				if(i - start > best.second){
					best = std::make_pair(start, i - start);
				}
				start = i + 1;
			}
		}
		std::wstringstream str{};
		for(int i = 0; i < (best.second == 0 ? 7 : best.first); i++){
			str << std::hex << std::get<uint16_t[8]>(ip)[i] << L":";
		}
		if(best.second == 0){
			str << std::hex << std::get<uint16_t[8]>(ip)[7];
		} else{
			for(int i = best.first + best.second; i < 8; i++){
				str << L":" << std::hex << std::get<uint16_t[8]>(ip)[i];
			}
		}
		return str.str();
	}
}

IPRange::IPRange(const IP& singleIP) : minIP(singleIP), maxIP(singleIP){}

IPRange::IPRange(const IP& minIP, const IP& maxIP) : minIP(minIP), maxIP(maxIP){
	assert(minIP.type == maxIP.type);
}

bool IPRange::IPInRange(const IP& ip) const {
	if(ip.type != minIP.type){
		return false;
	}
	if(ip.type == IP::Version::IPv4){
		return std::get<uint32_t>(minIP.ip) <= std::get<uint32_t>(ip.ip) && 
			std::get<uint32_t>(ip.ip) <= std::get<uint32_t>(maxIP.ip);
	} else{
		for(int i = 0; i < 8; i++){
			if(std::get<uint16_t[8]>(ip.ip)[i] > std::get<uint16_t[8]>(minIP.ip)[i]){
				break;
			} else if(std::get<uint16_t[8]>(ip.ip)[i] < std::get<uint16_t[8]>(minIP.ip)[i]){
				return false;
			}
		}
		for(int i = 0; i < 8; i++){
			if(std::get<uint16_t[8]>(ip.ip)[i] > std::get<uint16_t[8]>(maxIP.ip)[i]){
				return false;
			} else if(std::get<uint16_t[8]>(ip.ip)[i] < std::get<uint16_t[8]>(minIP.ip)[i]){
				break;
			}
		}
		return true;
	}
}

std::wstring IPRange::ToString() const{ return minIP.ToString() + L" - " + maxIP.ToString(); };

FirewallBasePolicy::FirewallBasePolicy(json config) : MitigationPolicy(config){
	assert(config.find("default-action") != config.end());

	auto default{ config["default-action"].get<std::string>() };
	if(CompareIgnoreCaseA(default, "block")){
		defaultAction = FirewallAction::BLOCK;
	} else if(CompareIgnoreCaseA(default, "allow")){
		defaultAction = FirewallAction::ALLOW;
	} else{
		throw std::exception(("Invalid default action: " + default).c_str());
	}

	if(config.find("allow-preexisting") != config.end()){
		allowPreexisting = config["allow-preexisting"].get<bool>();
	} else{
		allowPreexisting = true;
	}

	if(config.find("rules") != config.end()){
		for(auto& rule : rules){
			this->rules.emplace_back(FirewallRulePolicy{ rule });
		}
	}
}

FirewallRulePolicy::FirewallRulePolicy(json config) : MitigationPolicy(config){
	assert(config.find("direction") != config.end());
	assert(config.find("action") != config.end());

	if(config.find("protocol") != config.end()){

	}
	if(config.find("ports") != config.end()){

	}
	if(config.find("scoped-programs") != config.end()){

	}
	if(config.find("scoped-services") != config.end()){

	}
	if(config.find("destination-ips") != config.end()){

	}
	if(config.find("source-ips") != config.end()){

	}
}