#include "common/Utils.h"
#include "util/linuxcompat.h"
#include <sys/stat.h>

#include <iostream>
#include <sstream>
#include <iomanip>


std::string FormatStatTime(const struct statx_timestamp ft) {
	time_t seconds = (time_t) ft.tv_sec;
	struct tm * st = localtime(&seconds); //TODO: Should this be freed?
	std::stringstream w;
	w << std::setfill('0') << std::to_string(st->tm_year) << "-" << std::setw(2) << std::to_string(st->tm_mon) << "-" << std::setw(2) << std::to_string(st->tm_mday) << " " <<
		std::setw(2) << std::to_string(st->tm_hour) << ":" << std::setw(2) << std::to_string(st->tm_min) << ":" << std::setw(2) << std::to_string(st->tm_sec) << "." << "Z";
	return w.str();
}