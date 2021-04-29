#include "user/banners.h"

#include <algorithm>
#include <iostream>
#include <time.h>

#include "util/log/Log.h"

void print_banner() {
	// Put these in a file, then include that file in the resources for the exe

	std::replace(banners.at(4).begin(), banners.at(4).end(), 'A', (char)201u);
	std::replace(banners.at(4).begin(), banners.at(4).end(), 'B', (char)200u);
	std::replace(banners.at(4).begin(), banners.at(4).end(), 'C', (char)188u);
	std::replace(banners.at(4).begin(), banners.at(4).end(), 'D', (char)187u);
	std::replace(banners.at(4).begin(), banners.at(4).end(), 'E', (char)205u);
	std::replace(banners.at(4).begin(), banners.at(4).end(), 'F', (char)219u);
	std::replace(banners.at(4).begin(), banners.at(4).end(), 'G', (char)186u);

	srand(static_cast<unsigned int>(time(nullptr)));

	std::cout << banners.at(std::rand() % banners.size()) << std::endl;
}
