#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>

#include <cxxopts.hpp>

#include "CollectInfo.h"
#include "Output.h"
#include "Registry.h"
#include "Hunts.h"
#include "FileSystem.h"

using namespace std;

void print_banner() {
	vector<std::string> banners = {
		R"(
    _/_/_/    _/        _/    _/  _/_/_/_/    _/_/_/  _/_/_/      _/_/    _/          _/  _/      _/   
   _/    _/  _/        _/    _/  _/        _/        _/    _/  _/    _/  _/          _/  _/_/    _/    
  _/_/_/    _/        _/    _/  _/_/_/      _/_/    _/_/_/    _/_/_/_/  _/    _/    _/  _/  _/  _/     
 _/    _/  _/        _/    _/  _/              _/  _/        _/    _/    _/  _/  _/    _/    _/_/      
_/_/_/    _/_/_/_/    _/_/    _/_/_/_/  _/_/_/    _/        _/    _/      _/  _/      _/      _/       
)",
		R"(
 ____  ____  ____  ____  ____  ____  ____  ____  ____ 
||B ||||L ||||U ||||E ||||S ||||P ||||A ||||W ||||N ||
||__||||__||||__||||__||||__||||__||||__||||__||||__||
|/__\||/__\||/__\||/__\||/__\||/__\||/__\||/__\||/__\|
)",
		R"(
________ ______ _____  ____________________________ _______ ___       _______   __
___  __ )___  / __  / / /___  ____/__  ___/___  __ \___    |__ |     / /___  | / /
__  __  |__  /  _  / / / __  __/   _____ \ __  /_/ /__  /| |__ | /| / / __   |/ / 
_  /_/ / _  /___/ /_/ /  _  /___   ____/ / _  ____/ _  ___ |__ |/ |/ /  _  /|  /  
/_____/  /_____/\____/   /_____/   /____/  /_/      /_/  |_|____/|__/   /_/ |_/   
)",
		R"(
 /$$$$$$$  /$$       /$$   /$$ /$$$$$$$$  /$$$$$$  /$$$$$$$   /$$$$$$  /$$      /$$ /$$   /$$
| $$__  $$| $$      | $$  | $$| $$_____/ /$$__  $$| $$__  $$ /$$__  $$| $$  /$ | $$| $$$ | $$
| $$  \ $$| $$      | $$  | $$| $$      | $$  \__/| $$  \ $$| $$  \ $$| $$ /$$$| $$| $$$$| $$
| $$$$$$$ | $$      | $$  | $$| $$$$$   |  $$$$$$ | $$$$$$$/| $$$$$$$$| $$/$$ $$ $$| $$ $$ $$
| $$__  $$| $$      | $$  | $$| $$__/    \____  $$| $$____/ | $$__  $$| $$$$_  $$$$| $$  $$$$
| $$  \ $$| $$      | $$  | $$| $$       /$$  \ $$| $$      | $$  | $$| $$$/ \  $$$| $$\  $$$
| $$$$$$$/| $$$$$$$$|  $$$$$$/| $$$$$$$$|  $$$$$$/| $$      | $$  | $$| $$/   \  $$| $$ \  $$
|_______/ |________/ \______/ |________/ \______/ |__/      |__/  |__/|__/     \__/|__/  \__/
)",
		R"(
FFFFFFD FFD     FFD   FFDFFFFFFFDFFFFFFFDFFFFFFD  FFFFFD FFD    FFDFFFD   FFD
FFAEEFFDFFG     FFG   FFGFFAEEEECFFAEEEECFFAEEFFDFFAEEFFDFFG    FFGFFFFD  FFG
FFFFFFACFFG     FFG   FFGFFFFFD  FFFFFFFDFFFFFFACFFFFFFFGFFG FD FFGFFAFFD FFG
FFAEEFFDFFG     FFG   FFGFFAEEC  BEEEEFFGFFAEEEC FFAEEFFGFFGFFFDFFGFFGBFFDFFG
FFFFFFACFFFFFFFDBFFFFFFACFFFFFFFDFFFFFFFGFFG     FFG  FFGBFFFAFFFACFFG BFFFFG
BEEEEEC BEEEEEEC BEEEEEC BEEEEEECBEEEEEECBEC     BEC  BEC BEECBEEC BEC  BEEEC
)"
	};

	std::replace(banners.at(4).begin(), banners.at(4).end(), 'A', (char)201u);
	std::replace(banners.at(4).begin(), banners.at(4).end(), 'B', (char)200u);
	std::replace(banners.at(4).begin(), banners.at(4).end(), 'C', (char)188u);
	std::replace(banners.at(4).begin(), banners.at(4).end(), 'D', (char)187u);
	std::replace(banners.at(4).begin(), banners.at(4).end(), 'E', (char)205u);
	std::replace(banners.at(4).begin(), banners.at(4).end(), 'F', (char)219u);
	std::replace(banners.at(4).begin(), banners.at(4).end(), 'G', (char)186u);

	srand(time(NULL));

	SetConsoleColor("cyan");
	std::cout << banners.at(std::rand() % banners.size()) << std::endl;
	SetConsoleColor("white");
}

void print_help(cxxopts::ParseResult result, cxxopts::Options options) {
	std::string help_category = result["help"].as < std::string >();

	std::transform(help_category.begin(), help_category.end(),
		help_category.begin(), [](unsigned char c) { return std::tolower(c); });

	if (help_category.compare("hunt") == 0) {
		std::cout << options.help({ "hunt" }) << std::endl;
	}
	else if (help_category.compare("general") == 0) {
		std::cout << options.help() << std::endl;
	}
	else {
		std::cerr << "Unknown help category" << std::endl;
	}
}

void dispatch_hunt(cxxopts::ParseResult result, cxxopts::Options options) {
	std::string hunt_level = "Moderate";
	if (result.count("level")) {
		try {
			hunt_level = result["level"].as < std::string >();
		}
		catch (int e) {
			std::cerr << "Unknown hunt level. Please specify either Cursory, Moderate, Careful, or Aggressive" << std::endl;
		}
	}

	std::cout << "Doing a hunt at level " << hunt_level << std::endl;
}

int main(int argc, char* argv[])
{
	print_banner();

	cxxopts::Options options("BLUESPAWN.exe", "BLUESPAWN: A Windows based Active Defense Tool to empower Blue Teams");

	options.add_options()
		("h,hunt", "Perform a Hunt Operation", cxxopts::value<bool>())
		("help", "Help Information. You can also specify a category for help on a specific module such as hunt"
			, cxxopts::value<std::string>()->implicit_value("general"))
		;

	options.add_options("hunt")
		("l,level", "Aggressiveness of Hunt. Either Cursory, Moderate, Careful, or Aggressive", 
			cxxopts::value<std::string>())
		;

	options.parse_positional({ "help", "level" });
	auto result = options.parse(argc, argv);
	
	if (result.count("help")) {
		print_help(result, options);
	}
	else if (result.count("hunt")) {
		dispatch_hunt(result, options);
	}
	else {
		std::cout << "Nothing to do. Use the -h or --hunt flags to launch a hunt" << std::endl;
	}
}