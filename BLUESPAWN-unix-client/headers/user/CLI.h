#pragma once

#include "user/iobase.h"
#include "common/wrappers.hpp"

#include <map>

/**
 * This class serves as a way for BLUESPAWN's modules to interact with the user through a command line interface.
 * This class acts as a pseudo-singleton, permitting only one instance per input-output handle pair.
 */
class CLI : public IOBase {
private:
	pthread_mutex_t hMutex;

	/**
	 * Creates a new CLI object with a given input and output handle.
	 *
	 */
	CLI();

	~CLI();

	static const CLI instance;

public:

	static const CLI& GetInstance();

	/**
	 * This method displays a prompt to the user and presents a number of options. The user may select from among the provided
	 * options. If no valid option has been selected by the time the maximum delay is exceeded, an empty wstring will be returned.
	 * Otherwise, the returned wstring is guaranteed to be present in the provided options, or if no options are provided, it will
	 * be empty. Note that calling this function with no options is equivalent to calling AlertUser.
	 *
	 * @param prompt The prompt to display to the user
	 * @param options The options from which the user may choose
	 * @param dwMaximumDelay The maximum delay before returning an empty wstring, in milliseconds
	 *
	 * @return The option that the user chose, or an empty wstring if no options were provided.
	 */
	virtual std::string GetUserSelection(const std::string& prompt, const std::vector<std::string>& options,
		unsigned int dwMaximumDelay = -1, ImportanceLevel level = ImportanceLevel::LOW) const;

	/**
	 * This method displays a message to the user. No action is required for this function to return.
	 *
	 * @param information The message to be displayed to the user.
	 */
	virtual void InformUser(const std::string& information, ImportanceLevel level = ImportanceLevel::LOW) const;

	/**
	 * This method displays a message to the user. This will not return until the user acknowledges the message or
	 * the timeout occurs. Passing a value of INFINITY to dwMaximumDelay will indicate that the only case in which
	 * this function should return is when the user acknowledges the message.
	 *
	 * @param information The message to be displayed to the user.
	 * @param dwMaximumDelay The maximum delay before returning, in milliseconds.
	 *
	 * @return True if the user acknowledged the message, false otherwise.
	 */
	virtual bool AlertUser(const std::string& information, unsigned int dwMaximumDelay = -1, ImportanceLevel level = ImportanceLevel::LOW) const;

	/**
	 * This method displays a confirmation message to the user. This will display the prompt and three options:
	 * cancel, yes, or no. This will not return until the user has selected an option or until the maximum delay
	 * is exceeded, whichever comes first. If a timeout occurs or the user chooses cancel, -1 will be returned.
	 * If the user responds no, 0 is returned. If the user responds yes, 1 is returned.
	 *
	 * @param information The message to be displayed to the user.
	 * @param dwMaximumDelay The maximum delay before returning, in milliseconds.
	 *
	 * @return If a timeout occurs or the user chooses cancel, -1 will be returned. If the user responds no, 0 is
	 * returned. If the user responds yes, 1 is returned.
	 */
	virtual unsigned int GetUserConfirm(const std::string& prompt, unsigned int dwMaximumDelay = -1, ImportanceLevel level = ImportanceLevel::LOW) const;

	const pthread_mutex_t& GetMutex() const;
};

enum class MessageColor{
	RESET = 0,
	BLACK,
	RED,
	GREEN,
	YELLOW,
	BLUE,
	MAGENTA,
	CYAN,
	WHITE,
	BOLDBLACK,
	BOLDRED,
	BOLDGREEN,
	BOLDYELLOW,
	BOLDBLUE,
	BOLDMAGENTA,
	BOLDCYAN,
	BOLDWHITE
};


/**
 * Converts an enum MessageColor to a string that contains a color code
 * @param enum MessageColor for color
 * @return the resulting color string
 */ 
std::string GetColorStr(const enum MessageColor color);


