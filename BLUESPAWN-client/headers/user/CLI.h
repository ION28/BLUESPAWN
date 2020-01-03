#pragma once

#include "user/iobase.h"

#include <map>

/**
 * This class serves as a way for BLUESPAWN's modules to interact with the user through a command line interface.
 * This class acts as a pseudo-singleton, permitting only one instance per input-output handle pair.
 */
class CLI : public IOBase {
private:
	static std::map<std::pair<HANDLE, HANDLE>, CLI> instances;
	static const HANDLE hDefaultOutput;
	static const HANDLE hDefaultInput;

	const HANDLE input;
	const HANDLE output;

	/**
	 * Creates a new CLI object with a given input and output handle.
	 *
	 * @param output A handle to the file-like object to which output will be written. This is the console by default.
	 * @param input A handle to the file-like object from which input will be read. This is the console by default.
	 */
	CLI(const HANDLE output, const HANDLE input);

public:

	/**
	 * Returns a reference to a CLI object for the given input and output handles. If one already exists, it will be returned.
	 * Otherwise, a new instance will be created and returned.
	 *
	 * @param output A handle to the file-like object to which output will be written. This is the console by default.
	 * @param input A handle to the file-like object from which input will be read. This is the console by default.
	 *
	 * @return A reference to a CLI object to be used for user IO.
	 */
	static const CLI& GetInstance(const HANDLE output = hDefaultOutput, const HANDLE input = hDefaultInput);

	/**
	 * This method displays a prompt to the user and presents a number of options. The user may select from among the provided
	 * options. If no valid option has been selected by the time the maximum delay is exceeded, an empty string will be returned.
	 * Otherwise, the returned string is guaranteed to be present in the provided options, or if no options are provided, it will
	 * be empty. Note that calling this function with no options is equivalent to calling AlertUser.
	 *
	 * @param prompt The prompt to display to the user
	 * @param options The options from which the user may choose
	 * @param dwMaximumDelay The maximum delay before returning an empty string, in milliseconds
	 *
	 * @return The option that the user chose, or an empty string if no options were provided.
	 */
	virtual std::string GetUserSelection(const std::string& prompt, const std::set<std::string>& options,
		DWORD dwMaximumDelay = -1) const;

	/**
	 * This method displays a message to the user. No action is required for this function to return.
	 *
	 * @param information The message to be displayed to the user.
	 */
	virtual void InformUser(const std::string& information) const;

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
	virtual bool AlerUser(const std::string& information, DWORD dwMaximumDelay = -1) const;

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
	virtual DWORD GetUserConfirm(const std::string& prompt, DWORD dwMaximumDelay = -1) const;
};

