#pragma once

#include <Windows.h>

#include <vector>
#include <string>
#include <set>

enum class ImportanceLevel {
	LOW = 0,
	MEDIUM = 1,
	HIGH = 2
};

/**
 * This class is used to serve as an abstract interface for all user interfaces. User interfaces will
 * implement at least the methods defined here, either in GUI form or in CLI form.
 *
 * Other modules and subsystems in BLUESPAWN will refrain from user interaction not managed through this
 * IO base.
 */
class IOBase {

public: 

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
	virtual std::wstring GetUserSelection(const std::wstring& prompt, const std::vector<std::wstring>& options, 
		DWORD dwMaximumDelay = -1, ImportanceLevel level = ImportanceLevel::LOW) const = 0;

	/**
	 * This method displays a message to the user. No action is required for this function to return.
	 *
	 * @param information The message to be displayed to the user.
	 */
	virtual void InformUser(const std::wstring& information, ImportanceLevel level = ImportanceLevel::LOW) const = 0;

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
	virtual bool AlertUser(const std::wstring& information, DWORD dwMaximumDelay = -1, ImportanceLevel level = ImportanceLevel::LOW) const = 0;

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
	virtual DWORD GetUserConfirm(const std::wstring& prompt, DWORD dwMaximumDelay = -1, ImportanceLevel level = ImportanceLevel::LOW) const = 0;
};