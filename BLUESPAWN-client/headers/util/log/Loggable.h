#pragma once

#include <string>

/**
 *  Loggable is an interface classes must inherit from if they are fed
 *  directly to the logger. 
 */
class Loggable {
public:
	/**
	 *  ToString should return a string representation of the class.
	 *
	 *  @return A string representation of the class.
	 */
	virtual std::wstring ToString() const = 0;
};

