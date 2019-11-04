#pragma once

#include <string>

/**
 * Converts a wide-string to a UTF-8 encoded string
 *
 * @param in The widestring to convert
 *
 * @return The given wide-string converted to a UTF-8 encoded string
 */
std::string WidestringToString(const std::wstring& in);

/**
 * Converts a UTF-8 encoded string to a wide-string
 *
 * @param in The string to convert
 *
 * @return The string converted to a wide-string
 */
std::wstring StringToWidestring(const std::string& in);

/**
 * Convert a string or wstring to uppercase. Note that the only
 * allowable template classes are std::string and std::wstring.
 *
 * @param in The string/wstring to convert to uppercase.
 *
 * @return A copy of the given string, converted to uppercase.
 */
template<class T>
T ToUpperCase(const T& in);
#define ToUpperCaseA ToUpperCase<std::string>
#define ToUpperCaseW ToUpperCase<std::wstring>

/**
 * Convert a string or wstring to lowercase. Note that the only
 * allowable template classes are std::string and std::wstring.
 *
 * @param in The string/wstring to convert to lowercase.
 *
 * @return A copy of the given string, converted to lowercase.
 */
template<class T>
T ToLowerCase(const T& in);
#define ToLowerCaseA ToLowerCase<std::string>
#define ToLowerCaseW ToLowerCase<std::wstring>

/**
 * Compares two strings, ignoring case. Note that the only allowable
 * template classes are std::string and std::wstring.
 *
 * @param in1 The first string to compare
 * @param in2 The second string to compare.
 *
 * @return true if the two strings are equal; false otherwise.
 */
template<class T>
bool CompareIgnoreCase(const T& in1, const T& in2);
#define CompareIgnoreCaseA CompareIgnoreCase<std::string>
#define CompareIgnoreCaseW CompareIgnoreCase<std::wstring>