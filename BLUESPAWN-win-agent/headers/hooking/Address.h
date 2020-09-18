#pragma once

#include <Windows.h>

#include <optional>
#include <string>

namespace BLUESPAWN::Agent{

	/**
	 * Represents an address.
	 */
	class Address {

		/// The image base address of the DLL or EXE in which the address is located
		HMODULE hImage;

		/// A pointer to the address.
		LPVOID lpPointer;

		/// Describes the page protections on the page containing the address
		DWORD dwPageProtections;

		/// Describes the page protections on the initial allocation for the memory containing this address
		DWORD dwAllocationProtections;

		/// Extensions to the definition of Address present if the address is referring to a function
		struct {

			/// The name of the function containing the address; nullopt if unknown
			std::optional<std::string> szFunctionName;
		} FunctionExtensions;
	};
}