#pragma once

#include <Windows.h>

#include <optional>
#include <string>

namespace BLUESPAWN::Agent{

	/**
	 * \brief Represents an address and stores information about the memory at the address.
	 * 
	 * \details Note that the information stored in this class may become outdated and that this is only meant to
	 *          refer to the state of memory at the address at a snapshot in time.
	 */
	class Address {

		struct FunctionExtensions {
			std::string szFunctionName;
			std::wstring szLibraryName;
		};

		/// The image base address of the DLL or EXE in which the address is located
		HMODULE hImage;

		/// A pointer to the address.
		LPVOID lpPointer;

		/// Describes the page protections on the page containing the address
		DWORD dwPageProtections;

		/// Describes the page protections on the initial allocation for the memory containing this address
		DWORD dwAllocationProtections;

		/// Extensions to the definition of Address present if the address is referring to a function
		std::optional<FunctionExtensions> functionExtensions;

		/**
		 * \brief Queries the memory at lpPointer to automatically fill in hImage, dwPageProtections, and 
		 *        dwAllocationProtections. This function should only be called by constructors.
		 */
		void PrepareFields();

	public:

		/**
		 * \brief Creates an address object referring to the given address. Note that this will behave poorly with a
		 *        kernel address.
		 * 
		 * \param[in] lpPointer The address to which this object should refer.
		 */
		Address(_In_ LPVOID lpPointer);

		/**
		 * \brief Creates an address object referring to the address of the given function in the given library. 
		 *
		 * \details If the library is found but the function is not, hImage will refer to the base address of the 
		 *          library, but lpPointer will be null. If neither are found, then both will be null. In all cases,
		 *          the function extensions will be set.
		 * 
		 * \param[in] szLibrary  The name of the DLL in which the function can be found. Note that the DLL must already
		 *                       be loaded and able to be referenced via GetModuleHandle.
		 * \param[in] szFunction The name of the function whose address should be referenced by this object
		 */
		Address(_In_ const std::wstring& szLibrary, _In_ const std::string& szFunction);

		/**
		 * \brief Returns the image base address of the DLL or EXE in which the address is located
		 * 
		 * \details The initial allocation for the image must have been made via NtMapViewOfSection (or equivalent) and
		 *           have resulted memory with PAGE_EXECUTE_WRITECOPY page protections.
		 * 
		 * \return The image base address of the DLL or EXE in which the address is located
		 */
		constexpr inline HMODULE GetImage() const { return hImage; }

		/**
		 * \brief Returns a pointer to the address referenced by this object
		 * 
		 * \return A pointer to the address referenced by this object
		 */
		constexpr inline LPVOID GetPointer() const { return lpPointer; }

		/**
		 * \brief Returns the page protections on the address referenced by this object. This will be one of the WINAPI
		 *        page protection constants.
		 * 
		 * \return The page protections on the address referenced by this object
		 */
		constexpr inline DWORD GetPageProtections() const { return dwPageProtections; }

		/**
		 * \brief Returns the page protections on the initial allocation that included the address referenced by this 
		 *        object. This will be one of the WINAPI page protection constants.
		 *
		 * \return The page protections on the initial allocation that included the address referenced by this object.
		 */
		constexpr inline DWORD GetAllocationProtections() const { return dwAllocationProtections; }

		/**
		 * \brief Returns a reference to the function extensions stored in this object. If not present, this will be
		 *        std::nullopt. 
		 * 
		 * \details This reference should not be used after this object goes out of scope.
		 * 
		 * \return A reference to the function extensions stored in this object
		 */
		const std::optional<FunctionExtensions>& GetFunctionExtensions() const;
	};
}