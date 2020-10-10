#pragma once

#include "hooking/Address.h"

namespace BLUESPAWN::Agent::Util {
	
	/**
	 * \brief Retrieves information about a memory address. If specified, this address may be in another process.
	 * 
	 * \param[in] lpAddress The address for which information will be retrieved.
	 * \param[in] hProcess  An optional handle to the process in which the address is located.
	 * 
	 * \return An Address object containing information about the requested address
	 */
	Address GetAddressInformation(_In_ LPVOID lpAddress, _In_opt_ HANDLE hProcess = GetCurrentProcess());
}