#pragma once
#include <Windows.h>

namespace BLUESPAWN::Agent {

	/**
	 * \brief Performs initialization actions when the agent DLL is loaded.
	 *
	 * \details
	 *
	 * \return Returns true if the function succeeds; false otherwise
	 */
	_Success_(return == true)
	bool PerformAttachActions();

	/**
	 * \brief
	 *
	 * \details
	 *
	 * \return
	 */
	_Success_(return == true)
	bool PerformDetachActions();
}