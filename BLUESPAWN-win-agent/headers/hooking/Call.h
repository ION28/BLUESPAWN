#pragma once

#include <Windows.h>

#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "Address.h"
#include "Argument.h"

namespace BLUESPAWN::Agent{

	/**
	 * \brief Represents a call to a function, containing the full stack trace and all arguments being passed
	 */
	class Call : public Address {

		/// The call stack for this function call, not including this call.
		std::vector<Address> callStack;

		/// A vector containing the arguments passed into the function call. Note that for each possible Call being
		/// created, an enum should exist mapping the parameter names to indexes into this vector.
		std::vector<Argument> arguments;

	public:

		/**
		 * \brief Construct a call object using the provided call stack and arguments
		 *
		 * \param[in] callStack The call stack leading up to the call being described by this
		 * \param[in] arguments The arguments passed into the function call
		 */
		Call(_In_ const std::vector<Address>& callStack, _In_ const std::vector<Argument>& arguments);

		/**
		 * \brief Construct a call object using the provided call stack and arguments
		 *
		 * \param[in] callStack The call stack leading up to the call being described by this
		 * \param[in] arguments The arguments passed into the function call
		 */
		Call(_In_ std::vector<Address>&& callStack, _In_ std::vector<Argument>&& arguments);
	};
}