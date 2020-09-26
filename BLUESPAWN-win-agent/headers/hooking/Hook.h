#pragma once

#include <Windows.h>

#include <string>
#include <type_traits>

namespace BLUESPAWN::Agent::Hooks{

	template<class Func, class... Args>
	class Hook {
	protected:

		/// The name of the library in which the function is found
		std::wstring szLibraryName;

		/// The name of the function being hooked
		std::string szFunctionName;

		/// A pointer to the original function
		std::add_pointer_t<Func> lpOriginalFunction;

		/**
		 * \brief Instantiates a new Hook object and register the hook with the HookRegister
		 * 
		 * \details This constructor may only be called from within Hook subclasses.
		 *
		 * \param[in] szLibraryName  The name of the library in which the function is found
		 * \param[in] szFunctionName The name of the function to be hooked
		 * \param[in] type           A pointer to the subclass calling the constructor
		 */
		template<class HookType>
		Hook(_In_ const std::wstring& szLibraryName, _In_ const std::string& szFunctionName, HookType* type);

	public:

		/**
		 * \brief Calls the original function, ignoring the hook
		 * 
		 * \param args The arguments to the function
		 * 
		 * \return The return value from the original function
		 */
		std::invoke_result_t<Func, Args...> CallOriginal(Args&&... args) const{
			if(lpOriginalFunction){
				return lpOriginalFunction(args...);
			} else return {};
		}

		/**
		 * \brief The hook through which calls to the hooked functions will pass. This function should only be called
		 *        from within HookDelegate in HookRegister.h. Each hook subclass must override this function.
		 * 
		 * \param args The arguments being passed into the function
		 * 
		 * \return The return value from the hooked function
		 */
		virtual std::invoke_result_t<Func, Args...> HookFunc(Args... args) const = 0;
	};
};