#pragma once

#include <Windows.h>
#include <winternl.h>

#include <variant>
#include <string>
#include <memory>
#include <optional>
#include <typeindex>

#include "utils/HandleInfo.h"
#include "hooking/Address.h"

namespace BLUESPAWN::Agent{

	/**
	 * \brief Describes the supported argument types for the Argument class. Note that some arguments may be classified
	 *	      as multiple types described here (such as when an integer argument actually refers to an enum). When this
	 *        occurs, it is best to select the most specific option available here.
	 */
	enum class ArgumentType {
		Numerical,  // Refers to a numerical argument
		OutPointer, // Refers to a pointer to a memory address that will receive a value from the function
		String,     // Refers to a string used by the function
		Struct,     // Refers to a struct used by the function
		Enum,       // Refers to an enum used by the function
		Handle,     // Refers to a handle used by the function
		Pointer,    // Refers to a pointer used by the function
	};

	namespace Value{

		/**
		 * \brief Refers to a numerical argument of up to 64 bits.
		 */
		struct Number {

			/// The size of the number, in bits. This must be less than 64
			BYTE dwSize;

			/// True if the number is signed; 
			bool isSigned;

			/// The value of the argument, converted to an unsigned 64-bit number.
			uint64_t data;

			// Implicit casts to the most common (non-bitfield) types of integers
			constexpr inline operator uint64_t() const{ return dwSize; };
			constexpr inline operator uint32_t() const{ return static_cast<uint32_t>(dwSize); };
			constexpr inline operator uint16_t() const{ return static_cast<uint16_t>(dwSize); };
			constexpr inline operator uint8_t() const{ return static_cast<uint8_t>(dwSize); };
			constexpr inline operator int64_t() const{ return static_cast<int64_t>(dwSize); };
			constexpr inline operator int32_t() const{ return static_cast<int32_t>(dwSize); };
			constexpr inline operator int16_t() const{ return static_cast<int16_t>(dwSize); };
			constexpr inline operator int8_t() const{ return static_cast<int8_t>(dwSize); };

			/**
			 * \brief Constructs a Number referencing an unsigned 32 bit integer
			 *
			 * \param[in] dwValue The value of this number
			 */
			constexpr inline Number(_In_ DWORD dwValue) : data{ dwValue }, dwSize{ 32 }, isSigned{ false }{}

			/**
			 * \brief Constructs a Number referencing an unsigned 64 bit integer
			 *
			 * \param[in] dwValue The value of this number
			 */
			constexpr inline Number(_In_ DWORD64 dwValue) : data{ dwValue }, dwSize{ 64 }, isSigned{ false }{}

			/**
			 * \brief Constructs a Number referencing an integer with the specified number of bits and signedness
			 *
			 * \param[in] dwValue  The value of this number
			 * \param[in] bits     The number of bits in the number
			 * \param[in] isSigned A boolean indicated whether or not the number should be signed
			 */
			constexpr inline Number(_In_ DWORD64 dwValue, _In_ BYTE bits, _In_ bool isSigned) :
				data{ dwValue }, dwSize{ bits }, isSigned{ isSigned }{}
		};

		/**
		 * \brief Refers to a pointer to a memory address that will receive a value from the function
		 */
		struct OutPointer {

			/// The address to which some function output will be written
			LPVOID lpAddress;

			/// Indicates whether this pointer refers to a buffer (true) or a value (false)
			bool buffer;

			/**
			 * \brief Constructs an Outpointer referring to a specified address
			 * 
			 * \param[in] lpAddress The address being pointed to
			 * \param[in] buffer    Indicates whether this pointer refers to a buffer (true) or a value (false)
			 */
			constexpr inline OutPointer(LPVOID lpAddress, bool buffer) : lpAddress{ lpAddress }, buffer{ buffer }{}
		};

		/**
		 * \brief Refers to a string passed into a function. Generally, this can be an LPSTR, LPWSTR, or 
		 *		  PUNICODE_STRING.
		 */
		struct String {

			/// Stores the value of the string passed to the function. 
			std::wstring string;

			/**
			 * \brief Constructs a String object from a C-style string
			 * 
			 * \param[in] A pointer to a null terminated C-style string
			 */
			String(_In_ const char* lpszCString);

			/**
			 * \brief Constructs a String object from a C-style widestring
			 * 
			 * \param[in] A pointer to a null terminated C-style widestring
			 */
			String(_In_ const wchar_t* lpszCWString);

			/**
			 * \brief Constructs a String object from a pointer to a UNICODE_STRING struct
			 *
			 * \param[in] A pointer to a UNICODE_STRING struct
			 */
			String(_In_ const PUNICODE_STRING lpszUString);

			/**
			 * \brief Constructs a String object from an STL wstring object
			 *
			 * \param[in] The string to copy
			 */
			String(_In_ const std::wstring& string);

			/**
			 * \brief Constructs a String object from an STL string object
			 *
			 * \param[in] The string to copy
			 */
			String(_In_ const std::string& string);
		};

		/**
		 * \brief Refers to a struct passed into a function, either by value, reference, or pointer
		 */
		struct Struct {

			/// A pointer to the struct's location in memory. Note that it should be assumed that the struct is no
			/// longer at this location; this is merely for record keeping and for adjusting offsets in the data.
			LPVOID lpStructPointer;

			/// The data underlying the struct
			std::shared_ptr<byte[]> lpUnderlyingData;

			/// The type information of the struct
			std::type_index info;

			/**
			 * \brief Constructs a Struct object using a pointer to the struct being passed.
			 * 
			 * \details Records the type information of the struct in `info` and attempts to copy the value of the 
			 *          struct. In cases where the struct includes more bytes than sizeof would indicate such as with
			 *          structs that contain a string or variable sized array,
			 * 
			 * \param[in] value  A pointer to the struct being passed.
			 * \param[in] dwSize The size of the struct in memory, which defaults to the size indicated by sizeof
			 */
			template<class T>
			inline Struct(_In_ const T* value, _In_opt_ DWORD dwSize = sizeof(T)) : 
				info{ typeid(T) }, 
				lpUnderlyingData{ std::make_shared<byte[]>(value ? dwSize : 0) }{
				
				if(value){
					CopyMemory(lpUnderlyingData.get(), value, dwSize);
				}
			}

			/**
			 * \brief Constructs a Struct object using the type information, the memory address of the struct, and the
			 *        size of the struct.
			 * 
			 * \param[in] info      The type information for the struct, constructed with the result of typeof
			 * \param[in] lpPointer The address in memory of the struct
			 * \param[in] dwSize    The size of the struct in memory
			 */
			Struct(_In_ const std::type_index& info, _In_ LPVOID lpPointer, _In_ DWORD dwSize);
		};

		/**
		 * \brief Refers to an enum passed into a function
		 */
		struct Enum {

			/// The integer value of the enum
			DWORD dwIntegerValue;

			/// The name of the value of enum
			std::wstring name;

			Enum(_In_ DWORD dwIntegerValue, _In_ const std::wstring& name);

/// Instantiates an Enum using the value of the enum only
#define ValueCreateEnum(value) \
    BLUESPAWN::Agent::Value::Enum(static_cast<DWORD>(value), L"" #value);
		};

		/**
		 * \brief Refers to a handle passed into a function
		 */
		struct Handle {

			/// The value of the handle passed to the function. Note that the handle may be closed, so this should only
			/// be used for record-keeping purposes.
			HANDLE hHandle;

			/// The type of the handle
			HandleType type;

			/// The name of the object to which the handle refers, if available
			std::optional<std::wstring> name;

			/**
			 * \brief Constructs a Handle object using a WINAPI handle. This will automatically deduce information such
			 *        as handle type and name.
			 * 
			 * \param[in] hHandle The value of the handle being passed into a function
			 */
			Handle(_In_ HANDLE hHandle);
		};

		/**
		 * \brief Refers to a pointer passed into a function
		 */
		struct Pointer {

			/// The value of the pointer
			Address pointer;
			
			/// A copy of the data being pointed to, if available; nullptr if not availabe.
			std::shared_ptr<std::variant<Value::Number, Value::OutPointer, Value::String, Value::Struct,
				                         Value::Enum, Value::Handle, Value::Pointer>> pointee;

			/**
			 * \brief Constructs a Pointer object using the address the pointer is pointing too an an optional pointee
			 * 
			 * \param[in] lpAddress The address to which the pointer being passed is referencing
			 * \param[in] pointee   The value to which this pointer refers
			 */
			Pointer(
				_In_ LPVOID lpAddress, 
				_In_opt_ const std::optional<
				    std::variant<Value::Number, Value::OutPointer, Value::String, Value::Struct, Value::Enum, 
				                 Value::Handle, Value::Pointer>>& pointee = std::nullopt);
		};
	}

	/// ArgumentData can refer to any type of argument struct
	typedef std::variant<Value::Number, Value::OutPointer, Value::String, Value::Struct, Value::Enum,
	                     Value::Handle, Value::Pointer> ArgumentData;

	/**
	 * \brief Stores the data related to an argument passed into a function using an STL variant
	 */
	class Argument {

		/// Describes the type of argument being stored in this object
		ArgumentType type;

		/// The value of the argument
		ArgumentData value;

	public:

		/**
		 * \brief Constructs an argument referencing a number
		 * 
		 * \param[in] value A Number object containing the value of the argument
		 */
		Argument(_In_ const Value::Number& value);

		/**
		 * \brief Constructs an argument referencing a pointer to which the called function will write some result
		 *
		 * \param[in] value An OutPointer object containing the value of the argument
		 */
		Argument(_In_ const Value::OutPointer& value);

		/**
		 * \brief Constructs an argument referencing a string
		 *
		 * \param[in] value A String object containing the value of the argument
		 */
		Argument(_In_ const Value::String& value);

		/**
		 * \brief Constructs an argument referencing a struct
		 *
		 * \param[in] value A Struct object containing the value of the argument
		 */
		Argument(_In_ const Value::Struct& value);

		/**
		 * \brief Constructs an argument referencing a string
		 *
		 * \param[in] value A String object containing the value of the argument
		 */
		Argument(_In_ const Value::Enum& value);

		/**
		 * \brief Constructs an argument referencing a handle
		 *
		 * \param[in] value A Handle object containing the value of the argument
		 */
		Argument(_In_ const Value::Handle& value);

		/**
		 * \brief Constructs an argument referencing a pointer
		 *
		 * \param[in] value A Pointer object containing the value of the argument
		 */
		Argument(_In_ const Value::Pointer& value);

		/**
		 * Retrieves the type of value passed as this argument.
		 * 
		 * \return An ArgumentType referencing the type of this argument
		 */
		constexpr inline ArgumentType GetType(){ return type; }

		/**
		 * Retrieves the value of the this argument
		 * 
		 * \return An ArgumentData object containing the value of this argument
		 */
		constexpr inline ArgumentData& GetValue(){ return value; }
	};
};