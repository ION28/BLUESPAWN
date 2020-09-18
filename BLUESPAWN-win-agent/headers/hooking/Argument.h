#pragma once

#include <Windows.h>

#include <variant>
#include <string>
#include <memory>
#include <optional>

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
		};

		/**
		 * \brief Refers to a pointer to a memory address that will receive a value from the function
		 */
		struct OutPointer {

			/// The address to which some function output will be written
			LPVOID lpAddress;

			/// Indicates whether this pointer refers to a buffer (true) or a value (false)
			bool buffer;
		};

		/**
		 * \brief Refers to a string passed into a function. Generally, this can be an LPSTR, LPWSTR, or 
		 *		  PUNICODE_STRING.
		 */
		struct String {

			/// Stores the value of the string passed to the function. 
			std::wstring string;

		};

		/**
		 * \brief Refers to a struct passed into a function, either by value, reference, or pointer
		 */
		struct Struct {

			/// The data underlying the struct
			std::shared_ptr<byte[]> lpUnderlyingData;

			/// The type information of the struct
			std::type_info info;
		};

		/**
		 * \brief Refers to an enum passed into a function
		 */
		struct Enum {

			/// The integer value of the enum
			DWORD dwIntegerValue;

			/// The name of the enum
			std::wstring name;
		};

		/**
		 * \brief Refers to a handle passed into a function
		 */
		struct Handle {

			/// Refers to the various types of HANDLEs
			enum class Type{
				Process,
				Thread,
				File,
				Pipe,
				Synchronization, // Refers to a synchronization object such as an event or mutex
				RegistryKey,
				ETW,
				Directory,
				Section,
				ALPCPort,
				Mutant,
				Token,
				Other
			};

			/// The value of the handle passed to the function
			std::shared_ptr<HANDLE> hHandle;

			/// The type of the handle
			Type type;

			/// The name of the object to which the handle refers, if available
			std::optional<std::wstring> name;
		};

		/**
		 * \brief Refers to a pointer passed into a function
		 */
		struct Pointer {

			/// The value of the pointer
			LPVOID lpPointer;
			
			/// A copy of the data being pointed to, if available; nullptr if not availabe.
			std::unique_ptr<std::variant<Value::Number, Value::OutPointer, Value::String, Value::Struct,
				                         Value::Enum, Value::Handle, Value::Pointer>> pointee;
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
	};
};