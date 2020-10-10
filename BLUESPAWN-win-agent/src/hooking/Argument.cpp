#include "hooking/Argument.h"

namespace BLUESPAWN::Agent{
	namespace Value{
		String::String(_In_ const char* lpszCString) : String{ std::string(lpszCString) }{}
		String::String(_In_ const wchar_t* lpszWString) : string{ lpszWString }{}
		String::String(_In_ const std::string& str) : string(str.begin(), str.end()){}
		String::String(_In_ const std::wstring& str) : string{ str }{}
		String::String(_In_ PUNICODE_STRING str) : string{ str->Buffer, str->Length }{}

		Struct::Struct(_In_ const std::type_index& info, _In_ LPVOID lpPointer, _In_ DWORD dwSize) :
			info{ info }, lpStructPointer{ lpPointer }, lpUnderlyingData{ std::make_shared<byte[]>(dwSize) }{
			MoveMemory(lpUnderlyingData.get(), lpPointer, dwSize);
		}

		Enum::Enum(_In_ DWORD dwIntegerValue, _In_ const std::wstring& name) :
			dwIntegerValue{ dwIntegerValue }, name{ name }{}

		Handle::Handle(_In_ HANDLE hHandle) : hHandle{ hHandle }, type{ Util::GetHandleType(hHandle) },
			name{ Util::GetHandleName(hHandle) }{}

		Pointer::Pointer(_In_ LPVOID lpPointer, _In_ const std::optional<ArgumentData>& data) :
			pointer{ lpPointer }, pointee{ data ? std::make_shared<ArgumentData>(*data) : nullptr }{}
	};

	Argument::Argument(_In_ const Value::Number& value) : type{ ArgumentType::Numerical }, value{ value }{}
	Argument::Argument(_In_ const Value::OutPointer& value) : type{ ArgumentType::OutPointer }, value{ value }{}
	Argument::Argument(_In_ const Value::String& value) : type{ ArgumentType::String }, value{ value }{}
	Argument::Argument(_In_ const Value::Struct& value) : type{ ArgumentType::Struct }, value{ value }{}
	Argument::Argument(_In_ const Value::Enum& value) : type{ ArgumentType::Enum }, value{ value }{}
	Argument::Argument(_In_ const Value::Handle& value) : type{ ArgumentType::Handle }, value{ value }{}
	Argument::Argument(_In_ const Value::Pointer& value) : type{ ArgumentType::Pointer }, value{ value }{}
};