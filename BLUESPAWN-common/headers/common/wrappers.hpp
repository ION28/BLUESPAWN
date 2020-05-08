#pragma once
#include <Windows.h>

#include <map>
#include <string>
#include <memory>
#include <optional>
#include <functional>

template<class T>
class GenericWrapper {
protected:
	std::shared_ptr<void> ReferenceCounter;

	T WrappedObject;
	T BadValue;

public:

	GenericWrapper(T object, std::function<void(T)> freeFunction = [](T object){ delete object; }, T BadValue = nullptr) : 
		WrappedObject{ object }, 
		BadValue{ BadValue },
		ReferenceCounter{ nullptr, [object, BadValue, freeFunction](LPVOID memory){ 
		    if(object != BadValue && object){ freeFunction(object); } 
	    }}{}

	operator T() const { return WrappedObject; }
	T* operator *(){ return WrappedObject; }
	T operator ->(){ return WrappedObject; }
	T& operator &(){ return &WrappedObject; }
	bool operator ==(T object){ return WrappedObject == object; }
	bool operator !(){ return !WrappedObject || WrappedObject == BadValue; }
	operator bool(){ return !operator!(); }

	T Get() const { return WrappedObject; }
};

class HandleWrapper : public GenericWrapper<HANDLE> {
public:
	HandleWrapper(HANDLE handle) :
		GenericWrapper(handle, std::function<void(HANDLE)>(CloseHandle), INVALID_HANDLE_VALUE){};
};

class FindWrapper : public GenericWrapper<HANDLE> {
public:
	FindWrapper(HANDLE handle) :
		GenericWrapper(handle, std::function<void(HANDLE)>(FindClose), INVALID_HANDLE_VALUE){};
};

typedef HandleWrapper MutexType;
class AcquireMutex : public GenericWrapper<MutexType> {
public:
	explicit AcquireMutex(MutexType hMutex) :
		GenericWrapper(hMutex, std::function<void(MutexType)>(ReleaseMutex), INVALID_HANDLE_VALUE){
		WaitForSingleObject(hMutex, INFINITE);
	};
};

class AllocationWrapper {
	std::optional<std::shared_ptr<char[]>> Memory;
	const PCHAR pointer;
	SIZE_T AllocationSize;

public:
	enum AllocationFunction {
		VIRTUAL_ALLOC, HEAP_ALLOC, MALLOC, CPP_ALLOC, CPP_ARRAY_ALLOC, STACK_ALLOC
	};

	AllocationWrapper(LPVOID memory, SIZE_T size, AllocationFunction AllocationType = STACK_ALLOC) :
		pointer{ reinterpret_cast<PCHAR>(memory) },
		Memory{ 
			size && memory ? std::optional<std::shared_ptr<char[]>>{{
				reinterpret_cast<PCHAR>(memory), [AllocationType](char* value){
					if(AllocationType == CPP_ALLOC)
						delete value;
					else if(AllocationType == CPP_ARRAY_ALLOC)
						delete[] value; 
					else if(AllocationType == MALLOC)
						free(value);
					else if(AllocationType == HEAP_ALLOC)
						HeapFree(GetProcessHeap(), 0, value);
					else if(AllocationType == VIRTUAL_ALLOC)
						VirtualFree(value, 0, MEM_RELEASE);
				}
			}} : std::nullopt
	    },
		AllocationSize{ size }{}

	CHAR operator[](int i) const {
		return Memory && i < AllocationSize ? pointer[i] : 0;
	}

	operator bool() const {
		return Memory.has_value();
	}

	operator LPVOID() const {
		return pointer;
	}

	DWORD GetSize() const {
		return Memory.has_value() ? AllocationSize : 0;
	}

	template<class T>
	std::optional<T> operator*() const {
		return Dereference();
	}

	template<class T>
	std::optional<T> Dereference() const {
		if(AllocationSize < sizeof(T) || !Memory.has_value()){
			return std::nullopt;
		} else {
			return *reinterpret_cast<T*>(pointer);
		}
	}

	std::optional<std::wstring> ReadWString() const {
		if(Memory.has_value()){
			SIZE_T size = wcsnlen(reinterpret_cast<PWCHAR>(pointer), AllocationSize / 2);
			PWCHAR buffer = new WCHAR[size + 1];
			CopyMemory(buffer, pointer, size * 2);
			buffer[size] = 0;
			auto str = std::wstring{ buffer };
			delete[] buffer;
			return str;
		} else return std::nullopt;
	}

	std::optional<std::string> ReadString() const {
		if(Memory.has_value()){
			SIZE_T size = strnlen(reinterpret_cast<PCHAR>(pointer), AllocationSize);
			PCHAR buffer = new CHAR[size + 1];
			CopyMemory(buffer, pointer, size);
			buffer[size] = 0;
			auto str = std::string{ buffer };
			delete[] buffer;
			return str;
		} else return std::nullopt;
	}

	bool CompareMemory(const AllocationWrapper& wrapper) const {
		if(!wrapper && !Memory.has_value()){
			return true;
		} else if(!wrapper || !Memory.has_value()){
			return false;
		} else if(wrapper.AllocationSize == AllocationSize){
			for(int i = 0; i < AllocationSize; i++)
				if(pointer[i] != wrapper[i])
					return false;
			return true;
		} else {
			return false;
		}
	}

	bool SetByte(SIZE_T offset, char value){
		if(offset < AllocationSize){
			pointer[offset] = value;
			return true;
		}
		return false;
	}
};

template<class T = CHAR>
class MemoryWrapper {
	T LocalCopy{};

public:
	T* address;
	HandleWrapper process;
	SIZE_T MemorySize;

	MemoryWrapper(LPVOID lpMemoryBase, SIZE_T size = sizeof(T), HANDLE process = GetCurrentProcess())
		: address{ reinterpret_cast<T*>(lpMemoryBase) }, process{ process }, MemorySize{ size } {}

	T Dereference() const {
		if(!process){
			return *address;
		} else {
			T mem = {};
			ReadProcessMemory(process, address, &mem, MemorySize, nullptr);
			return mem;
		}
	}

	T operator *() const {
		return Dereference();
	}
	T** operator &() const {
		return &(address);
	}
	operator T* () const {
		return (address);
	}
	T* operator->(){
		if(!process){
			return address;
		} else {
			LocalCopy = {};
			if(ReadProcessMemory(process, address, &LocalCopy, MemorySize, nullptr)){
				return &LocalCopy;
			} else {
				return nullptr;
			}
		}
	}

	template<class V>
	MemoryWrapper<V> Convert() const {
		return { reinterpret_cast<V*>(address), MemorySize, process };
	}

	MemoryWrapper<T> GetOffset(SIZE_T offset) const {
		if(offset > MemorySize){
			return { nullptr, 0, process };
		} else {
			return { reinterpret_cast<T*>(PCHAR(address) + offset), MemorySize - offset, process };
		}
	}

	bool CompareMemory(MemoryWrapper<T> memory) const {
		auto data1 = Dereference();
		auto data2 = memory.Dereference();
		return !memcmp(&data1, &data2, min(memory.MemorySize, MemorySize));
	}

	bool Protect(DWORD protections, SIZE_T size = -1){
		if(size == -1) size = MemorySize;
		DWORD dwOldProtections{};
		if(!process){
			return VirtualProtect(address, size, protections, &dwOldProtections);
		} else {
			return VirtualProtectEx(process, address, size, protections, &dwOldProtections);
		}
	}

	std::string ReadString(){
		if(!process){
			return std::string{ reinterpret_cast<char*>(address) };
		} else {
			int idx = 0;
			int maxIdx = 10;
			char* memory = new char[maxIdx * 2];
			bool valid = false;
			while(!valid && !ReadProcessMemory(process, address, memory, maxIdx = min(maxIdx * 2, MemorySize), nullptr)){
				for(; idx < maxIdx; idx++){
					if(memory[idx] == 0){
						valid = true;
						break;
					}
					delete[] memory;
					memory = new char[maxIdx * 2];
				}
			}
			if(valid){
				return std::string{ memory };
			} else {
				return std::string{};
			}
		}
	}

	std::wstring ReadWstring(){
		if(!process){
			return std::wstring{ reinterpret_cast<WCHAR*>(address) };
		} else {
			int idx = 0;
			int maxIdx = 10;
			wchar_t* memory = new wchar_t[maxIdx * 2];
			bool valid = false;
			while(!valid && !ReadProcessMemory(process, address, memory, (maxIdx = min(maxIdx * 2, MemorySize / sizeof(WCHAR))) * sizeof(WCHAR), nullptr)){
				for(; idx < maxIdx; idx++){
					if(memory[idx] == 0){
						valid = true;
						break;
					}
				}
				delete[] memory;
				memory = new wchar_t[maxIdx * 2];
			}
			if(valid){
				return std::wstring{ memory };
			} else {
				return std::wstring{};
			}
		}
	}

	AllocationWrapper Read() const {
		if(!process){
			return AllocationWrapper{ address, MemorySize };
		} else{
			AllocationWrapper copy{ VirtualAlloc(nullptr, MemorySize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE), MemorySize, AllocationWrapper::VIRTUAL_ALLOC };
			if(ReadProcessMemory(process, address, copy, MemorySize, nullptr)){
				return copy;
			} else{
#ifdef LOG_ERROR
				LOG_ERROR("Failed to read memory at " << address << " of process with PID " << GetProcessId(process) << " (Error " << GetLastError() << ")");
#endif
			}
		}
	}

	operator bool() const { return address; }
	bool operator !() const { return !address; }
};

#define WRAP(type, name, value, function) \
    GenericWrapper<type> name = {value, [&](type data){ function; }}

#define SCOPE_LOCK(function, name) \
    GenericWrapper<DWORD> __##name = { 1, [&](DWORD data){ function; }, 0 }
