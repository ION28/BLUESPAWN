#pragma once
#include <sys/mman.h>
#include <pthread.h>
#include <string.h>
#include <map>
#include <string>
#include <memory>
#include <optional>
#include <functional>
#include <sys/types.h>
#include <unistd.h>
#include <algorithm>

template<class T>
class GenericWrapper {
protected:
	std::shared_ptr<void> ReferenceCounter;

	T WrappedObject;
	std::optional<T> BadValue;

public:

	GenericWrapper(T object, std::function<void(T)> freeFunction = [](T object){ delete object; }, std::optional<T> BadValue = std::nullopt) : 
		WrappedObject{ object }, 
		BadValue{ BadValue },
		ReferenceCounter{ nullptr, [object, BadValue, freeFunction](void* memory){ 
		    if((!BadValue || object != BadValue) && object){ freeFunction(object); } 
	    }}{}

	operator T() const { return WrappedObject; }
	T operator *() const{ return WrappedObject; }
	T operator ->() const{ return WrappedObject; }
	T* operator &() const{ return const_cast<T*>(&WrappedObject); }
	bool operator ==(T object) const{ return WrappedObject == object; }
	bool operator !() const{ return !WrappedObject || WrappedObject == BadValue; }
	operator bool() const{ return !operator!(); }
	T Release(){ auto tmp = WrappedObject; WrappedObject = BadValue; return tmp; }
	T Get() const { return WrappedObject; }
};

//NOTE: Temporarily removed - find linux equiv
/*class FindWrapper : public GenericWrapper<HANDLE> {
public:
	FindWrapper(HANDLE handle) :
		GenericWrapper(handle, std::function<void(HANDLE)>(FindClose), INVALID_HANDLE_VALUE){};
};*/

class AcquireMutex {
	const pthread_mutex_t &hMutex;
	std::shared_ptr<void> tracker;

public:
	explicit AcquireMutex(const pthread_mutex_t& mutex) :
		hMutex{ mutex },
		tracker{ nullptr, [&](void* nul){ pthread_mutex_unlock(const_cast<pthread_mutex_t*>(&hMutex)); } }{
		pthread_mutex_lock(const_cast<pthread_mutex_t*>(&hMutex));
	}
};

class AllocationWrapper {
	std::optional<std::shared_ptr<char[]>> Memory;
	char* pointer;
	size_t AllocationSize;

public:
	enum AllocationFunction {
		MALLOC, CPP_ALLOC, CPP_ARRAY_ALLOC, STACK_ALLOC
	};

	AllocationWrapper(void* memory, size_t size, AllocationFunction AllocationType = STACK_ALLOC) :
		pointer{ reinterpret_cast<char*>(memory) },
		Memory{ 
			size && memory ? std::optional<std::shared_ptr<char[]>>{{
				reinterpret_cast<char*>(memory), [AllocationType](char* value){
					if(AllocationType == CPP_ALLOC)
						delete value;
					else if(AllocationType == CPP_ARRAY_ALLOC)
						delete[] value;
					else if(AllocationType == MALLOC)
						free(value);
				}
			}} : std::nullopt
	    },
		AllocationSize{ size }{}

	char operator[](int i) const {
		return Memory && i < AllocationSize ? pointer[i] : 0;
	}

	operator bool() const {
		return Memory.has_value();
	}

	operator void*() const {
		return pointer;
	}

	unsigned int GetSize() const {
		return Memory.has_value() ? AllocationSize : 0;
	}

	template<class T>
	std::optional<T> Dereference() const {
		if(AllocationSize < sizeof(T) || !Memory.has_value()){
			return std::nullopt;
		} else {
			return *reinterpret_cast<T*>(pointer);
		}
	}

	template<class T>
	std::optional<T> operator*() const {
		return Dereference<T>();
	}

	std::optional<std::wstring> ReadWString() const {
		if(Memory.has_value()){
			size_t size = wcsnlen(reinterpret_cast<wchar_t*>(pointer), AllocationSize / 2);
			wchar_t * buffer = new wchar_t[size + 1];
			memcpy(buffer, pointer, size * 2);
			buffer[size] = 0;
			auto str = std::wstring{ buffer };
			delete[] buffer;
			return str;
		} else return std::nullopt;
	}

	std::optional<std::string> ReadString() const {
		if(Memory.has_value()){
			size_t size = strnlen(reinterpret_cast<char*>(pointer), AllocationSize);
			char* buffer = new char[size + 1];
			memcpy(buffer, pointer, size);
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

	bool SetByte(size_t offset, char value){
		if(offset < AllocationSize){
			pointer[offset] = value;
			return true;
		}
		return false;
	}

	template<class T = void*>
	T* GetAsPointer(){ 
		return reinterpret_cast<T*>(pointer); 
	}
};

template<class T = char>
class MemoryWrapper {
	T LocalCopy{};

public:
    //TODO: remove references to processes? unless want to include ptrace?
	T* address;
	pid_t process;
	size_t MemorySize;

	MemoryWrapper(void* lpMemoryBase, size_t size = sizeof(T), pid_t process = getpid())
		: address{ reinterpret_cast<T*>(lpMemoryBase) }, process{ process }, MemorySize{ size } {}

	T Dereference() const {
		if(!process){
			return *address;
		} else {
			T mem = {};
			ReadProcessMemory(process, address, &mem, sizeof(T), nullptr);
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
			if(ReadProcessMemory(process, address, &LocalCopy, sizeof(LocalCopy), nullptr)){
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

	MemoryWrapper<T> GetOffset(size_t offset) const {
		if(offset > MemorySize){
			return { nullptr, 0, process };
		} else {
			return { reinterpret_cast<T*>(reinterpret_cast<char*>(address) + offset), MemorySize - offset, process };
		}
	}

	bool CompareMemory(MemoryWrapper<T> memory) const {
		auto data1 = Dereference();
		auto data2 = memory.Dereference();
		return !memcmp(&data1, &data2, std::min(memory.MemorySize, MemorySize));
	}

	bool Protect(unsigned int protections, size_t size = -1){
		if(size == -1) size = MemorySize;

		return mprotect(address, size, protections);
	}

	std::string ReadString(){
		if(!process){
			return std::string{ reinterpret_cast<char*>(address) };
		} else {
			int idx = 0;
			int maxIdx = 10;
			char* memory = new char[maxIdx * 2];
			bool valid = false;
			while(!valid && !ReadProcessMemory(process, address, memory, maxIdx = std::min(reinterpret_cast<size_t>(maxIdx * 2), MemorySize), nullptr)){
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
			return std::wstring{ reinterpret_cast<wchar_t*>(address) };
		} else {
			int idx = 0;
			int maxIdx = 10;
			wchar_t* memory = new wchar_t[maxIdx * 2];
			bool valid = false;
			while(!valid && !ReadProcessMemory(process, address, memory, (maxIdx = std::min(reinterpret_cast<size_t>(maxIdx * 2), MemorySize / sizeof(wchar_t))) * sizeof(wchar_t), nullptr)){
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

	operator bool() const { return address; }
	bool operator !() const { return !address; }

	AllocationWrapper ToAllocationWrapper(unsigned int size = -1){
		if(size == -1) size = MemorySize;
		size = std::min(reinterpret_cast<size_t>(size), MemorySize);
		AllocationWrapper wrapper{ malloc(size), size, AllocationWrapper::MALLOC };
		memmove(wrapper, address, size);
		return wrapper;
	}
};

#define WRAP(type, name, value, function) \
    GenericWrapper<type> name = {value, [&](type data){ function; }}

#define SCOPE_LOCK(function, name) \
    GenericWrapper<unsigned int> __##name = { 1, [&](unsigned int data){ function; }, 0 }
