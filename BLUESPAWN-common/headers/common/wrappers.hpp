#pragma once
#include <Windows.h>

#include <map>
#include <string>
#include <memory>
#include <optional>

template<class T>
class GenericWrapper {
protected:
	static inline std::map<T, DWORD> mReferenceCounts{};

	T WrappedObject;
	T BadValue;
	bool bFreeOnDestruction = true;

	void (*freeResource)(T);

	void DestroyReference(){
		mReferenceCounts[WrappedObject]--;
		if(mReferenceCounts[WrappedObject] == 0){
			mReferenceCounts.erase(WrappedObject);
			if(bFreeOnDestruction && operator bool()){
				freeResource(WrappedObject);
			}
		}
	}

	void SetReference(T object){
		if(mReferenceCounts.find(object) == mReferenceCounts.end()){
			mReferenceCounts.emplace(object, 1);
		} else {
			mReferenceCounts[object]++;
		}
	}

public:

	GenericWrapper(T object, void(*freeFunction)(T) = [](T object){ delete object; }, T BadValue = nullptr)
		: WrappedObject{ object }, freeResource{ freeFunction }, BadValue{ BadValue } { SetReference(object); }

	GenericWrapper(const GenericWrapper& copy)
		: freeResource{ copy.freeResource } { SetReference(copy.WrappedObject); }

	GenericWrapper(GenericWrapper&& move)
		: freeResource{ move.freeResource } { SetReference(move.WrappedObject); move.DestroyReference(); }

	GenericWrapper& operator=(const GenericWrapper& copy){ 
		freeResource = copy.freeResource; 
		DestroyReference(); 
		SetReference(copy.WrappedObject); 
		return *this;
	}
	GenericWrapper&& operator=(GenericWrapper&& move) = delete;

	~GenericWrapper(){ DestroyReference(); }

	operator T() const { return WrappedObject; }
	T* operator *(){ return *WrappedObject; }
	T& operator &(){ return &WrappedObject; }
	bool operator ==(T object){ return WrappedObject == object; }
	bool operator !(){ return !WrappedObject || WrappedObject == BadValue; }
	operator bool(){ return !operator!(); }

	T Get() const { return WrappedObject; }
	bool Release(){ return bFreeOnDestruction != (bFreeOnDestruction = false); }
	bool Lock(){ return bFreeOnDestruction != (bFreeOnDestruction = true);  }
	DWORD GetReferenceCount(){ return mReferenceCounts[WrappedObject]; }
};

class HandleWrapper : public GenericWrapper<HANDLE> {
public:
	HandleWrapper(HANDLE handle) :
		GenericWrapper(handle, (void(*)(HANDLE)) CloseHandle, INVALID_HANDLE_VALUE){};
};

class AllocationWrapper {
	std::optional<std::shared_ptr<char[]>> Memory;
	SIZE_T AllocationSize;

public:
	enum AllocationFunction {
		VIRTUAL_ALLOC, HEAP_ALLOC, MALLOC, CPP_ALLOC, CPP_ARRAY_ALLOC, STACK_ALLOC
	};

	AllocationWrapper(LPVOID memory, SIZE_T size, AllocationFunction AllocationType = STACK_ALLOC) :
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
		return Memory ? (*Memory)[i] : 0;
	}

	operator bool() const {
		return Memory.has_value();
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
		if(AllocationSize < sizeof(T)){
			return std::nullopt;
		} else {
			char* buffer = new char[sizeof(T)];
			for(int i = 0; i < sizeof(T); i++){
				buffer[i] = (*Memory)[i];
			}
			T value = *reinterpret_cast<T*>(buffer);
			delete[] buffer;
			return value;
		}
	}

	std::optional<std::wstring> ReadWString() const {
		if(Memory.has_value()){
			SIZE_T size = 0;
			while(size * 2 + 1 < AllocationSize && ((*Memory)[size * 2] || (*Memory)[size * 2 + 1]))
				size++;
			char* buffer = new char[size * 2 + 2];
			for(int i = 0; i < size * 2; i++){
				buffer[i] = (*Memory)[i];
			}
			buffer[size * 2] = buffer[size * 2 + 1] = 0;
			auto str = std::wstring{ reinterpret_cast<wchar_t*>(buffer) };
			delete[] buffer;
			return str;
		} else return std::nullopt;
	}

	std::optional<std::string> ReadString() const {
		if(Memory.has_value()){
			SIZE_T size = 0;
			while(size < AllocationSize && (*Memory)[size])
				size++;
			char* buffer = new char[size + 1];
			for(SIZE_T i = 0; i < size; i++){
				buffer[i] = (*Memory)[i];
			}
			buffer[size] = 0;
			auto str = std::string{ buffer };
			delete[] buffer;
			return str;
		} else return std::nullopt;
	}

	bool CompareMemory(const AllocationWrapper& wrapper){
		if(!wrapper && !Memory.has_value()){
			return true;
		} else if(!wrapper || !Memory.has_value()){
			return false;
		} else if(wrapper.AllocationSize == AllocationSize){
			for(int i = 0; i < AllocationSize; i++)
				if((*Memory)[i] != wrapper[i])
					return false;
			return true;
		} else {
			return false;
		}
	}

	char* Copy(){
		if(Memory.has_value()){
			char* copy = new char[AllocationSize];
			for(SIZE_T i = 0; i < AllocationSize; i++)
				copy[i] = (*Memory)[i];
			return copy;
		} else return nullptr;
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

	operator bool() const { return address; }
	bool operator !() const { return !address; }
};

#define WRAP(type, name, value, function) \
    GenericWrapper<type> name = {value, [](type data){ function; }}