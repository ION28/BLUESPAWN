#pragma once
#include <Windows.h>

#include <map>
#include <string>

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
		: freeResource{ move.freeResource } { SetRefernce(move.WrappedObject); move.DestroyReference(); }

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
	
	bool Write(T* lpToWrite, SIZE_T nWriteSize = sizeof(T), SIZE_T offset = 0){
		if(offset != 0){
			return GetOffset(offset).Write(lpToWrite, nWriteSize);
		}

		if(nWriteSize > MemorySize){
			return false;
		} else {
			if(!process){
				CopyMemory(address, lpToWrite, nWriteSize);
				return true;
			} else {
				return WriteProcessMemory(process, address, lpToWrite, nWriteSize, nullptr);
			}
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
			char* memory = nullptr;
			bool valid = false;
			while(!valid && !ReadProcessMemory(process, address, memory, maxIdx *= 2, nullptr)){
				for(; idx < maxIdx; idx++){
					if(memory[idx] == 0){
						valid = true;
						break;
					}
				}
			}
			if(valid){
				return std::string{ memory };
			} else {
				return std::string{};
			}
		}
	}

	std::string ReadWstring(){
		if(!process){
			return std::wstring{ reinterpret_cast<WCHAR*>(address) };
		} else {
			int idx = 0;
			int maxIdx = 10;
			wchar_t* memory = nullptr;
			bool valid = false;
			while(!valid && !ReadProcessMemory(process, address, memory, (maxIdx *= 2) * sizeof(wchar_t), nullptr)){
				for(; idx < maxIdx; idx++){
					if(memory[idx] == 0){
						valid = true;
						break;
					}
				}
			}
			if(valid){
				return std::string{ memory };
			} else {
				return std::string{};
			}
		}
	}

	operator bool() const { return address; }
	bool operator !() const { return !address; }
};

template<class T>
class MemoryAllocationWrapper : 
	public GenericWrapper<T*>, 
	public MemoryWrapper<T> {
public:
	MemoryAllocationWrapper(T* lpAddress, SIZE_T nSize = sizeof(T)) :
		GenericWrapper<T*>(reinterpret_cast<T*>(lpAddress), [](T* memory){
			VirtualFree(memory, 0, MEM_RELEASE);
		}, nullptr),
		MemoryWrapper<T>(reinterpret_cast<T*>(lpAddress), nSize, GetCurrentProcess()) {};

	using MemoryWrapper<T>::operator*;
	using MemoryWrapper<T>::operator&;
	using MemoryWrapper<T>::operator!;
	using MemoryWrapper<T>::operator bool;
};

#define WRAP(type, name, value, function) \
    GenericWrapper<type> name = {value, [](type data){ function; }}