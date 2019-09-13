#pragma once
#include <Windows.h>

#include <map>

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
		SetReference(copy); 
	}
	GenericWrapper&& operator=(GenericWrapper&& move){ 
		freeResource = move.freeResource;
		DestroyReference(); 
		SetReference(move);  
		move.DestroyReference(); 
	}

	~GenericWrapper(){ DestroyReference(); }

	operator T(){ return WrappedObject; }
	T* operator *(){ return *WrappedObject; }
	T& operator &(){ return &WrappedObject; }
	bool operator ==(T object){ return WrappedObject == object; }
	bool operator !(){ return !WrappedObject || WrappedObject == BadValue; }
	operator bool(){ return !operator!(); }

	T Get(){ return WrappedObject; }
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

	T Dereferene(){
		if(!process){
			return *address;
		} else {
			LocalCopy = {};
			ReadProcessMemory(process, address, &LocalCopy, MemorySize, nullptr);
			return LocalCopy;
		}
	}

	T operator *(){
		return Dereferene();
	}
	T** operator &(){
		return &(address);
	}
	operator T* (){
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
	MemoryWrapper<V> Convert(){
		return { reinterpret_cast<V*>(address), MemorySize, process };
	}

	MemoryWrapper<T> GetOffset(SIZE_T offset){
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

	bool CompareMemory(MemoryWrapper<T> memory){
		auto data1 = Dereferene();
		auto data2 = memory.Dereferene();
		return !memcmp(&data1, &data2, min(memory.MemorySize, MemorySize));
	}

	bool Protect(DWORD protections, DWORD size = MemorySize){
		DWORD dwOldProtections{};
		if(!process){
			return VirtualProtect(address, size, protections, &dwOldProtections);
		} else {
			return VirtualProtextEx(process, address, size, protections, &dwOldProtections);
		}
	}

	operator bool(){ return address; }
	bool operator !(){ return !address; }
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