#pragma once
#include <Windows.h>

#include <map>

template<class T>
class GenericWrapper {
protected:
	static map<T, DWORD> mReferenceCounts{};

	T WrappedObject;
	bool bFreeOnDestruction = true;

	void (*freeResource)(T);

	void DestroyReference(){
		mReferenceCounts[WrappedObject]--;
		if(mReferenceCounts[WrappedObject] == 0){
			mReferenceCounts.remove(WrappedObject);
			if(bFreeOnDestruction){
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

	GenericWrapper(T object, void(*freeFunction)(T) = [](T object){ delete object })
		: freeResource { freeFunction } { SetReference(object); }

	GenericWrapper(const GenericWrapper& copy)
		: freeResource{ copy.freeResource } { SetReference(copy); }

	GenericWrapper(GenericWrapper&& move)
		: freeResource{ move.freeResource } { SetRefernce(move); move.DestroyReference(); }

	GenericWrapper& operator=(const GenericWrapper& copy){ 
		freeResource = copy.freeResource; 
		DestroyReference(); 
		SetReference(copy); 
	}
	GenericWrapper&& operator=(GenericWrapper&& move){ 
		freeResource = move.freeResource;
		DestroyReference(); 
		SetReference(copy);  
		move.DestroyReference(); 
	}

	~GenericWrapper(){ DestroyReference(); }

	operator T(){ return WrappedObject; }
	T* operator *(){ return *WrappedObject; }
	T& operator &(){ return &WrappedObject; }

	bool Release(){ return bFreeOnDestruction != (bFreeOnDestruction = false); }
	bool Lock(){ return bFreeOnDestruction != (bFreeOnDestruction = true);  }
	DWORD GetReferenceCount(){ return mRefernceCounts[WrappedObject]; }
};

class HandleWrapper : public GenericWrapper<HANDLE> {
public:
	HandleWrapper(HANDLE handle) : GenericWrapper(handle, [](HANDLE handle){ CloseHandle(handle); }){};
};

template<class T>
struct GenericMemoryType { T* memory; HANDLE process; };

template<class T = void>
class MemoryWrapper {
	GenericMemoryType memory;
	SIZE_T MemorySize;

	T LocalCopy{};

public:
	MemoryWrapper(T data) : memory{ &data, GetCurrentProcess() }, size{ sizeof(data) } {}
	MemoryWrapper(T* lpMemoryBase, SIZE_T size = sizeof(T), HANDLE process = GetCurrentProcess()) 
		: memory{ lpMemoryBase, process }, MemorySize{ size } {}
	T operator *(){
		if(memory.process == GetCurrentProcess()){
			return *(memory.memory);
		} else {
			LocalCopy = {};
			ReadProcessMemory(memory.process, memory.memory, &data, MemorySize, nullptr);
			return LocalCopy;
		}
	}
	T** operator &(){
		return &(memory.memory);
	}
	operator T* (){
		return (memory.memory);
	}
	T* operator->(){
		if(memory.process == GetCurrentProcess()){
			return *memory.memory;
		} else {
			LocalCopy = {};
			ReadProcessMemory(memory.process, memory.memory, &data, MemorySize, nullptr);
			return &LocalCopy;
		}
	}

	template<class V>
	MemoryWrapper<V> Convert(){
		return { reinterpret_cast<V*>(memory.memory), MemorySize, memory.process };
	}

	MemoryWrapper<T> GetOffset(SIZE_T offset){
		if(offset > MemorySize){
			return { nullptr, 0, memory.process };
		} else {
			return { reinterpret_cast<V*>(PCHAR(memory.memory) + offset, MemorySize - offset, memory.process); }
		}
	}

	bool Write(T* lpToWrite, SIZE_T nWriteSize, SIZE_T offset = 0){
		if(offset != 0){
			return GetOffset(offset).Write(lpToWrite, nWriteSize);
		}

		if(nWriteSize > MemorySize){
			return false;
		} else {
			if(memory.process == GetCurrentProcess()){
				CopyMemory(memory.memory, lpToWrite, nWriteSize);
				return true;
			} else {
				return WriteProcessMemory(memory.process, memory.memory, lpToWrite, nWriteSize, nullptr);
			}
		}
	}
};

class AllocationWrapper : public GenericWrapper<LPVOID> {
public:
	AllocationWrapper(LPVOID allocation) :
		GenericWrapper(allocation, [](LPVOID memory){ VirtualFree(memory, 0, MEM_RELEASE); }){};
};

template<class T>
class MemoryAllocationWrapper : 
	public GenericWrapper<GenericAllocationType<T>>, 
	public MemoryWrapper<T> {
public:
	GenericAllocationWrapper(GenericAllocationType allocation) :
		GenericWrapper(allocation, [](GenericAllocationType memory){ 
		    if(memory.process != GetCurrentProcess && memory.process != nullptr){
				VirtualFreeEx(memory.process, memory.memory, 0, MEM_RELEASE);
			} else {
				VirtualFree(memory.memory, 0, MEM_RELEASE);
			}
		}), 
		MemoryWrapper(allocation.memory, sizeof(T), allocation.process) {};

	GenericAllocationWrapper(LPVOID lpAddress, HANDLE process = GetCurrentProcess()) : 
		GenericAllocationWrapper(GenericAllocationType{ lpAddress, process }),
		MemoryWrapper(lpAddress, sizeof(T), process) {};

	LPVOID operator *() = delete;
	LPVOID& operator &() = delete;
};

#define WRAP(type, name, value, function) \
    GenericWrapper<type> name = {value, function}