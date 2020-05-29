#include "common/ThreadPool.h"

#include <eh.h>

ThreadPool ThreadPool::instance{};

void ThreadPool::ThreadFunction(){
	while(true){
		auto result{ WaitForSingleObject(hSemaphore, INFINITE) };
		if(result == WAIT_OBJECT_0){
			EnterCriticalSection(hGuard);
			auto function{ tasks.front() };
			tasks.pop();
			LeaveCriticalSection(hGuard);

			try{
				function();
			} catch(std::exception& e){
				// Handle Exception
			}
		} else{
			if(WaitForSingleObject(hSemaphore, 0) == WAIT_FAILED){
				// hSemaphore has become invalidated somehow. Recreate it
				hSemaphore = CreateSemaphoreW(nullptr, 0, static_cast<LONG>(-1), nullptr);
			} else {
				throw std::exception(("Error " + std::to_string(GetLastError()) + " occured when waiting for semaphore").c_str());
			}
			// Handle exception
		}
	}
}

ThreadPool::ThreadPool() :
	hSemaphore{ CreateSemaphoreW(nullptr, 0, static_cast<LONG>(-1), nullptr) }{

	// https://stackoverflow.com/questions/457577/catching-access-violation-exceptions
	_set_se_translator([](unsigned int u, EXCEPTION_POINTERS* pExp){
		std::string error = "Structured Exception: ";
		char result[11];
		sprintf_s(result, 11, "0x%08X", u);
		error += result;
		throw std::exception(error.c_str());
    });

	auto count{ std::thread::hardware_concurrency() };

	for(unsigned int idx = 0; idx < count; idx++){
		threads.emplace_back(std::thread{ &ThreadFunction, this });
	}
}

void ThreadPool::EnqueueTask(IN CONST std::function<void()>& function){
	auto lock{ BeginCriticalSection(hGuard) };

	tasks.emplace(function);

	ReleaseSemaphore(hSemaphore, 1, nullptr);
}

ThreadPool& ThreadPool::GetInstance(){
	return instance;
}