#include "util/ThreadPool.h"

#include <eh.h>

ThreadPool ThreadPool::instance{};

void ThreadPool::ThreadFunction(){
	while(active){
		auto result{ WaitForSingleObject(hSemaphore, INFINITE) };
		if(result == WAIT_OBJECT_0){
			if(!active){
				return;
			}

			EnterCriticalSection(hGuard);
			auto function{ tasks.front() };
			tasks.pop();
			LeaveCriticalSection(hGuard);

			try{
				function();

				EnterCriticalSection(hGuard);
				count--;
				if(count == 0){
					SetEvent(hEvent);
				}
				LeaveCriticalSection(hGuard);

			} catch(std::exception e){
				EnterCriticalSection(hGuard);
				count--;
				if(count == 0){
					SetEvent(hEvent);
				}
				LeaveCriticalSection(hGuard);

				auto functions{ vExceptionHandlers };

				// Defer handling the exceptions until later
				EnqueueTask([functions, e](){
					for(auto& function : functions){
						function(e);
					}
				});
			}
		} else{
			if(WaitForSingleObject(hSemaphore, 0) == WAIT_FAILED){
				// hSemaphore has become invalidated somehow. Recreate it
				hSemaphore = CreateSemaphoreW(nullptr, 0, static_cast<LONG>(-1), nullptr);
			}
		}
	}
}

ThreadPool::ThreadPool() :
	hSemaphore{ CreateSemaphoreW(nullptr, 0, LONG_MAX, nullptr) },
	hEvent{ CreateEventW(nullptr, true, true, nullptr) },
	active{ true }{

	auto error{ GetLastError() };
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
		threads.emplace_back(std::thread{ &ThreadPool::ThreadFunction, this });
	}
}

ThreadPool::~ThreadPool(){
	active = false;

	ReleaseSemaphore(hSemaphore, threads.size(), nullptr);

	for(auto& thread : threads){
		thread.join();
	}
}

void ThreadPool::EnqueueTask(IN CONST std::function<void()>& function){
	ResetEvent(hEvent);

	auto lock{ BeginCriticalSection(hGuard) };

	tasks.emplace(function);
	count++;

	ReleaseSemaphore(hSemaphore, 1, nullptr);
}

ThreadPool& ThreadPool::GetInstance(){
	return instance;
}

void ThreadPool::AddExceptionHandler(
	IN CONST std::function<void(const std::exception & e)>& function){
	vExceptionHandlers.emplace_back(function);
}

void ThreadPool::Wait() const {
	while(true){
		auto status{ WaitForSingleObject(hEvent, INFINITE) };
		if(status == WAIT_OBJECT_0){
			EnterCriticalSection(hGuard);
			if(count == 0){
				LeaveCriticalSection(hGuard);
				return;
			}
			LeaveCriticalSection(hGuard);
		} else{
			throw std::exception{ "Error waiting for threadpool to finish" };
		}
	}
}