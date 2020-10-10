#pragma once

#include <Windows.h>

#include <memory>

namespace BLUESPAWN::Agent::Util {

	class CriticalSection {
		std::shared_ptr<CRITICAL_SECTION> counter;

	public:
		CriticalSection();

		operator LPCRITICAL_SECTION() const;
	};

	class BeginCriticalSection {
		CriticalSection critsec;
		bool released;

	public:
		explicit BeginCriticalSection(const CriticalSection& section);
		~BeginCriticalSection();
		void Release();
		void Acquire();
	};

	void SafeCloseHandle(_In_ HANDLE hHandle);
}