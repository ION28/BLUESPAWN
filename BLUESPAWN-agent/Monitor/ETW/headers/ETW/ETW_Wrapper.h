#pragma once

#include "krabs.hpp"
#include <thread>

class ETW_Wrapper {
	public:
		ETW_Wrapper();
		void start();
		void initProviders();

	private:
		// user_trace instances should be used for any non-kernel traces that are defined
		// by components or programs in Windows.
		krabs::user_trace trace;

		// A trace can have any number of providers, which are identified by GUID. These
		// GUIDs are defined by the components that emit events, and their GUIDs can
		// usually be found with various ETW tools (like wevutil).
		krabs::provider<> pshellProvider;

		std::thread * traceThread;
		void start_trace();
};