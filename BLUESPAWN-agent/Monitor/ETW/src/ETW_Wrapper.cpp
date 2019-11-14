#include "ETW\ETW_Wrapper.h"
#include <iostream>

ETW_Wrapper::ETW_Wrapper() : pshellProvider(krabs::guid(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}"))
{
}

void ETW_Wrapper::initProviders() {
	// user_trace providers typically have any and all flags, whose meanings are
	// unique to the specific providers that are being invoked. To understand these
	// flags, you'll need to look to the ETW event producer.
	pshellProvider.any(0xf0010000000003ff);

	// providers should be wired up with functions (or functors) that are called when
	// events from that provider are fired.
	pshellProvider.add_on_event_callback([](const EVENT_RECORD& record) {

		// Once an event is received, if we want krabs to help us analyze it, we need
		// to snap in a schema to ask it for information.
		krabs::schema schema(record);

		// We then have the ability to ask a few questions of the event.
		std::wcout << L"Event " << schema.event_id();
		std::wcout << L"(" << schema.event_name() << L") received." << std::endl;

		if (schema.event_id() == 7937) {
			// The event we're interested in has a field that contains a bunch of
			// info about what it's doing. We can snap in a parser to help us get
			// the property information out.
			krabs::parser parser(schema);

			// We have to explicitly name the type that we're parsing in a template
			// argument.
			// We could alternatively use try_parse if we didn't want an exception to
			// be thrown in the case of failure.
			std::wstring context = parser.parse<std::wstring>(L"ContextInfo");
			std::wcout << L"\tContext: " << context << std::endl;
		}
	});
}

void ETW_Wrapper::start() {
	traceThread = new std::thread(&ETW_Wrapper::start_trace, this);
	std::wcout << "trace started . . ." << std::endl;
}

void ETW_Wrapper::start_trace() {
	// the user_trace needs to know about the provider that we've set up.
	trace.enable(pshellProvider);

	// begin listening for events. This call blocks, so if you want to do other things
	// while this runs, you'll need to call this on another thread.
	trace.start();
}