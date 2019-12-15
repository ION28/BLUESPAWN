### Example Powershell Callback fucntion

```
wrapper.addPowershellCallback([](const EVENT_RECORD& record) {
	// Once an event is received, if we want krabs to help us analyze it, we need
	// to snap in a schema to ask it for information.
	krabs::schema schema(record);

	// We then have the ability to ask a few questions of the event.
	std::wcout << L"Event " << schema.event_id();
	std::wcout << L"(" << schema.event_name() << L") received." << std::endl;

	if (schema.event_id() == 45060) {
		// The event we're interested in has a field that contains a bunch of
		// info about what it's doing. We can snap in a parser to help us get
		// the property information out.
		krabs::parser parser(schema);

		// We have to explicitly name the type that we're parsing in a template
		// argument.
		// We could alternatively use try_parse if we didn't want an exception to
		// be thrown in the case of failure.
		std::wstring command = parser.parse<std::wstring>(L"Command");
		std::wcout << L"\Command: " << command << std::endl;

		std::wstring name = parser.parse<std::wstring>(L"Name");
		std::wcout << L"\Name: " << name << std::endl;

	}
});
```