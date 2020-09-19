#pragma once

/// Refers to the various types of HANDLEs
enum class Type{
	Process,
	Thread,
	File,
	Pipe,
	Synchronization, // Refers to a synchronization object such as an event or mutex
	RegistryKey,
	ETW,
	Directory,
	Section,
	ALPCPort,
	Mutant,
	Token,
	Other
};