/*
	DWYW License (Do whatever you want)

	Permission is hereby granted, free of charge, to any person obtaining
	a copy of this software, to do whatever they want to do with this software.

	This is not copyrighted, and you don't need to worry about licensing issues.

	In no event shall the authors be liable for any claim,
	damages, or other liability, whether in an action of contract,
	tort or otherwise, arising from, out of or in connection with
	the software or the use or other dealings in the software.
*/

#include <format>

#include "scanner.hpp"

// comment this out if ur not compiling as a dll
#define dll_mode

int main()
{
	const scan_cfg cfg =
	{
		//"ntdll.dll"
	};

	const auto opened_process = process(
#ifndef dll_mode
	"victim_app.exe"
#endif
	);
	const auto [pid, proc_base, is32, curr_proc, curr_mod] = opened_process;

	if (!curr_mod && !curr_proc && !pid && !proc_base && !is32) {
		std::printf("Error: the process is not running.\n");
		return 0;
	}
	
	std::printf("Process ID: %lu\nProcess base address: 0x%02lX\nProcess is under wow64: %d\n", pid, proc_base, is32);

	// scan for xrefs to "BASE STRING PREFIX"
	const auto str_results = scanner::string_scan(opened_process, "BASE STRING PREFIX");
	for (const auto & [loc] : str_results) {
		std::printf("String xref found at: 0x%02llX\n", util::rebase(opened_process, loc));
	}

	const auto SCAN_FOR_ME = *util::get_prologue(opened_process, str_results[0].loc);
	std::printf("SCAN_FOR_ME: 0x%02llX\n", util::rebase(opened_process, SCAN_FOR_ME));

	const auto scan_for_me_xrefs = scanner::xref_scan(opened_process, SCAN_FOR_ME);
	for (const auto & [loc] : scan_for_me_xrefs) {
		std::printf("SCAN_FOR_ME xref found at: 0x%02llX\n", util::rebase(opened_process, loc));
	}

	std::cin.get();
	return 0;
}

#ifdef dll_mode
std::uintptr_t _console_main () {
	AllocConsole();
	return main();
}

int __stdcall DllMain(const HINSTANCE dll_handle, const DWORD call_reason, const void** reserved) {
	if (call_reason == DLL_PROCESS_ATTACH)
		std::thread(_console_main).detach();

	return 0;
}
#endif