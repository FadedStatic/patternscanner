#pragma once

#include <functional>
#include <iostream>
#include <Windows.h>
#include <string_view>
#include <Psapi.h>
#include <processthreadsapi.h>
#include <thread>


namespace scanner_cfg_templates
{
	const auto page_flag_check_default = [](const std::uintptr_t page_flags) -> bool
	{
		if (!(page_flags bitand (PAGE_NOACCESS bitor PAGE_EXECUTE bitor PAGE_GUARD))) // credits to Fishy
			return true;
		return false;
	};
}

struct scan_result
{
	std::uintptr_t loc;
};

// Struct for configuring scans.
struct scan_cfg
{
	// This is the page flag check, so if you want to filter it by access flags you can do so.
	std::function<bool(const std::uintptr_t)> page_flag_check = scanner_cfg_templates::page_flag_check_default;

	// Minimum and Maximum page size (in bytes)
	std::uintptr_t min_page_size = 0ull, max_page_size = ~0ull; // credits to Fishy for the suggestion using bit not instead of 0xFFFFFFFFFFFFFFFF

	// Are we scanning a specific module?
	std::string module_scanned;

	std::function<std::vector<scan_result>()> scan_routine; // Ignore this shit atm
};

// Struct for process, this will just have like the pid and the PROCESS
struct process
{
	std::uintptr_t pid;

	HANDLE curr_proc { nullptr };
	HMODULE curr_mod { nullptr };
	explicit process(const std::string_view process_name);
};

namespace scanner
{
	// The format should be "\xED\xEF\x0E", "??x"
	std::vector<scan_result> aob_scan(const process& proc, const std::string_view aob, const std::string_view mask, const scan_cfg& config = {});
}

int main()
{
	const auto a = process("scattern_panner.exe");
	std::cout << a.pid << "\r\n";

	scanner::aob_scan(a, "\xEF\xED", "??");
}