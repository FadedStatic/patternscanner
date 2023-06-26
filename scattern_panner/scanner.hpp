#pragma once

#include <functional>
#include <Windows.h>

namespace scanner_cfg_templates
{
	const auto page_flag_check_default = [](const std::uintptr_t page_flags) -> bool
	{
		if (page_flags != PAGE_GUARD and page_flags != PAGE_NOACCESS and (page_flags == PAGE_READWRITE or page_flags == PAGE_EXECUTE or page_flags == PAGE_EXECUTE_READWRITE or page_flags == PAGE_EXECUTE_READ or page_flags == PAGE_READONLY))
			return true;
		return false;
	};
}

// Struct for configuring scans.
struct scan_cfg
{
	// This is the page flag check, so if you want to filter it by access flags you can do so.
	std::function<bool(const std::uintptr_t)> page_flag_check = scanner_cfg_templates::page_flag_check_default;

	// Minimum and Maximum page size (in bytes)
	std::uintptr_t min_page_size, max_page_size = 0ull, 0ull;
};
