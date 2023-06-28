/*
 * Copyright 2023 FadedStatic
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#pragma once

#include <functional>
#include <iostream>
#include <Windows.h>
#include <string_view>
#include <Psapi.h>
#include <processthreadsapi.h>
#include <thread>

constexpr auto max_modules = 512; // 512 by default
constexpr auto max_processes = 1024; // 1024 by default

struct scan_result
{
	std::uintptr_t loc;
};

namespace scanner_cfg_templates
{
	// This is an example, you can either make this a function or a variable containing lambda or std::function.
	// Argument must be std::uintptr_t and return must be bool.
	const auto page_flag_check_default = [](const std::uintptr_t page_flags) -> bool
	{
		return !(page_flags bitand PAGE_NOACCESS) and !(page_flags bitand PAGE_GUARD) and ((page_flags bitand PAGE_READWRITE) or (page_flags bitand PAGE_READONLY) or (page_flags bitand PAGE_EXECUTE_READWRITE)) and !(page_flags bitand PAGE_EXECUTE);
	};

	// Reference the cpp file for more information about this.
	std::vector<scan_result> aob_scan_routine_internal_default(const std::uintptr_t start, const std::uintptr_t end, const std::string_view aob, const std::string_view mask), aob_scan_routine_external_default(const std::uintptr_t start, const std::uintptr_t end, const std::string_view aob, const std::string_view mask);
}

// Struct for configuring scans.
struct scan_cfg
{
	// Are we scanning a specific module?
	std::string module_scanned;

	// This is the page flag check, so if you want to filter it by access flags you can do so.
	std::function<bool(const std::uintptr_t)> page_flag_check = scanner_cfg_templates::page_flag_check_default;

	// Minimum and Maximum page size (in bytes)
	std::uintptr_t min_page_size = 0ull, max_page_size = ~0ull; // credits to Fishy for the suggestion using bit not instead of 0xFFFFFFFFFFFFFFFF

	// Change these dependent on the scan function.
	// By default, this is AOB scanning.
	// This is more useful if you need to scan for something more specific (opaque predicates etc)
	std::function<std::vector<scan_result>(const std::uintptr_t, const std::uintptr_t, const std::string_view, const std::string_view)> scan_routine_internal = scanner_cfg_templates::aob_scan_routine_internal_default, scan_routine_external = scanner_cfg_templates::aob_scan_routine_external_default;
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
	std::vector<scan_result> scan(const process& proc, const std::string_view aob, const std::string_view mask, const scan_cfg& config = {});
}