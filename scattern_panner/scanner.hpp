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
#include <shared_mutex>
#include <string_view>
#include <Psapi.h>
#include <processthreadsapi.h>
#include <thread>

// This part will be using preprocessor macros so that performance profiling isnt compiled by default, this way we save a negligible amount of CPU time
#define PERFORMANCE_PROFILING_MODE false // true = true, false = false
// False by default, this will set the priority of the process for better use of resources (faster scanning), this is advised for external applications but not for internal, as it could be detected easily.
// Also note, this will set the priority back to the old priority when we are done with scanning.
#define SET_PRIORITY_OPTIMIZATION true 


// Misc. Settings for the 
constexpr auto max_modules = 512; // 512 by default
constexpr auto max_processes = 1024; // 1024 by default

struct scan_result
{
	std::uintptr_t loc;
};

// Struct for process, this will just have like the pid and the PROCESS
struct process
{
	std::uintptr_t pid, proc_base;
	bool is32; // False means x86_64, True means just x86 
	HANDLE curr_proc{ nullptr };
	HMODULE curr_mod{ nullptr };
	explicit process(const std::string_view process_name);
};

// INSTRUCTIONS FOR ADDING CUSTOM ARGUMENTS!
// This struct will be UNTOUCHED by the scan function, and it is up to you to add whatever relevant information is required to this.
// Now, when you add an argument or something it's not that important, you WILL have to compile the source as any linked libraries will contain a different definition of scanner_args, but no additional modifications will have to be made.
// If you are to add an argument, please do it at the bottom-most variable, as it will not break any structured binding in the methods.
struct scanner_optargs
{
	// This is where the optional args go in.
	const std::string_view xref_trace_endianized; // This is the offset we are looking for in scanning, it's endianized.

	// ADD PAST THIS LINE!
};

// Expr suggested making this a struct, so I did just that.
struct scanner_args
{
	const process& proc;
	const std::uintptr_t start;
	const std::uintptr_t end;
	std::shared_mutex& return_vector_mutex;
	std::vector<scan_result>& return_vector;
	const std::string_view aob;
	const std::string_view mask;
	scanner_optargs opt_args;
};

namespace scanner_cfg_templates
{
	// This is an example, you can either make this a function or a variable containing lambda or std::function.
	// Argument must be std::uintptr_t and return must be bool.
	const auto page_flag_check_default = [](const std::uintptr_t page_flags) -> bool
	{
		// Credits to Fishy for this genius optimization (see credits in readme for more information)
		return !(page_flags & (PAGE_NOACCESS | PAGE_GUARD)) && (page_flags & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ)) && !(page_flags == PAGE_EXECUTE && !(page_flags & (PAGE_GUARD | PAGE_NOACCESS)));
	};

	// Reference the cpp file for more information about this.
	void aob_scan_routine_internal_default(const scanner_args& args),
		 aob_scan_routine_external_default(const scanner_args& args),
		 string_xref_scan_internal_default(const scanner_args& args),
		 string_xref_scan_external_default(const scanner_args& args);
}

// Struct for configuring scans.
struct scan_cfg
{
	// Are we scanning a specific module?
	std::string module_scanned;

	// This is the page flag check, so if you want to filter it by access flags you can do so.
	std::function<bool(const std::uintptr_t)> page_flag_check = scanner_cfg_templates::page_flag_check_default;

	// Minimum and Maximum page size (in bytes)
	std::uintptr_t min_page_size = 0ull, max_page_size = ~0ull; // credits to Fishy for the suggestion using bit not instead of 0xFFFFFFFFFFFFFFF

	// Change these dependent on the scan function.
	// By default, this is AOB scanning.
	// This is more useful if you need to scan for something more specific (opaque predicates etc)
	std::function<void(const scanner_args&) > scan_routine_internal = scanner_cfg_templates::aob_scan_routine_internal_default, scan_routine_external = scanner_cfg_templates::aob_scan_routine_external_default;
};

namespace scanner
{
	// The format should be "\xED\xEF\x0E", "??x"
	std::vector<scan_result> scan(const process& proc, const std::string_view aob, const std::string_view mask, const scan_cfg& config = {}, const scanner_optargs& opt_args = {});

	// BELOW THIS LINE YOU CANNOT CHANGE scan_routine_internal and scan_routine_external, doesnt matter if you do we ignore it anyways.

	// This is for scanning string xrefs, so if you had a string such as "we are mcdonalds gaming", it would get all xrefs of that string.
	// Null terminator is not important, if you are missing it it will find it anyways.
	// n_result is the number result of the scan we are targeting.
	std::vector<scan_result> string_scan(const process& proc, const std::string_view str, const scan_cfg& config = {}, const std::uintptr_t n_result = 0);
}

namespace util
{
	template <typename T> requires std::is_integral_v<T>
	T rebase(const process& proc, const T address, const T new_base = 0)
	{
		return address - static_cast<T>(proc.proc_base) + new_base;
	}

	std::vector<scan_result> get_calls(const process& proc, const std::uintptr_t func);
	std::vector<scan_result> get_jumps(const process& proc, const std::uintptr_t func);
	std::uintptr_t get_prologue(const process& proc, const std::uintptr_t func);
	// all_alignment pretty much means that all bytes after ret must be 0x90 or 0xC3 until the next prologue in order for a match to occur.
	// min_alignment is the amount of alignment that is required for a match to occur, so if you know that your epilogue will have x amount of alignment bytes, then this helps increase speed tremendously.
	std::uintptr_t get_epilogue(const process& proc, const std::uintptr_t func, const bool all_alignment=true, const std::uint32_t min_alignment = 0);
	std::uintptr_t resolve_relative(const std::uintptr_t func, const std::uintptr_t loc);
}