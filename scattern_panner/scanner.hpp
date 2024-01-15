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

#pragma once

#include <functional>
#include <iostream>
#include <Windows.h>
#include <shared_mutex>
#include <string_view>
#include <Psapi.h>
#include <processthreadsapi.h>
#include <thread>
#include <expected>

#define PERFORMANCE_PROFILING_MODE false
#define SET_PRIORITY_OPTIMIZATION true 


// Misc. Settings for the 
constexpr auto max_modules = 512;
constexpr auto max_processes = 1024;

struct scan_result
{
	std::uintptr_t loc;
};

// Struct for process, this will just have like the pid and the PROCESS
struct process
{
	std::uintptr_t pid, proc_base;
	bool is32;
	HANDLE curr_proc{ nullptr };
	HMODULE curr_mod{ nullptr };

	// process_is_owner: this basically means that your process is running on its own, not as a module of another process.
	// if your process is running under a host such as conhost (console host) and is not being discovered, make this arg false.
	explicit process(const std::string_view process_name);
};

// INSTRUCTIONS FOR ADDING CUSTOM ARGUMENTS!
// When you adding an argument, you WILL have to compile the source as any linked libraries will contain a different definition of scanner_args, but no additional modifications will have to be made.
// If you are to add an argument, please do it at the bottom-most variable, as it will not break any structured binding in the methods.
struct scanner_optargs
{
	const std::string_view xref_trace_endianized;
	const std::uintptr_t xref_trace_int;
	// add your args below this
};

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
	const auto page_flag_check_default = [](const std::uintptr_t page_flags) -> bool
	{
		// Credits to Fishy
		return !(page_flags & (PAGE_NOACCESS | PAGE_GUARD)) && (page_flags & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ)) && !(page_flags == PAGE_EXECUTE && !(page_flags & (PAGE_GUARD | PAGE_NOACCESS)));
	};

	void aob_scan_routine_internal_default(const scanner_args& args),
		aob_scan_routine_external_default(const scanner_args& args),
		string_xref_scan_internal_default(const scanner_args& args),
		string_xref_scan_external_default(const scanner_args& args),
		function_xref_scan_internal_default(const scanner_args& args),
		function_xref_scan_external_default(const scanner_args& args);
}

struct scan_cfg
{
	std::string module_scanned;

	std::function<bool(const std::uintptr_t)> page_flag_check = scanner_cfg_templates::page_flag_check_default;

	std::uintptr_t min_page_size = 0ull, max_page_size = ~0ull; // credits to Fishy for suggesting ~0ull

	std::function<void(const scanner_args&) > scan_routine_internal = scanner_cfg_templates::aob_scan_routine_internal_default, scan_routine_external = scanner_cfg_templates::aob_scan_routine_external_default;
};

namespace scanner
{
	// The format should be "\xED\xEF\x0E", "??x"
	std::vector<scan_result> scan(const process& proc, const std::string_view aob, const std::string_view mask, const scan_cfg& config = {}, const scanner_optargs& opt_args = {});

	// Changing the scan routines on string_scan and xref_scan through scan_cfg will do nothing.
	std::vector<scan_result> string_scan(const process& proc, const std::string_view str, const scan_cfg& config = {}, const std::uintptr_t n_result = 0);

	std::vector<scan_result> xref_scan(const process& proc, const std::uintptr_t func, const scan_cfg& config = {}, const bool include_twobyte = false);
}

namespace util
{
	template <typename T> requires std::is_integral_v<T>
	T rebase(const process& proc, const T address, const T new_base = 0)
	{
		return address - static_cast<T>(proc.proc_base) + new_base;
	}

	std::vector<scan_result> get_calls(const process& proc, const std::uintptr_t func);

	// functions_only: do an alignment check
	std::vector<scan_result> get_jumps(const process& proc, const std::uintptr_t func, const bool functions_only=true, const bool include_twobyte_jmps=false);

	auto get_prologue(const process& proc, const std::uintptr_t func) -> std::expected<std::uintptr_t, std::string>;

	// all_alignment: all bytes after ret must be 0x90 or 0xC3 until the next prologue in order for a match to occur.
	// min_alignment: use this if you know how many alignment bytes your function has before the epilogue
	auto get_epilogue(const process& proc, const std::uintptr_t func, const bool all_alignment=true, const std::uint32_t min_alignment = 0) -> std::expected<std::uintptr_t, std::string>;
}