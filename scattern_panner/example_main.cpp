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

#include <format>

#include "scanner.hpp"

int main()
{
	const scan_cfg cfg =
	{
		//"ntdll.dll"
	};

	const auto opened_process = process("victim_app.exe");
	std::printf("Process ID: %llu\nProcess base address: 0x%02llX\nProcess is under wow64: %d\n", opened_process.pid, opened_process.proc_base, opened_process.is32);

	// scan for xrefs to "BASE STRING PREFIX"
	const auto str_results = scanner::string_scan(opened_process, "BASE STRING PREFIX");
	for (const auto & [loc] : str_results) {
		std::printf("String xref found at: 0x%02llX\n", util::rebase(opened_process, loc));
	}

	const auto SCAN_FOR_ME = util::get_prologue(opened_process, str_results[0].loc);
	std::printf("SCAN_FOR_ME: 0x%02llX\n", util::rebase(opened_process, SCAN_FOR_ME));

	const auto scan_for_me_xrefs = scanner::xref_scan(opened_process, SCAN_FOR_ME);
	for (const auto & [loc] : scan_for_me_xrefs) {
		std::printf("SCAN_FOR_ME xref found at: 0x%02llX\n", util::rebase(opened_process, loc));
	}

	std::cin.get();
	return 0;
}