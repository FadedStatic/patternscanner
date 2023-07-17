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

#include "scanner.hpp"


int main()
{
	auto a = process("Windows10Universal.exe");

	const scan_cfg cfg =
	{
		//"ntdll.dll"
	};
	// too many captures
	// xxxxxxxxxxxxxxxxx

	const auto scan_loc = scanner::string_scan(a, "too many captures")[0].loc;

	const auto start_time = std::chrono::high_resolution_clock::now();

	const auto push_captures = util::get_prologue(a, scan_loc);
	const auto push_captures_calls = util::get_calls(a, push_captures);
	const auto end_time = std::chrono::high_resolution_clock::now();
	std::printf("Time taken: %lldms\n", std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count());

	for (const auto& [c] : push_captures_calls)
		std::printf("Found sig at: %02llX\nRebased: %02llX\n", c, util::rebase(a, c));
}