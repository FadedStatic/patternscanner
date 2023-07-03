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
	std::cout << a.pid << "\r\n";

	const scan_cfg cfg =
	{
		//"ntdll.dll"
	};
	// \x74\x6F\x6F\x20\x6D\x61\x6E\x79\x20\x63\x61\x70\x74\x75\x72\x65\x73
	// xxxxxxxxxxxxxxxxx
	for (const auto& [loc] : scanner::scan(a, "\x74\x6F\x6F\x20\x6D\x61\x6E\x79\x20\x63\x61\x70\x74\x75\x72\x65\x73", "xxxxxxxxxxx???xxx"))
		std::printf("Found sig at: %02llX\n", util::rebase(a, loc));

	for (const auto& [loc] : scanner::string_scan(a, "too many captures"))
		std::printf("Found sig at: %02llX\n", util::rebase(a, loc));
}