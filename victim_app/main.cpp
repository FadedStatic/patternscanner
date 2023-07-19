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

#include <iostream>
#include <Windows.h>
#include <string_view>
#include <vector>
#include <Windows.h>

auto finding_nemo = "Finding nemo.";

__declspec(noinline) std::uintptr_t get_module_base_address(const std::string_view str)
{
	return reinterpret_cast<std::uintptr_t>(str.empty() ? GetModuleHandleA(nullptr) : GetModuleHandleA(str.data()));
}

__declspec(noinline) std::string SCAN_FOR_ME()
{
	auto retn_string = std::string();
	for (auto c : std::string(finding_nemo))
		retn_string.push_back(c);

	return retn_string;
}

int mainer()
{
	SetConsoleTitleA("Pattern Scanner Testing Application");
	const auto str = SCAN_FOR_ME();

	std::printf("Program Base Address: %02llX\nntdll.dll Base: %02llX\nAddress of str: %02llX\n", get_module_base_address(""), get_module_base_address("ntdll.dll"), reinterpret_cast<std::uintptr_t>(&finding_nemo) - get_module_base_address(""));
	std::cin.get();

	return get_module_base_address(str);
}