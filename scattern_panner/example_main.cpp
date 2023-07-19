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

	/*
	 *const auto start_time = std::chrono::high_resolution_clock::now();

	const auto tmc = EyeStep::scanner::scan_xrefs("too many captures")[0];

	const auto push_captures = EyeStep::util::getPrologue(tmc);

	const auto push_captures_calls = EyeStep::util::getCalls(push_captures);

	ret.push_back({ "push_captures", EyeStep::util::raslr(push_captures) });

	ret.push_back({ "lua_checkstack", EyeStep::util::raslr(push_captures_calls[0])});
	const auto luaL_error = push_captures_calls[2];
	ret.push_back({ "luaL_error", EyeStep::util::raslr(luaL_error) });
	ret.push_back({ "push_onecapture", EyeStep::util::raslr(push_captures_calls[1]) });
	const auto luaL_error_calls = EyeStep::util::getCalls(luaL_error);

	const auto end_time = std::chrono::high_resolution_clock::now();
	std::printf("Time taken: %lldms\n", std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count());

	for (const auto& c : luaL_error_calls)
		std::printf("%02X\n", EyeStep::util::raslr(c));
	 *
	 *
	 */
	/*
	155E370
	155D9A0
	15AD910
	15DEBE0
	15E0860
	156FC40
	15DEBE0
	15DEBE0
	15E9A50
	15E9840
	15E9A50
	15E9950
	15E9B00
	15E80D0
	1570390
	156CF40
	15E9810

155E370
155D9A0
15AD910
15DEBE0
15E0860
156FC40
15DEBE0
15DEBE0
15E9A50
15E9840
15E9A50
EA55F3E0
15E9950
15E9B00
15E80D0
155DEC0
1570390
156CF40
15E9810
	 */
	const auto start_time = std::chrono::high_resolution_clock::now();

	const auto scan_loc = scanner::string_scan(a, "too many captures")[0].loc;

	const auto push_captures = util::get_prologue(a, scan_loc);
	const auto push_captures_calls = util::get_calls(a, push_captures);

	const auto luaL_error = push_captures_calls[2].loc;
	const auto luaL_error_calls = util::get_calls(a, luaL_error);
	// 	ret.push_back({ "str_find_aux", EyeStep::util::raslr(EyeStep::util::getPrologue(EyeStep::scanner::scan_xrefs(push_captures)[1]))});

	const auto str_find_aux = util::get_prologue(a, scanner::xref_scan(a, push_captures)[1].loc);
	const auto end_time = std::chrono::high_resolution_clock::now();
	std::printf("Time taken: %lldms\nLoc: %llX\n", std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count(), util::rebase(a, str_find_aux));
}