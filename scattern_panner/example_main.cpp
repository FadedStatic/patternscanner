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


struct addr_match
{
	std::string name;
	std::uintptr_t addr;
};

std::vector<addr_match> get_offs(const process& a)
{
	std::vector<addr_match> return_vector;

	const auto start_time = std::chrono::high_resolution_clock::now();

	const auto scan_loc = scanner::string_scan(a, "too many captures")[0].loc;

	const auto push_captures = util::get_prologue(a, scan_loc);
	const auto push_captures_calls = util::get_calls(a, push_captures);

	const auto luaL_error = push_captures_calls[2].loc;
	const auto luaL_error_calls = util::get_calls(a, luaL_error);
	// 	ret.push_back({ "str_find_aux", EyeStep::util::raslr(EyeStep::util::getPrologue(EyeStep::scanner::scan_xrefs(push_captures)[1]))});

	const auto str_find_aux = util::get_prologue(a, scanner::xref_scan(a, push_captures)[1].loc);

	const auto luaD_throw = luaL_error_calls[luaL_error_calls.size() - 2].loc;
	const auto luaL_where = luaL_error_calls[0].loc;
	const auto lua_pushvfstring = luaL_error_calls[1].loc;
	const auto luaC_step = luaL_error_calls[2].loc;
	const auto luaC_step_calls = util::get_calls(a, luaC_step);

	const auto luaV_tostring = luaL_error_calls[3].loc;
	const auto add_value = util::get_prologue(a, scanner::xref_scan(a, push_captures)[2].loc);
	const auto add_value_xrefs = scanner::xref_scan(a, add_value);
	const auto str_gsub = util::get_prologue(a, add_value_xrefs[0].loc);
	const auto str_gsub_calls = util::get_calls(a, str_gsub);
	const auto tag_error = util::get_calls(a, str_gsub)[11].loc;
	const auto lua_typename = scanner::string_scan(a, "no value")[0].loc - 1;
	//const auto luaL_typeerrorL = util::get_prologue(a, util::get_calls(a, tag_error)[0].loc);
	//const auto luaL_typeerrorL_calls = util::get_calls(a, luaL_typeerrorL);
	//std::printf("%02llX\n", util::rebase(a, luaL_typeerrorL));
	const auto end_time = std::chrono::high_resolution_clock::now();
	std::printf("Time taken: %lldms\nLoc: %llX\n", std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count(), util::rebase(a, str_find_aux));

	return_vector.push_back({ "push_captures", push_captures });
	return_vector.push_back({ "luaL_error", luaL_error });
	return_vector.push_back({ "str_find_aux", str_find_aux });
	return_vector.push_back({ "luaD_throw", luaD_throw });
	return_vector.push_back({ "luaL_where", luaL_where });
	return_vector.push_back({ "lua_pushvfstring", lua_pushvfstring });
	return_vector.push_back({ "luaC_step", luaC_step });
	return_vector.push_back({ "luaV_tostring", luaV_tostring });
	return_vector.push_back({ "add_value", add_value });
	return_vector.push_back({ "str_gsub", str_gsub });
	return_vector.push_back({ "tag_error", tag_error });
	return_vector.push_back({ "lua_typename", lua_typename });
	//return_vector.push_back({ "luaL_typeerrorL", luaL_typeerrorL });

	return return_vector;
}



int main()
{
	const scan_cfg cfg =
	{
		//"ntdll.dll"
	};

	const auto a = process("Windows10Universal.exe");
	for (const auto& [name, addr] : get_offs(a))
		std::printf("%02llX, %s\n", util::rebase(a, addr), name);

	/*

	const auto luaL_typeerrorL = EyeStep::util::getPrologue(EyeStep::util::getCalls(tag_error)[0]);
	const auto luaL_typeerrorL_calls = EyeStep::util::getCalls(luaL_typeerrorL);
	ret.push_back({ "luaL_typeerrorL", EyeStep::util::raslr(luaL_typeerrorL) });
	const auto currfuncname = EyeStep::util::getEpilogue(EyeStep::util::getPrologue(EyeStep::util::getPrologue(luaL_typeerrorL - 0xC) - 0xC)) + 0x3;
	ret.push_back({ "currfuncname", EyeStep::util::raslr(currfuncname) });

	const auto luaL_where_calls = EyeStep::util::getCalls(luaL_where);
	const auto luaO_chunkid = luaL_where_calls[0];
	ret.push_back({ "luaO_chunkid", EyeStep::util::raslr(luaO_chunkid) });
	 */
}