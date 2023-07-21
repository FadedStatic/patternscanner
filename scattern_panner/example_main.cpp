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

	const auto reqcheck = util::get_prologue(a, scanner::string_scan(a, "about:blank")[0].loc);
	const auto push_captures = util::get_prologue(a, scanner::string_scan(a, "too many captures")[0].loc);
	const auto push_captures_calls = util::get_calls(a, push_captures);
	const auto luaL_error = push_captures_calls[2].loc;
	const auto luaL_error_calls = util::get_calls(a, luaL_error);
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
	const auto tag_error = util::get_calls(a, str_gsub)[10].loc;
	const auto lua_typename = scanner::string_scan(a, "no value")[0].loc;
	const auto luaL_typeerrorL = util::get_prologue(a, util::get_calls(a, tag_error)[1].loc);
	const auto luaL_typeerrorL_calls = util::get_calls(a, luaL_typeerrorL);
	const auto currfuncname = luaL_typeerrorL_calls[0].loc;
	const auto luaL_where_calls = util::get_calls(a, luaL_where);
	const auto luaO_chunkid = luaL_where_calls[1].loc;
	const auto luaT_objtypename = luaL_typeerrorL_calls[2].loc;
	const auto luaT_objtypename_xrefs = scanner::xref_scan(a, luaT_objtypename);
	const auto luaG_typeerrorL = util::get_prologue(a, luaT_objtypename_xrefs[1].loc);
	const auto luaG_ordererror = util::get_prologue(a, luaT_objtypename_xrefs[5].loc);
	const auto luaG_runerrorL = util::get_calls(a, luaG_ordererror)[2].loc;
	const auto luaG_runerrorL_calls = util::get_calls(a, luaG_runerrorL);
	const auto pusherror = luaG_runerrorL_calls[1].loc;
	const auto pusherror_calls = util::get_calls(a, pusherror);
	const auto luaO_chunkid_xrefs = scanner::xref_scan(a, luaO_chunkid);
	const auto luau_load_inlined = util::get_prologue(a, luaO_chunkid_xrefs[3].loc);
	const auto getfunc = util::get_prologue(a, luaO_chunkid_xrefs[21].loc);
	const auto currentline = pusherror_calls[1].loc;
	const auto luaO_pushfstring = pusherror_calls[2].loc;
	const auto luaO_pushfstring_calls = util::get_calls(a, luaO_pushfstring);
	const auto luaO_pushvfstring = luaO_pushfstring_calls[0].loc;
	const auto luaO_pushvfstring_calls = util::get_calls(a, luaO_pushvfstring);
	const auto luaO_pushvfstring_xrefs = scanner::xref_scan(a, luaO_pushvfstring);
	const auto lua_pushfstringL = util::get_prologue(a, luaO_pushvfstring_xrefs[1].loc);
	const auto lua_pushfstringL_xrefs = scanner::xref_scan(a, lua_pushfstringL);
	const auto luaL_tolstring = util::get_prologue(a, lua_pushfstringL_xrefs[8].loc);
	const auto auxresume = util::get_prologue(a, lua_pushfstringL_xrefs[9].loc);
	const auto auxresume_calls = util::get_calls(a, auxresume);
	const auto lua_resume = auxresume_calls[3].loc;
	const auto lua_resume_calls = util::get_calls(a, lua_resume);
	const auto resume_error = lua_resume_calls[0].loc;
	const auto lua_xmove = auxresume_calls[4].loc;
	const auto luaD_rawrunprotected = lua_resume_calls[2].loc;
	const auto lua_resumeerror = util::get_prologue(a, scanner::xref_scan(a, resume_error)[2].loc);
	const auto lua_resumeerror_calls = util::get_calls(a, lua_resumeerror);
	const auto resume_findhandler = lua_resumeerror_calls[1].loc;
	const auto resume_finish = lua_resumeerror_calls[3].loc;
	const auto seterrorobj = util::get_calls(a, resume_finish)[0].loc;
	const auto seterrorobj_xrefs = scanner::xref_scan(a, seterrorobj);
	const auto luaB_pcally = util::get_prologue(a, seterrorobj_xrefs[2].loc);
	const auto luaB_pcally_calls = util::get_calls(a, luaB_pcally);
	const auto lua_rawcheckstack = luaB_pcally_calls[4].loc;
	const auto lua_rawcheckstack_xrefs = scanner::xref_scan(a, lua_rawcheckstack);
	const auto db_info = util::get_prologue(a, lua_rawcheckstack_xrefs[0].loc);
	const auto luaB_pcallcont = util::get_prologue(a, lua_rawcheckstack_xrefs[2].loc);
	const auto luaB_xpcallcont = util::get_prologue(a, lua_rawcheckstack_xrefs[4].loc);
	const auto auxresumecont = util::get_prologue(a, lua_rawcheckstack_xrefs[6].loc);
	const auto luaL_pushresults = str_gsub_calls[9].loc;
	const auto luaL_pushresults_xrefs = scanner::xref_scan(a, luaL_pushresults);
	const auto codepoint = util::get_prologue(a, scanner::string_scan(a, "string slice too long")[0].loc);
	const auto codepoint_calls = util::get_calls(a, codepoint); 
	const auto lua_tointegerx = codepoint_calls[3].loc;
	const auto lua_tointegerx_calls = util::get_calls(a, lua_tointegerx);
	const auto pseudo2addr = lua_tointegerx_calls[0].loc;
	const auto luaL_checkstack = codepoint_calls[4].loc;
	const auto utf8_decode = codepoint_calls[5].loc;
	const auto utf8_decode_xrefs = scanner::xref_scan(a, utf8_decode);
	const auto utflen = util::get_prologue(a, utf8_decode_xrefs[0].loc);
	const auto iter_aux = util::get_prologue(a, utf8_decode_xrefs[2].loc);
	const auto db_traceback = util::get_prologue(a, luaL_pushresults_xrefs[0].loc);
	const auto utfchar = util::get_prologue(a, luaL_pushresults_xrefs[1].loc);
	const auto utfchar_calls = util::get_calls(a, utfchar);
	const auto buffutfchar = utfchar_calls[0].loc;
	const auto str_format = util::get_prologue(a, luaL_pushresults_xrefs[8].loc);
	const auto str_format_calls = util::get_calls(a, str_format);
	const auto luaL_checklstring = str_format_calls[0].loc;
	const auto luaL_extendbuffer = str_format_calls[1].loc;
	const auto luaL_checknumber = str_format_calls[4].loc;
	const auto lua_clock = luaC_step_calls[0].loc;
	const auto gcstep = luaC_step_calls[3].loc;
	const auto gcstep_calls = util::get_calls(a, gcstep);
	const auto gcstep_xrefs = scanner::xref_scan(a, gcstep);
	const auto luaC_fullgc = util::get_prologue(a, gcstep_xrefs[1].loc);
	const auto luaC_fullgc_calls = util::get_calls(a, luaC_fullgc);
	const auto luaC_fullgc_xrefs = scanner::xref_scan(a, luaC_fullgc);
	const auto markroot = gcstep_calls[0].loc;
	const auto markroot_calls = util::get_calls(a, markroot);
	const auto propagatemark = gcstep_calls[1].loc;
	const auto propagatemark_calls = util::get_calls(a, propagatemark);
	const auto reallymarkobject = markroot_calls[0].loc;
	const auto finishGcCycleMetrics = luaC_fullgc_calls[2].loc;
	const auto shrinkbuffersfull = luaC_fullgc_calls[6].loc;
	const auto lua_collectgarbage = util::get_prologue(a, luaC_fullgc_xrefs[0].loc);
	const auto resume_handle = util::get_prologue(a, seterrorobj_xrefs[0].loc);
	const auto resume_handle_calls = util::get_calls(a, resume_handle);
	const auto resume_continue = resume_handle_calls[resume_handle_calls.size() - 1].loc;
	const auto resume_continue_xrefs = scanner::xref_scan(a, resume_continue);
	const auto resume = util::get_prologue(a, resume_continue_xrefs[1].loc);

	const auto end_time = std::chrono::high_resolution_clock::now();
	std::printf("Time taken: %lldms\r\n", std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count());

	return_vector.push_back({ "reqcheck", reqcheck});
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
	return_vector.push_back({ "luaL_typeerrorL", luaL_typeerrorL });
	return_vector.push_back({ "currfuncname", currfuncname });
	return_vector.push_back({ "luaO_chunkid", luaO_chunkid });
	return_vector.push_back({ "luaT_objtypename", luaT_objtypename });
	return_vector.push_back({ "luaG_typeerrorL", luaG_typeerrorL });
	return_vector.push_back({ "luaG_ordererror", luaG_ordererror });
	return_vector.push_back({ "luaG_runerrorL", luaG_runerrorL });
	return_vector.push_back({ "pusherror", pusherror });
	return_vector.push_back({ "luau_load_inlined", luau_load_inlined });
	return_vector.push_back({ "getfunc", getfunc });
	return_vector.push_back({ "currentline", currentline });
	return_vector.push_back({ "luaO_pushfstring", luaO_pushfstring });
	return_vector.push_back({ "luaO_pushvfstring", luaO_pushvfstring });
	return_vector.push_back({ "lua_pushfstringL", lua_pushfstringL });
	return_vector.push_back({ "luaL_tolstring", luaL_tolstring });
	return_vector.push_back({ "auxresume", auxresume });
	return_vector.push_back({ "lua_resume", lua_resume });
	return_vector.push_back({ "resume_error", resume_error });
	return_vector.push_back({ "lua_xmove", lua_xmove });
	return_vector.push_back({ "luaD_rawrunprotected", luaD_rawrunprotected });
	return_vector.push_back({ "lua_resumeerror", lua_resumeerror });
	return_vector.push_back({ "resume_finish", resume_finish });
	return_vector.push_back({ "seterrorobj", seterrorobj });
	return_vector.push_back({ "resume_findhandler", resume_findhandler });
	return_vector.push_back({ "luaB_pcally", luaB_pcally });
	return_vector.push_back({ "lua_rawcheckstack", lua_rawcheckstack });
	return_vector.push_back({ "db_info", db_info });
	return_vector.push_back({ "luaB_pcallcont", luaB_pcallcont });
	return_vector.push_back({ "luaB_xpcallcont", luaB_xpcallcont });
	return_vector.push_back({ "auxresumecont", auxresumecont });
	return_vector.push_back({ "luaL_pushresults", luaL_pushresults });
	return_vector.push_back({ "codepoint", codepoint });
	return_vector.push_back({ "lua_tointegerx", lua_tointegerx });
	return_vector.push_back({ "pseudo2addr", pseudo2addr });
	return_vector.push_back({ "luaL_checkstack", luaL_checkstack });
	return_vector.push_back({ "utf8_decode", utf8_decode });
	return_vector.push_back({ "utflen", utflen });
	return_vector.push_back({ "iter_aux", iter_aux });
	return_vector.push_back({ "db_traceback", db_traceback });
	return_vector.push_back({ "utfchar", utfchar });
	return_vector.push_back({ "buffutfchar", buffutfchar });
	return_vector.push_back({ "str_format", str_format });
	return_vector.push_back({ "luaL_checklstring", luaL_checklstring });
	return_vector.push_back({ "luaL_extendbuffer", luaL_extendbuffer });
	return_vector.push_back({ "luaL_checknumber", luaL_checknumber });
	return_vector.push_back({ "lua_clock", lua_clock });
	return_vector.push_back({ "gcstep", gcstep });
	return_vector.push_back({ "luaC_fullgc", luaC_fullgc });
	return_vector.push_back({ "markroot", markroot });
	return_vector.push_back({ "propagatemark", propagatemark });
	return_vector.push_back({ "finishGcCycleMetrics", finishGcCycleMetrics });
	return_vector.push_back({ "shrinkbuffersfull", shrinkbuffersfull });
	return_vector.push_back({ "lua_collectgarbage", lua_collectgarbage });
	return_vector.push_back({ "resume_handle", resume_handle });
	return_vector.push_back({ "resume_continue", resume_continue });
	return_vector.push_back({ "resume", resume });

	return return_vector;
}



int main()
{
	const scan_cfg cfg =
	{
		//"ntdll.dll"
	};

	const auto a = process("Windows10Universal.exe");
	for (const auto d : get_offs(a))
	{
		std::printf("MakeName(0x%02llX, \"", util::rebase(a, d.addr), d.name);
		std::cout << d.name << "\");\r\n";
	}
}