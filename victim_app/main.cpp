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

#include <iostream>
#include <Windows.h>
#include <string_view>
#include <vector>

auto finding_nemo = "Finding nemo.";

__declspec(noinline) std::uintptr_t get_module_base_address(const std::string_view str)
{
	return reinterpret_cast<std::uintptr_t>(str.empty() ? GetModuleHandleA(nullptr) : GetModuleHandleA(str.data()));
}

__declspec(noinline) std::string SCAN_FOR_ME()
{
	auto retn_string = std::string("BASE STRING PREFIX");
	for (auto c : std::string(finding_nemo))
		retn_string.push_back(c);

	return retn_string;
}

int main()
{
	SetConsoleTitleA("Pattern Scanner Testing Application");
	const auto str = SCAN_FOR_ME();

	std::printf("Program Base Address: %02llX\nntdll.dll Base: %02llX\nAddress of str: %02llX\n", get_module_base_address(""), get_module_base_address("ntdll.dll"), reinterpret_cast<std::uintptr_t>(&finding_nemo) - get_module_base_address(""));
	std::cin.get();

	return get_module_base_address(str);
}