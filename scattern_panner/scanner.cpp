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


process::process(const std::string_view process_name)
{
	std::vector<std::uint32_t> pid_list(max_processes); // adjust these values if you're running into index errors
	std::vector<HMODULE> module_list(max_modules);
	DWORD n_pids{ 0 };
	K32EnumProcesses(reinterpret_cast<DWORD*>(pid_list.data()), static_cast<std::uint32_t>(pid_list.capacity()) * sizeof(DWORD), &n_pids);

	pid_list.resize(n_pids / 4); // shrink that heap alloc so it isn't that bad
	std::string module_name(MAX_PATH, '\x0'); // MAX_FILE
	const auto default_mod_name = module_name;

	for (const auto i : pid_list)
	{
		if (const auto proc_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, i); proc_handle)
		{
			DWORD n_modules{ 0 };
			if (K32EnumProcessModulesEx(proc_handle, module_list.data(), static_cast<std::uint32_t>(module_list.capacity()) * sizeof(HMODULE), &n_modules, LIST_MODULES_ALL))
			{
				module_list.resize(n_modules / sizeof(HMODULE));
				for (const auto& j : module_list)
				{
					if (K32GetModuleBaseNameA(proc_handle, j, module_name.data(), MAX_PATH))
					{
						// Reason for this is that we're going to just have zeroes
						std::erase_if(module_name, [](const char c)
						{
							return !c;
						});

						if (module_name == process_name.data())
						{
							this->curr_proc = proc_handle;
							this->pid = i;
							this->curr_mod = j;
							return;
						}
					}

					module_name.clear();
					module_name.resize(MAX_PATH);
				}

				module_list.clear();
				module_list.resize(max_modules);
			}
		}
	}
	throw std::runtime_error("Process not found.");
}

std::vector<scan_result> scanner::scan(const process& proc, const std::string_view aob, const std::string_view mask, const scan_cfg& config)
{
	std::vector<scan_result> ret;

	const auto is_internal = (GetCurrentProcessId() == proc.pid);
	const auto is_modulerange = !config.module_scanned.empty();
	auto mod_found = proc.curr_mod;

	const auto scan_base_address = is_internal ? 
	[config] {
		return reinterpret_cast<std::uintptr_t>(GetModuleHandleA(config.module_scanned.data()));
	}()
	:
	[proc, config, &mod_found, is_modulerange] {
		if (is_modulerange)
		{
			mod_found = [proc, config] {
				std::vector<HMODULE> module_list(max_modules);
				DWORD n_modules{ 0 };
				std::string module_name(MAX_PATH, '\x0');

				if (K32EnumProcessModulesEx(proc.curr_proc, module_list.data(), static_cast<std::uint32_t>(module_list.capacity()) * sizeof(HMODULE), &n_modules, LIST_MODULES_ALL))
				{
					module_list.resize(n_modules / sizeof(HMODULE));
					for (const auto& j : module_list)
					{
						if (K32GetModuleBaseNameA(proc.curr_proc, j, module_name.data(), MAX_PATH))
						{
							std::erase_if(module_name, [](const char c)
							{
								return !c;
							});

							if (module_name == config.module_scanned)
								return j;
						}

						module_name.clear();
						module_name.resize(MAX_PATH);
					}
				}
				throw std::runtime_error("No module found under this name.");
			}();
		}

		MODULEINFO mod_info;
		if (K32GetModuleInformation(proc.curr_proc, mod_found, &mod_info, sizeof(mod_info)))
			return reinterpret_cast<std::uintptr_t>(mod_info.lpBaseOfDll);

		throw std::runtime_error("Error getting module base address. Call GetLastError to see problem.");
	}();

	if (!mod_found)
		return ret;

	std::printf("%02llX", scan_base_address);
	if (is_internal)
	{
		// Be very intelligent here
		return ret;
	}
	else
	{
	}

	return ret;
}
