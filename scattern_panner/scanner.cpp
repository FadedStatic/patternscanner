#include "scanner.hpp"


process::process(const std::string_view process_name)
{
	std::vector<std::uint32_t> pid_list(1024); // adjust these values if you're running into index errors
	std::vector<HMODULE> module_list(512);
	DWORD n_pids{ 0 };
	K32EnumProcesses(reinterpret_cast<DWORD*>(pid_list.data()), static_cast<std::uint32_t>(pid_list.capacity()) * sizeof(DWORD), &n_pids);

	pid_list.resize(n_pids / 4); // shrink that heap alloc so it isn't that bad
	std::string module_name(260, '\x0'); // MAX_FILE
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
					if (K32GetModuleBaseNameA(proc_handle, j, module_name.data(), 260))
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
					module_name.resize(260);
				}

				module_list.clear();
				module_list.resize(1024);
			}
		}
	}
}

std::vector<scan_result> scanner::aob_scan(const process& proc, const std::string_view aob, const std::string_view mask, const scan_cfg& config)
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
				std::vector<HMODULE> module_list(512);
				DWORD n_modules{ 0 };
				std::string module_name(260, '\x0');

				if (K32EnumProcessModulesEx(proc.curr_proc, module_list.data(), static_cast<std::uint32_t>(module_list.capacity()) * sizeof(HMODULE), &n_modules, LIST_MODULES_ALL))
				{
					module_list.resize(n_modules / sizeof(HMODULE));
					for (const auto& j : module_list)
					{
						if (K32GetModuleBaseNameA(proc.curr_proc, j, module_name.data(), 260))
						{
							std::erase_if(module_name, [](const char c)
							{
								return !c;
							});

							if (module_name == config.module_scanned)
								return j;
						}

						module_name.clear();
						module_name.resize(260);
					}
				}
				return reinterpret_cast<HMODULE>(0);
			}();
		}

		MODULEINFO mod_info;
		if (K32GetModuleInformation(proc.curr_proc, mod_found, &mod_info, sizeof(mod_info)))
		{
			return reinterpret_cast<std::uintptr_t>(mod_info.lpBaseOfDll);
		}

		return static_cast<std::uintptr_t>(0);
	}();

	if (!mod_found)
		return ret;

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
