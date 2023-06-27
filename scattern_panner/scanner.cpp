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
								if (c == 0)
									return true;
								return false;
							});

						if (module_name == process_name.data())
						{
							this->curr_proc = proc_handle;
							this->pid = i;
							return;
						}
					}

					// Horribly inefficient but .clear will nuke everything so what choice do I have.
					module_name = default_mod_name;
				}

				module_list.clear();
				module_list.resize(1024);
			}
		}
	}
}
