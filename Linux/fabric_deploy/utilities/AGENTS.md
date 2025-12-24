# AGENTS

Scope
- This file documents the core support modules under `utilities/` (not `utilities/modules/`).
- Focus is on discovery, deployment orchestration, shell-command builders, utilities, and data models.

discovery.py (system inventory and OS detection)
- `OSFamily` enum and `CommandResult` data container are defined at `utilities/discovery.py:20-40`.
- `SystemDiscovery` orchestrates the full discovery pass and owns the per-host `ServerInfo` (`utilities/discovery.py:43-88`).
- The discovery workflow is a fixed task list (including sudoers) and records per-task errors before setting `discovery_successful` (`utilities/discovery.py:57-82`).
- Command execution helpers `_run_command` and `_try_command_chain` handle fabric calls and fallbacks (`utilities/discovery.py:176-229`).
- OS and shell detection logic live in `_discover_basic_info`, `_discover_shell`, `_discover_os_info`, and `_detect_os_fallback` (`utilities/discovery.py:231-349`).
- User, group, service, and network enumeration are in `_discover_users`, `_discover_groups`, `_discover_services`, `_discover_network` (`utilities/discovery.py:351-513`).
- Sudoers discovery collects a sudoers dump, runs `analyze_sudoers`, and stores results on `ServerInfo` (`utilities/discovery.py:603-623`).
- Security tools, available user-management commands, resources, and package managers are gathered in `_discover_security_tools`, `_discover_available_commands`, `_discover_system_resources`, `_discover_package_managers` (`utilities/discovery.py:515-601`).
- `UserManager` is instantiated with available commands, groups, and sudoers data (`utilities/discovery.py:46-51`).

deployment.py (module orchestration)
- `HardeningOrchestrator` builds the ordered module list and filters/apply modules (`utilities/deployment.py:28-89`).
- `get_summary` aggregates per-module results into a readable report (`utilities/deployment.py:91-113`).
- `HardeningDeployer` ties a discovered host to the orchestrator, pulling `os_family` from the discovery object (`utilities/deployment.py:116-158`).

actions.py (shell command builders)
- `UserManager` returns shell snippets for user and group operations; it does not run them directly (`utilities/actions.py:10-390`).
- It selects platform-appropriate commands by checking `available_commands` and uses `sudoers_info.sudoer_group_all` to choose sudo groups (`utilities/actions.py:11-119`).
- When no sudoers groups are discovered, `UserManager` seeds `sudoers_groups` with `blue-sudoers` (`utilities/actions.py:16-20`).
- Key helpers: `add_user` (`utilities/actions.py:31-107`), `add_sudo_user` (`utilities/actions.py:109-195`), `remove_user` (`utilities/actions.py:197-253`), `remove_user_from_sudoers` (`utilities/actions.py:255-311`), `get_users_in_group` (`utilities/actions.py:313-343`), `lock_user` (`utilities/actions.py:345-390`).

models.py (shared data structures)
- `ServerCredentials`, `UserInfo`, `OSInfo`, and `NetworkInfo` define the core discovery data types (`utilities/models.py:7-66`).
- `SudoersInfo` stores sudoers analysis output (`utilities/models.py:69-75`).
- `ServerInfo` aggregates discovery output (including sudoers) and offers convenience properties for counts and subsets (`utilities/models.py:78-161`).
- `ServerInfo.__str__` formats a human-friendly summary for logging/debug, including sudoers detail (`utilities/models.py:165-310`).

utils.py (config, parsing, and analysis helpers)
- `load_config`, `parse_hosts_file`, `save_discovery_summary`, and `setup_logging` live at `utilities/utils.py:17-132`.
- `save_discovery_summary` writes JSON summaries of discovery results (`utilities/utils.py:96-124`).
- `analyze_sudoers` parses a sudoers dump and returns sudo users/groups, NOPASSWD lines, and ALL-capable groups (`utilities/utils.py:134-235`).

Cross-file relationships
- `SystemDiscovery` populates `ServerInfo` objects which are consumed by `HardeningDeployer` and modules (`utilities/discovery.py:43-88`, `utilities/deployment.py:116-158`).
- `SystemDiscovery` uses `UserManager` from `actions.py` to adapt to available system commands and sudoers data (`utilities/discovery.py:46-51`, `utilities/actions.py:11-119`).
- `SystemDiscovery` uses `analyze_sudoers` from `utils.py` to populate `ServerInfo.sudoers_dump` and `ServerInfo.sudoers_info` (`utilities/discovery.py:603-623`, `utilities/utils.py:134-235`).
