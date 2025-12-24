# AGENTS

Scope
- This file documents the core support modules under `utilities/` (not `utilities/modules/`).
- Focus is on discovery, deployment orchestration, shell-command builders, and data models.

discovery.py (system inventory and OS detection)
- `OSFamily` enum and `CommandResult` data container are defined at `utilities/discovery.py:19-39`.
- `SystemDiscovery` orchestrates the full discovery pass and owns the per-host `ServerInfo` (`utilities/discovery.py:42-86`).
- The discovery workflow is a fixed task list and records per-task errors before setting `discovery_successful` (`utilities/discovery.py:56-86`).
- Command execution helpers `_run_command` and `_try_command_chain` handle fabric calls and fallbacks (`utilities/discovery.py:161-214`).
- OS and shell detection logic live in `_discover_shell`, `_discover_os_info`, and `_detect_os_fallback` (`utilities/discovery.py:231-335`).
- User, group, service, and network enumeration are in `_discover_users`, `_discover_groups`, `_discover_services`, `_discover_network` (`utilities/discovery.py:336-498`).
- Security tools, available user-management commands, resources, and package managers are gathered in `_discover_security_tools`, `_discover_available_commands`, `_discover_system_resources`, `_discover_package_managers` (`utilities/discovery.py:500-586`).
- `UserManager` is instantiated with the discovered available commands (`utilities/discovery.py:14-50`).

deployment.py (module orchestration)
- `HardeningOrchestrator` builds the ordered module list and filters/apply modules (`utilities/deployment.py:28-89`).
- `get_summary` aggregates per-module results into a readable report (`utilities/deployment.py:91-113`).
- `HardeningDeployer` ties a discovered host to the orchestrator, pulling `os_family` from the discovery object (`utilities/deployment.py:116-158`).

actions.py (shell command builders)
- `UserManager` returns shell snippets for user and group operations; it does not run them directly (`utilities/actions.py:9-345`).
- It selects platform-appropriate commands by checking `available_commands` (`utilities/actions.py:10-15`).
- Key helpers: `add_user` (`utilities/actions.py:21-97`), `add_sudo_user` (`utilities/actions.py:99-196`), `remove_user` (`utilities/actions.py:198-254`), `remove_user_from_sudoers` (`utilities/actions.py:256-312`), `get_users_in_group` (`utilities/actions.py:314-345`).

models.py (shared data structures)
- `ServerCredentials`, `UserInfo`, `OSInfo`, and `NetworkInfo` define the core discovery data types (`utilities/models.py:7-67`).
- `ServerInfo` aggregates discovery output and offers convenience properties for counts and subsets (`utilities/models.py:69-148`).
- `ServerInfo.__str__` formats a human-friendly summary for logging/debug (`utilities/models.py:151-285`).

Cross-file relationships
- `SystemDiscovery` populates `ServerInfo` objects which are consumed by `HardeningDeployer` and modules (`utilities/discovery.py:42-86`, `utilities/deployment.py:116-158`).
- `SystemDiscovery` uses `UserManager` from `actions.py` to adapt to available system commands (`utilities/discovery.py:14-50`, `utilities/actions.py:9-15`).
