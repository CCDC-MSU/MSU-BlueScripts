# AGENTS

Scope
- This file documents the Fabric entrypoint and task flow in `fabfile.py`, with line references.
- It does not document individual hardening modules; those live under `utilities/modules/`.

Key relationships
- `fabfile.py` is the CLI entrypoint and wires tasks to `utilities` components (`SystemDiscovery`, `HardeningDeployer`, host parsing, logging setup) at `fabfile.py:25-28`.
- Configuration is loaded once at startup via `load_config()` (`fabfile.py:42-47`) and reused by tasks.

Logging and parallel behavior
- Parallel tasks reconfigure logging to keep stdout minimal and send per-host logs to disk via `_configure_parallel_logging` and `_host_log_handler` (`fabfile.py:71-112`).
- Host log labels are normalized by `_host_label` for filesystem-safe paths (`fabfile.py:87-91`).
- Per-host log files are created under `logs/{task}/{host}/{timestamp}.log` by `_host_log_handler` (`fabfile.py:94-111`).
- `run_script` uses a separate output layout under `script_outputs/<script_name>/<host>_<timestamp>.log` (`fabfile.py:518-535`).

Main tasks (user-facing)
- `discover` runs single-host discovery and writes `discovery_<host>.json` summaries (`fabfile.py:114-159`).
- `discover-all` runs discovery on every host in `hosts.txt` in parallel, writes per-host logs under `logs/discover-all/...`, and returns `ServerInfo` objects (`fabfile.py:162-298`).
- `harden` runs discovery + hardening per host in parallel, writes per-host logs under `logs/harden/...`, and summarizes success/failure (`fabfile.py:301-465`).
- `deploy-scripts` is a convenience wrapper that limits `harden` to the `bash_scripts` module (`fabfile.py:468-485`).
- `run-script` uploads a local script, runs it via the requested shell, and writes per-host stdout/stderr logs under `script_outputs/<script_name>/` (`fabfile.py:488-677`).
- `test-connection` validates SSH connectivity and reports a simple echo response (`fabfile.py:716-737`).
- `test-module` runs a single hardening module against all hosts in parallel, with per-host logs under `logs/test-module/...` (`fabfile.py:739-812`).
- `list-modules` prints the available hardening module names (`fabfile.py:815-825`).
- `test-all-modules` runs every module sequentially against a selected host index (`fabfile.py:827-864`).

Task inputs and data flow
- `hosts.txt` parsing is handled by `parse_hosts_file` from `utilities.utils` and drives `ServerCredentials` creation (`fabfile.py:180-181`, `fabfile.py:323-325`, `fabfile.py:508-510`, `fabfile.py:752-754`).
- `discover-all` and `harden` both instantiate `SystemDiscovery` for each host (`fabfile.py:227-228`, `fabfile.py:385-386`).
- `discover-all` and `harden` stash the discovery instance on `ServerInfo` for OS family lookups (`fabfile.py:231`, `fabfile.py:387`).
- `harden` uses `HardeningDeployer` to execute the module pipeline for a host (`fabfile.py:397-404`).
