#!/bin/sh
# Secure php.ini files (POSIX sh, safe for spaces)

sudo find / -type f -name 'php.ini' 2>/dev/null -exec sh -c '
  for ini do
    echo "[+] Writing php.ini options to $ini..."

    {
      echo "disable_functions = shell_exec, exec, passthru, proc_open, popen, system, phpinfo"
      echo "max_execution_time = 3"
      echo "register_globals = off"
      echo "magic_quotes_gpc = on"
      echo "allow_url_fopen = off"
      echo "allow_url_include = off"
      echo "display_errors = off"
      echo "short_open_tag = off"
      echo "session.cookie_httponly = 1"
      echo "session.use_only_cookies = 1"
      echo "session.cookie_secure = 1"
    } >> "$ini"
  done
' sh {} +
