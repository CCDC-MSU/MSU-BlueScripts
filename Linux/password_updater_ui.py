import paramiko
import os
import shutil

# Constants
current_directory = os.getcwd()
HOSTS_FILE = "hosts.txt"
LOCAL_SCRIPT = "update_passwords.sh"
LOCAL_PASS_FILE = os.path.join(current_directory, "passwords.comf")
REMOTE_DIR = "/tmp"  # Where files will be uploaded on remote hosts

# Load hosts
HOSTS = []
try:
    with open(HOSTS_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 3:
                print(f"[!] Invalid line in hosts.txt: {line}")
                continue
            ip, username, password = parts
            HOSTS.append({"ip": ip, "username": username, "password": password})
except FileNotFoundError:
    print(f"[!] {HOSTS_FILE} not found.")
    exit(1)

def upload_file(ip, username, password, local_path, remote_path):
    print(f"[{ip}] Uploading {os.path.basename(local_path)} -> {remote_path} ...")
    client = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=ip,
            username=username,
            password=password,
            timeout=10,
            allow_agent=False,
            look_for_keys=False,
        )
        sftp = client.open_sftp()
        sftp.put(local_path, remote_path)
        try:
            sftp.chmod(remote_path, 0o755)
        except Exception:
            pass
        sftp.close()
        client.close()
        print(f"[{ip}] Uploaded {os.path.basename(local_path)} successfully.")
        return True
    except Exception as e:
        print(f"[{ip}] Failed to upload {local_path}: {e}")
        return False
    finally:
        if client:
            client.close()

def run_remote_command(ip, username, password, command):
    print(f"[{ip}] Executing: {command}")
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password, timeout=10,
                       allow_agent=False, look_for_keys=False)

        stdin, stdout, stderr = client.exec_command(command)
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        exit_code = stdout.channel.recv_exit_status()
        client.close()

        return out, err, exit_code
    except Exception as e:
        return "", str(e), -1

def update_hosts_file(ip, username, new_password):
    lines = []
    with open(HOSTS_FILE, "r") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) == 3 and parts[0] == ip and parts[1] == username:
                line = f"{ip} {username} {new_password}\n"
            lines.append(line)
    with open(HOSTS_FILE, "w") as f:
        f.writelines(lines)
    print(f"[{ip}] Updated hosts.txt line to: {ip} {username} {new_password}")

def main():
    print(f"Starting remote password update for {len(HOSTS)} host(s)...\n")

    for i, host in enumerate(HOSTS, 1):
        ip = host["ip"]
        username = host["username"]
        password = host["password"]

        print(f"[{i}] Processing host {ip} ({username}) - (old password hidden)")

        remote_script_path = os.path.join(REMOTE_DIR, "update_passwords.sh")
        remote_pass_path = os.path.join(REMOTE_DIR, "passwords.conf")

        if not upload_file(ip, username, password, LOCAL_SCRIPT, remote_script_path):
            continue
        if not upload_file(ip, username, password, LOCAL_PASS_FILE, remote_pass_path):
            continue

        # Always update "user"
        command = f"cd {REMOTE_DIR} && ./update_passwords.sh user"
        out, err, code = run_remote_command(ip, username, password, command)

        print(f"[{ip}] Command execution completed.")
        if out:
            print(f"[{ip}] OUTPUT:\n{out}")
        if err:
            print(f"[{ip}] ERROR:\n{err}")
        print(f"[{ip}] Exit status: {code}")

        # Pull back updated passwords.conf
        pulled_file = f"{LOCAL_PASS_FILE}.{ip}.pulled"
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, username=username, password=password,
                           timeout=10, allow_agent=False, look_for_keys=False)
            sftp = client.open_sftp()
            sftp.get(remote_pass_path, pulled_file)
            sftp.close()
            client.close()
            print(f"[{ip}] Pulled {remote_pass_path} successfully.")

            # Replace local copy
            shutil.copy(pulled_file, LOCAL_PASS_FILE)
            print(f"[{ip}] Replaced local {LOCAL_PASS_FILE} with pulled copy.")
        except Exception as e:
            print(f"[{ip}] Failed to pull {remote_pass_path}: {e}")

        # Extract "new" password from pulled config
        new_password = None
        in_section = False
        with open(LOCAL_PASS_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if line.lower() == "[user]":
                    in_section = True
                    continue
                if in_section:
                    if line.startswith("["):
                        break
                    if line.lower().startswith("new="):
                        new_password = line.split("=", 1)[1].strip()
                        break

        if new_password:
            update_hosts_file(ip, username, new_password)
        else:
            print(f"[{ip}] No new password found in pulled passwords.conf")

        print(f"[{ip}] Host processing done.")
        print("--------------------------------------------------\n")

    print("All hosts processed.")

if __name__ == "__main__":
    main()
