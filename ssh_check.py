import subprocess

def check_ssh_status_mac():
    try:
        result = subprocess.run(
            ["systemsetup", "-getremotelogin"],
            capture_output=True,
            text=True
        )

        output = result.stdout.strip()

        if "On" in output:
            return "SSH Service: ENABLED (Remote Login ON)"
        else:
            return "SSH Service: DISABLED (Remote Login OFF)"

    except Exception as e:
        return f"Error checking SSH: {e}"


if __name__ == "__main__":
    print(check_ssh_status_mac())
