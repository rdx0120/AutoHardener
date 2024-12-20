import os
import subprocess
import csv
import psutil
import re

APACHE_CONF_PATH = [
    "/etc/apache2/apache2.conf", "/etc/apache2/mods-enabled/ssl.conf", "/etc/apache2/sites-enabled/default-ssl.conf"]
UBUNTU_SSHD_CONF_PATH = "/etc/ssh/sshd_config"
RESULTS_FILE = "compliance_results.csv"

APACHE_RULES = {
    "ServerTokens": "Prod",              # Prevents the server from disclosing version information
    "ServerSignature": "Off",            # Disables server signature in error pages
    "TraceEnable": "Off",                # Disables HTTP TRACE requests
    "Options": "-Indexes",               # Prevents directory listing
    "SSLProtocol": "all -SSLv2 -SSLv3",  # Disables outdated SSL protocols
    "SSLCipherSuite": "HIGH:!aNULL:!MD5" # Enforces strong SSL/TLS cipher suites
}

UBUNTU_RULES = {
    "PermitRootLogin": "no",             # Prevents root login over SSH
    "PasswordAuthentication": "yes",    # Ensures password-based login is allowed
    "MaxAuthTries": "4",                 # Limits the number of authentication attempts
    "IgnoreRhosts": "yes",               # Disables .rhosts files
    "Protocol": "2",                     # Ensures SSH uses protocol version 2
    "LogLevel": "INFO"                   # Sets appropriate logging level for SSHD
}

def check_running_services():
    services = []
    for proc in psutil.process_iter(attrs=["pid", "name"]):
        try:
            services.append(proc.info["name"])
        except psutil.NoSuchProcess:
            pass
    return services

def check_apache_compliance():
    results = []
    found_keys = set() 

    for conf_path in APACHE_CONF_PATH:
        if os.path.exists(conf_path):
            with open(conf_path, "r") as conf_file:
                config_lines = conf_file.readlines()

                for key, expected_value in APACHE_RULES.items():
                    if key in found_keys: 
                        continue

                    found = False
                    for line in config_lines:
                        match = re.search(rf"{key}\s+(.+)", line, re.IGNORECASE)
                        if match:
                            actual_value = match.group(1).strip()

                            if key == "Options" and "-Indexes" in actual_value:
                                results.append([f"Apache: {key}", "Compliant", f"Value: {actual_value}"])
                            elif actual_value.lower() == expected_value.lower():
                                results.append([f"Apache: {key}", "Compliant", f"Value: {actual_value}"])
                            else:
                                results.append([f"Apache: {key}", "Non-Compliant", f"Expected: {expected_value}, Found: {actual_value}"])
                            
                            found = True
                            found_keys.add(key)
                            break

                    if not found and key not in found_keys:
                        results.append([f"Apache: {key}", "Non-Compliant", "Key not found in configuration files"])

        else:
            results.append([f"Apache Config {conf_path}", "Non-Compliant", "Configuration file not found"])

    return results

def check_ubuntu_compliance():
    results = []
    if os.path.exists(UBUNTU_SSHD_CONF_PATH):
        with open(UBUNTU_SSHD_CONF_PATH, "r") as conf_file:
            config_lines = conf_file.readlines()
            for key, expected_value in UBUNTU_RULES.items():
                found = False
                for line in config_lines:
                    if key.lower() in line.lower():
                        actual_value = line.split()[1] if len(line.split()) > 1 else None
                        if actual_value.lower() == expected_value.lower():
                            results.append([f"Ubuntu: {key}", "Compliant", f"Value: {actual_value}"])
                        else:
                            results.append([f"Ubuntu: {key}", "Non-Compliant", f"Expected: {expected_value}, Found: {actual_value}"])
                        found = True
                        break
                if not found:
                    results.append([f"Ubuntu: {key}", "Non-Compliant", "Key not found in configuration file"])
    else:
        results.append(["Ubuntu SSHD Config", "Non-Compliant", "Configuration file not found"])
    return results

def write_results_to_csv(results):
    with open(RESULTS_FILE, mode="w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["Configuration", "Status", "Details"])
        writer.writerows(results)

def main():
    print("Starting automated hardening configuration review...")

    print("Identifying running services...")
    running_services = check_running_services()
    print(f"Running services: {', '.join(running_services)}")

    print("Checking Apache compliance...")
    apache_results = check_apache_compliance()

    print("Checking Ubuntu compliance...")
    ubuntu_results = check_ubuntu_compliance()

    combined_results = apache_results + ubuntu_results

    print("Writing results to CSV file...")
    write_results_to_csv(combined_results)
    print(f"Compliance check completed. Results saved to {RESULTS_FILE}")

if __name__ == "__main__":
    main()
