
**Title:** How to Set Up and Customize Nmap on Linux

---

**Introduction**

Nmap (Network Mapper) is a powerful open-source tool for network exploration and security auditing. This guide walks you through installing Nmap on Linux, using its core functionalities, and creating custom scripts with the Nmap Scripting Engine (NSE) to extend its capabilities.

---

### **1. Installing Nmap on Linux**

Before diving into advanced usage, we need to ensure Nmap is properly installed.

#### **Step 1: Update Your System**
Run the following commands to update your Linux distribution:

bash
sudo apt update && sudo apt upgrade -y


#### **Step 2: Install Nmap**
Install Nmap using the package manager for your distribution:

For Debian/Ubuntu-based systems:
bash
sudo apt install nmap -y


For CentOS/Red Hat-based systems:
bash
sudo yum install nmap -y


For Arch-based systems:
bash
sudo pacman -S nmap


#### **Step 3: Verify Installation**
After installation, verify the version:
bash
nmap --version

You should see output like:
Nmap version 7.x (https://nmap.org)


---

### **2. Basic Nmap Usage**

Here are some commonly used Nmap commands to get started:

#### **Scan a Single Host**
bash
nmap 192.168.1.1


#### **Scan a Range of IPs**
bash
nmap 192.168.1.1-100


#### **Scan for Open Ports**
bash
nmap -p 1-65535 192.168.1.1


#### **Detect Operating System and Services**
bash
nmap -O -sV 192.168.1.1


#### **Save Output to a File**
bash
nmap -oN output.txt 192.168.1.1


---

### **3. Writing Custom Scripts with Nmap Scripting Engine (NSE)**

NSE allows you to write scripts in Lua to automate tasks such as vulnerability detection, service discovery, or brute-forcing. Let’s create a custom script step-by-step.

#### **Step 1: Locate the NSE Script Directory**
Nmap scripts are stored in the following directory by default:
bash
/usr/share/nmap/scripts/


#### **Step 2: Create a New Script**
Navigate to the scripts directory and create a new script:
bash
cd /usr/share/nmap/scripts/
sudo nano my_custom_script.nse


#### **Step 3: Write the Script**
Here’s a simple example script to check if a specific port is open:

lua
-- my_custom_script.nse

local nmap = require "nmap"
local shortport = require "shortport"

-- Define the script description
description = [[
This script checks if port 8080 is open on the target host.
]]

author = "YourName"

-- Define the script action
portrule = shortport.port_or_service(8080, "http")

action = function(host, port)
    return "Port 8080 is open!"
end


#### **Step 4: Test the Script**
Run your script with Nmap:
bash
sudo nmap --script my_custom_script.nse 192.168.1.1

If the target’s port 8080 is open, you’ll see the custom message.

---

### **4. Integrating Nmap with Python**

If you want to automate Nmap scans programmatically, Python is a great choice. We’ll use the python-nmap library.

#### **Step 1: Install python-nmap**
Install the library with pip:
bash
pip install python-nmap


#### **Step 2: Write a Python Script**
Here’s an example Python script to scan a network and display open ports:

python
import nmap

def scan_network(target):
    scanner = nmap.PortScanner()
    print(f"Scanning {target}...")
    scanner.scan(target, '1-1024', '-sV')

    for host in scanner.all_hosts():
        print(f"\nHost: {host} ({scanner[host].hostname()})")
        print(f"State: {scanner[host].state()}")

        for protocol in scanner[host].all_protocols():
            print(f"\nProtocol: {protocol}")
            ports = scanner[host][protocol].keys()
            for port in sorted(ports):
                print(f"Port: {port}\tState: {scanner[host][protocol][port]['state']}")

# Example usage
scan_network('192.168.1.0/24')


Save this script as nmap_scan.py and run it:
bash
python nmap_scan.py


---

### **5. Best Practices and Precautions**

- **Use Responsibly:** Ensure you have permission to scan a network or host before running Nmap.
- **Stay Updated:** Regularly update Nmap to the latest version to get new features and bug fixes.
- **Script Validation:** Test custom scripts in a controlled environment before deploying them.

---

**Conclusion**

Nmap is an incredibly versatile tool for network exploration and security auditing. By understanding its basics and leveraging features like NSE and Python integration, you can customize it to suit your specific needs. Experiment with writing your own scripts and automate repetitive tasks to enhance your productivity.
