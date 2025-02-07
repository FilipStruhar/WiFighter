#!/bin/bash

# Check if the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run this script again as root!"
    exit 1
fi

#---------------------------------------------------------------------------------
# git python3 awk sed
dependencies=('awk' 'sed' 'iputils' 'iproute2' 'iw' 'git' 'python3' 'aircrack-ng' 'hashcat' 'pocl' 'hostapd' 'dhcp-server' 'iptables')

THIS_FILE_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

echo -e "\n| PACKAGE DEPENDENCY CHECK |"

# Prepare an array to store packages that need to be installed
to_install=()

# Check each package and determine if it is already installed
for package in "${dependencies[@]}"; do
    echo "[>] Looking for \"$package\" package"
    if ! zypper search --installed-only "$package" &>/dev/null; then
        to_install+=("$package")
    fi
done

# If there are missing packages, prompt the user to install them
if [ ${#to_install[@]} -gt 0 ]; then
    echo -e "\nThe following packages are missing and need to be installed:"
    for pkg in "${to_install[@]}"; do
        echo "[>] $pkg"
    done
    echo ""
    # Ask the user if they want to install the missing dependencies
    read -p "Do you wish to install these packages with \"zypper in -y\"? (y/n): " choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
        echo -e "\n| PACKAGE DEPENDENCY INSTALL |"
        # Loop through and install missing packages
        for package in "${to_install[@]}"; do
            zypper install -y "$package" &>/dev/null
            if zypper search --installed-only "$package" &>/dev/null; then
                echo "[>] Package \"$package\" installed successfully"
            else
                echo "ERROR Installing package \"$package\" failed!"
            fi
        done
    else
        echo "Installation aborted!"
        exit 1
    fi
else
    echo -e "\n[>] All required packages are already installed..."
fi

#---------------------------------------------------------------------------------

github_dependencies=('hcxpcapngtool' 'hcxdumptool')

echo -e "\n| HCXTOOLS DEPENDENCY CHECK |"

to_install=()

# Prepare an array to store hcxtools that need to be installed
for tool in "${github_dependencies[@]}"; do
    echo "[>] Looking for \"$tool\" tool"
    if ! "$tool" --version &>/dev/null; then
            to_install+=("$tool")
    elif [ "$tool" == 'hcxdumptool' ]; then
        installed_version=$(hcxdumptool --version | awk '{print $2}')
        if [[ ! "$installed_version" == "6.2.6" ]]; then
            echo "[>] Tool \"hcxdumptool\" needs version 6.2.6. - will be treated as not installed!"
            to_install+=("$tool")
        fi
    fi
done

# If there are missing hcxtools, prompt the user to install them
if [ ${#to_install[@]} -gt 0 ]; then
    echo -e "\nThe following hcxtools are missing and need to be installed along with it's dependencies:"
    for pkg in "${to_install[@]}"; do
        echo "[>] $pkg"
    done
    echo ""
    echo -e "[>] Dependencies -> gcc libopenssl3 libopenssl-devel libz1 zlib-ng-compat-devel libcurl4 libcurl-devel libpcap1 libpcap-devel pkgconf-pkg-config\n"
    # Ask the user if they want to install the missing dependencies
    read -p "Do you wish to install (github clone & compile) these hcxtools with all it's dependencies? (y/n): " choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
        echo -e "\n| PACKAGE DEPENDENCY INSTALL |"
        # Loop through and install missing hcxtools
        for package in "${to_install[@]}"; do
            # Install hcxtools dependencies
            zypper in -y gcc libopenssl3 libopenssl-devel libz1 zlib-ng-compat-devel libcurl4 libcurl-devel libpcap1 libpcap-devel pkgconf-pkg-config &>/dev/null
            if [[ "$package" == 'hcxpcapngtool' ]]; then
                echo "Installing tool hcxpcapngtool"
                git clone https://github.com/ZerBea/hcxtools.git &>/dev/null
                cd hcxtools
                # Compile the tool
                make -j $(nproc) &>/dev/null
                make install &>/dev/null
                if hcxpcapngtool --version &>/dev/null; then
                    echo "[>] Package \"hcxpcapngtool\" installed successfully"
                else
                    echo "ERROR Installing package \"hcxpcapngtool\" failed!"
                fi
                cd ..
                rm -r hcxtools
            elif [[ "$package" == 'hcxdumptool' ]]; then
            echo "Installing tool hcxdumptool"
                git clone https://github.com/ZerBea/hcxdumptool.git &>/dev/null
                cd hcxdumptool
                # Compile the tool
                make -j $(nproc) &>/dev/null
                make install &>/dev/null
                if hcxdumptool --version &>/dev/null; then
                    echo "[>] Package \"hcxdumptool\" installed successfully"
                else
                    echo "ERROR Installing package \"hcxdumptool\" failed!"
                fi
                cd ..
                rm -r hcxdumptool
            fi
        done
    else
        echo "ERROR Installation aborted!"
        exit 1
    fi
else
    echo -e "\n[>] All required hcxtools are already installed..."
fi


#---------------------------------------------------------------------------------

echo -e "\n| PYTHON3 & VENV SETUP |"

pwd

if [ ! -d "$THIS_FILE_DIR/venv" ]; then
    python3 -m venv venv  # Create python virtual enviroment
    sleep 3
    echo "[>] Created python virtual enviroment called \"venv\""
fi
if [ -d "$THIS_FILE_DIR/venv" ]; then
    source venv/bin/activate
    pip3 install --upgrade pip
    pip3 install prettytable psutil scapy  # Install needed python modules in virtual enviroment
    deactivate
fi
#---------------------------------------------------------------------------------


echo -e "\n| WIFIGHTER COMMAND INSTALLATION |"

pwd

# Make Python tool script executable
if [ -e "$THIS_FILE_DIR/wifighter.py" ]; then
    chmod +x wifighter.py
else
    echo "ERROR Installation script isn't in the same directory as wifighter.py or wifighter.py doesn't exist!"
    exit 1
fi

if [ -e "$THIS_FILE_DIR/wifighter.py" ] && [ -d "$THIS_FILE_DIR/venv" ]; then
    echo "[>] Setting correct shebang in wifighter.py..."
    sed -i "1s|^#!.*|#!$THIS_FILE_DIR/venv/bin/python3|" wifighter.py
else
    echo "ERROR Installation script isn't in the same directory as wifighter.py/venv or wifighter.py/venv doesn't exist!"
    exit 1
fi

# Make link to /usr/sbin
if [ -d "/usr/sbin" ] && [ ! -e "/usr/sbin/wifighter" ]; then
    ln -s ${THIS_FILE_DIR}/wifighter.py /usr/sbin/wifighter
    echo "[>] Created symlink in /usr/sbin"
fi

# Verify installation
if [ -x "/usr/sbin/wifighter" ]; then
    echo -e "\nInstallation complete. You can verify it by executing 'wifighter -h'"
    exit 0
else
    echo -e "\nERROR Installation failed!"
    exit 1
fi
