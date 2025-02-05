#!/bin/bash

# Check if the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run this script again as root!"
    exit 1
fi

#---------------------------------------------------------------------------------
# git python3 awk
dependencies=('btop' 'cowsay')

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
            if zypper install -y "$package" &>/dev/null; then
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
            o_install+=("$tool")
        fi
    fi
done

# If there are missing hcxtools, prompt the user to install them
if [ ${#to_install[@]} -gt 0 ]; then
    echo -e "\nThe following hcxtools are missing and need to be installed:"
    for pkg in "${to_install[@]}"; do
        echo "[>] $pkg"
    done
    echo ""
    # Ask the user if they want to install the missing dependencies
    read -p "Do you wish to install (github clone & compile) these hcxtools with all it's dependencies? (y/n): " choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
        echo -e "\n| PACKAGE DEPENDENCY INSTALL |"
        # Loop through and install missing hcxtools
        for package in "${to_install[@]}"; do
            sudo zypper in gcc libopenssl3 libopenssl-devel libz1 libz-devel libcurl4 libcurl-devel pkgconf-pkg-config  # Install hcxtools dependencies
            if [[ "$package" == 'hcxpcapngtool' ]]; then
                echo "Installing tool hcxpcapngtool"
                git clone https://github.com/ZerBea/hcxtools.git  # Pull git repo
                cd hcxtools
                sudo make install  # Compile the tool
            elif [[ "$package" == 'hcxdumptool' ]]; then
                echo "Installing tool hcxdumptool"
                git clone https://github.com/ZerBea/hcxdumptool.git  # Pull git repo # Install version 6.2.6
                cd hcxdumptool
                sudo make install  # Compile the tool
            fi
        done
    else
        echo "Installation aborted!"
        exit 1
    fi
else
    echo -e "\n[>] All required hcxtools are already installed..."
fi


#---------------------------------------------------------------------------------

echo -e "\n| PYTHON3 & VENV SETUP |"

if [ ! -d "venv" ]; then
    python3 -m venv venv  # Create python virtual enviroment
    echo "[>] Created python virtual enviroment called \"venv\""
fi
if [ -d "venv" ]; then
    source venv/bin/activate
    pip3 install prettytable psutil scapy  # Install needed python modules in virtual enviroment
    deactivate
fi
#---------------------------------------------------------------------------------

<<COMMENT
echo -e "\n| WIFIGHTER COMMAND INSTALLATION |"

# Make Python tool script executable
if [ -e "wifighter.py" ]; then
    chmod +x wifighter.py
else
    echo "ERROR Installation script isn't in the same directory as wifighter.py or wifighter doesn't exist!"
    exit 1
fi

# Make link to /usr/local/sbin
if [ -d "/usr/local/sbin" ] && [ ! -e "/usr/local/sbin/wifighter" ]; then
    echo "[>] Created symlink in /usr/local/sbin"
    sudo ln -s ${THIS_FILE_DIR}/wifighter.py /usr/local/sbin/wifighter
fi

# Verify installation
if [ -x "/usr/local/sbin/wifighter" ]; then
    echo -e "\nInstallation complete. You can verify it by executing 'wifighter -h'"
    exit 0
else
    echo -e "\nERROR Installation failed!"
    exit 1
fi
COMMENT