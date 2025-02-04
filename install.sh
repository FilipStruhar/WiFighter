#!/bin/bash
echo "$HOME"
# Check if the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run this script again as root!"
    exit 1
fi

dependencies=('btop' 'cowsay')

THIS_FILE_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# Install dependencies function
echo -e "\n| DEPENDENCY CHECK |"

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
        echo -e "\n| DEPENDENCIES INSTALL |"
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
