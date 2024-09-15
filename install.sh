#!/bin/bash

# RUN IT WITH ROOT ONLY !!FIX!!
# IF EXISTS WHEN CREATING LINK TO BIN !!FIX!!

# Dependencies array
dependencies=('aircrack-ng' 'crunch')

THIS_FILE_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"


# Install dependencies
echo "Installing dependencies..."

#sudo apt update
# Loop through each dependency
for package in "${dependencies[@]}"; do
    # Check if the package is already installed
    if ! dpkg -l | grep -q "^ii  $package "; then
        echo "Installing $package..."
        sudo apt install -y "$package"
    else
        echo "$package is already installed."
    fi
done


# Make Python tool script executable
chmod +x wifighter.py

# Make link to /usr/bin
echo "Installing WiFighter tool to /usr/local/bin..."
sudo ln -s ${THIS_FILE_DIR}/wifighter.py /usr/local/bin/wifighter

# Verify installation
if [ -x "/usr/local/bin/wifighter" ]; then
    echo "Installation complete. You can verify it by executing 'wifighter'"
    exit 0
else
    echo "Installation failed..."
    exit 1
fi
