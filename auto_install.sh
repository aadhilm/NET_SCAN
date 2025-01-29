#!/bin/bash

# Function for Debian/Ubuntu
install_python_debian() {
    echo "Installing Python3 and related packages for Debian/Ubuntu..."
    sudo apt update
    sudo apt upgrade -y
    sudo apt install -y python3-pip sqlitebrowser

    pip3 install pyparsing
    pip3 install six
    pip install scapy networkx matplotlib psutil

    # Final message
    echo
    echo -e "\033[1mInstallation complete for Debian/Ubuntu. Now run your Python scripts...!!!"
}

# Function for Arch Linux
install_python_arch() {
    echo "Installing Python3 and related packages for Arch Linux..."
    sudo pacman -Syu --noconfirm
    sudo pacman -S --noconfirm python-pip sqlitebrowser

    pip3 install pyparsing
    pip3 install six
    pip install scapy networkx matplotlib psutil

    # Final message
    echo
    echo -e "\033[1mInstallation complete for Arch Linux. Now run your Python scripts...!!!"
}

# Function for Fedora
install_python_fedora() {
    echo "Installing Python3 and related packages for Fedora..."
    sudo dnf update -y
    sudo dnf install -y python3-pip sqlitebrowser

    pip3 install pyparsing
    pip3 install six
    pip install scapy networkx matplotlib psutil

    # Final message
    echo
    echo -e "\033[1mInstallation complete for Fedora. Now run your Python scripts...!!!"
}

# Check the operating system
if [[ -f /etc/debian_version ]]; then
    install_python_debian
elif [[ -f /etc/arch-release ]]; then
    install_python_arch
elif [[ -f /etc/fedora-release ]]; then
    install_python_fedora
else
    echo "Unsupported Linux distribution."
    exit 1
fi
