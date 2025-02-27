# WiFighter
Easy-to-use python WiFi pen-testing tool for OpenSUSE.
Utilizes aircrack-ng, hcxtools, hashcat and it's own mechanisms for wifi network scanning and executing common wifi attacks.

--------------------------------------------------------------------

## Installation 

Clone the project
```sh
git clone https://github.com/FilipStruhar/WiFighter.git
```

Enter the project folder
```sh
cd WiFighter
```

Make the install script executable
```sh
sudo chmod +x install.sh
```

Run install script
```sh
sudo ./install.sh
```

Run the tool
```sh
sudo wifighter
```

Show help
```sh
sudo wifighter -h
```

--------------------------------------------------------------------

## !! IMPORTANT !! - Read before use
- **Evil Twin Attack - disconnect all other internet connected interfaces than the one selected as "Internet interface"**

## Future visions
- Choose more wordlists at once for cracking
- Cracking with hashcat GPU
- Generating wordlists
- More info in reports
- More linux platforms supported

--------------------------------------------------------------------