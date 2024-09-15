# WiFighter
Easy-to-use WiFI pen-testing tool build on aircrack-ng library written in python and bash

## 1. Aircrack guide

### Monitor mode

Set interface to monitor
```c
airmon-ng start <INTERFACE>
```

Set interface to managed
```c
airmon-ng stop <INTERFACE>mon
```

### Scan nearby WiFi's

Scan all
```c
airodump-ng <INTERFACE>mon
```

Scan by ESSID
```c
airodump-ng --essid <ESSID> <INTERFACE>
```
