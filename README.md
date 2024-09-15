# WiFighter
Easy-to-use WiFI pen-testing tool build on aircrack-ng library written in python and bash

## 1. Aircrack guide

### Monitor mode

Set interface to monitor
```
airmon-ng start <INTERFACE>
```

Set interface to managed
```
airmon-ng stop <INTERFACE>mon
```

### Scan nearby WiFi's

Scan all
```
airodump-ng <INTERFACE>mon
```

Scan by ESSID
```
airodump-ng --essid <ESSID> <INTERFACE>
```
