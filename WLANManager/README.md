#WLANManager
Invokes standard Windows Wireless Network Properties dialog

##Usage
```
WLANManager profile <name>
```

- `name` - The name of the network profile (not neccessarely the same as SSID)

Return codes:
- -1 = Invalid parameters
- 0  = Success
- 1  = Error parsing command line
- 2  = WLAN handle could not be opened
- 3  = WLAN provider negotiated unsupported version
- 4  = Interface enumeration failed
- 5  = Edit profile UI failed
