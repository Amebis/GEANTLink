#WLANManager
Invokes standard Windows Wireless Network Properties dialog

##Usage
```
WLANManager profile <profile name> [interface <interface name>]
```

- `profile name`   - The name of the network profile (not neccessarely the same as SSID)
- `interface name` - The name of the specific network interface to search the profile at

Return codes:
- -1 = Invalid parameters
- 0  = Success
- 1  = Error parsing command line
- 2  = WLAN handle could not be opened
- 3  = WLAN provider negotiated unsupported version
- 4  = Interface enumeration failed
- 5  = Edit profile UI failed
