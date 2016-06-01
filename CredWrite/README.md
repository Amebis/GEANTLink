#CredWrite
Imports given credentials to Windows Credential Manager for GEANTLink use

##Usage
```
CredWrite <username> <password> [<realm>]
```

- `username` - Base64 encoded UTF-8 user name (usually of the form user@domain or domain\user)
- `password` - Base64 encoded UTF-8 user password
- `realm`    - A realm ID to allow grouping of credentials over different WLAN profiles (optional, default is domain part of `username`)

The credentials are stored to Windows Credential Manager in invoking user's roaming profile.

Return codes:
- -1 = Invalid parameters
- 0  = Success
- 1  = Error parsing command line
- 2  = Error encrypting password
- 3  = Error writing credentials to Credential Manager
