# CredWrite

Imports given credentials to Windows Credential Manager for GÉANTLink use

## Usage

```
CredWrite <username> <password> [<realm> [level]]
```

- `username` - Base64 encoded UTF-8 user name (usually of the form user@domain or domain\user)
- `password` - Base64 encoded UTF-8 user password
- `realm`    - A realm ID to allow grouping of credentials over different WLAN profiles (optional, default is domain part of `username`)
- `level`    - Credential level (0=outer, 1=inner, 2=inner-inner..., default is 0=outer)

The credentials are stored to Windows Credential Manager in invoking user's roaming profile.

### Return codes

- -1 = Invalid parameters
- 0  = Success
- 1  = Error parsing command line
- 2  = Error encrypting password or writing credentials

### Example

```
CredWrite dXNlckBjb250b3NvLmNvbQ== cGFzc3dvcmQxMjM= urn:RFC4282:realm:contoso.com 1
```
