#MsiUseFeature
Checks the installation state of the given feature of GÉANTLink product

##Usage
```
MsiUseFeature <feature name>
```

- `feature name` - The name of the feature to check (i.e. "featEAPTTLS"; see Feature table of product MSI file)

Note: The MSI product code changes on every release. Therefore, `MsiUseFeature` utility with identical version should be used.

Return codes:
- -1 = Invalid parameters
- 0  = Success
- 1  = The product is not installed or feature state is unknown
- 2  = The feature is not installed locally
