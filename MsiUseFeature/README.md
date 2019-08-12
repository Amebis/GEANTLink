# MsiUseFeature

Checks the installation state of the given feature of GÉANTLink product

## Usage

```
MsiUseFeature <feature name> [language]
```

- `feature name` - The name of the feature to check (i.e. "featEAPTTLS"; see Feature table of product MSI file)
- `language`     - The user preferred language of the product

Note: The MSI product code changes on every release. Therefore, `MsiUseFeature` utility with identical version should be used.

### Return codes

- -1 = Invalid parameters
- 0  = Success
- 1  = The product is not installed, or feature state is unknown
- 2  = The feature is not installed locally
- 3  = The installed user preferred language is different
