/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2022 Amebis
    Copyright © 2016 GÉANT
*/

/*
    NOTE: This file should not be UTF-16 encoded, as the build process
    uses grep.exe to extract version numbers.

    NOTE: When any of the strings contain non-ASCII characters, this
    file should be UTF-8 encoded with BOM. Without BOM, MSVC will read
    this file using the "Language for non-Unicode programs" charset
    (aka ANSI CP).
*/

#pragma once

//
// Product version by components
// Note: Resource Compiler has limited preprocessing capability,
// thus we need to specify major, minor and other version components
// separately.
//
#define PRODUCT_VERSION_MAJ      1
#define PRODUCT_VERSION_MIN      3
#define PRODUCT_VERSION_REV      7
#define PRODUCT_VERSION_BUILD    0

//
// Human readable product version and build year for UI
//
#define PRODUCT_VERSION_STR      "1.3g"
#define PRODUCT_BUILD_YEAR_STR   "2022"

//
// Numerical version presentation for ProductVersion propery in
// MSI packages (syntax: N.N[.N[.N]])
//
#define PRODUCT_VERSION_INST     "1.3.7"

//
// The product code for ProductCode property in MSI packages
// Replace with new on every version change, regardless how minor it is.
//
#define PRODUCT_VERSION_GUID     "{5CA2AF38-39E1-4C2B-BA76-C8C7D021EF8F}"

//
// Product vendor
//
#define VENDOR_NAME_STR          "GÉANT"

//
// Since the product name is not finally confirmed at the time of
// developing it, make it easily customizable.
//
#define PRODUCT_NAME_STR         "GÉANTLink"

//
// EAPHost author ID
//
#define EAPMETHOD_AUTHOR_ID        67532
