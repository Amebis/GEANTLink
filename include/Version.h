/*
    Copyright 2015-2016 Amebis
    Copyright 2016 GÉANT

    This file is part of GÉANTLink.

    GÉANTLink is free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    GÉANTLink is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with GÉANTLink. If not, see <http://www.gnu.org/licenses/>.
*/

/*
    NOTE: This file should not be UTF-16 encoded, as the build process
    uses grep.exe to extract version numbers.
*/

#pragma once

//
// Product version as a single DWORD
// Note: Used for version comparison within C/C++ code.
//
#define PRODUCT_VERSION          0x01020000

//
// Product version by components
// Note: Resource Compiler has limited preprocessing capability,
// thus we need to specify major, minor and other version components
// separately.
//
#define PRODUCT_VERSION_MAJ      1
#define PRODUCT_VERSION_MIN      2
#define PRODUCT_VERSION_REV      0
#define PRODUCT_VERSION_BUILD    0

//
// Human readable product version and build year for UI
//
#define PRODUCT_VERSION_STR      "1.2-alpha"
#define PRODUCT_BUILD_YEAR_STR   "2016"

//
// Numerical version presentation for ProductVersion propery in
// MSI packages (syntax: N.N[.N[.N]])
//
#define PRODUCT_VERSION_INST     "1.2.0"

//
// The product code for ProductCode property in MSI packages
// Replace with new on every version change, regardless how minor it is.
//
#define PRODUCT_VERSION_GUID     "{0B45DE8B-B7CB-4A77-985A-F302E1BB8BA0}"

//
// Product vendor
//
#define VENDOR_NAME_STR          "GÉANT"

//
// Since the product name is not finally confirmed at the time of
// developing it, make it easily customizable.
//
#define PRODUCT_NAME_STR         "GÉANTLink"
