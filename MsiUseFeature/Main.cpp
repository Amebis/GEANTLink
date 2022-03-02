/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2022 Amebis
    Copyright © 2016 GÉANT
*/

#include "PCH.h"

#pragma comment(lib, "Msi.lib")

using namespace std;
using namespace winstd;


static int MsiUseFeature()
{
    int nArgs;
    unique_ptr<LPWSTR[], LocalFree_delete<LPWSTR[]> > pwcArglist(CommandLineToArgvW(GetCommandLineW(), &nArgs));
    if (pwcArglist == NULL) {
        OutputDebugStr(_T("CommandLineToArgvW failed (error %u).\n"), GetLastError());
        return 1;
    }

    if (nArgs < 2) {
        OutputDebugStr(_T("Not enough parameters.\n"));
        return -1;
    }

    // Query the feature state.
    if (MsiQueryFeatureStateW(_L(PRODUCT_VERSION_GUID), pwcArglist[1]) == INSTALLSTATE_UNKNOWN) {
        OutputDebugStr(_T("The product is not installed or feature state is unknown.\n"));
        return 1;
    }

    // Perform the Microsoft Installer's feature completeness check.
    if (MsiUseFeatureW(_L(PRODUCT_VERSION_GUID), pwcArglist[1]) != INSTALLSTATE_LOCAL) {
        OutputDebugStr(_T("The feature is not installed locally.\n"));
        return 2;
    }

    if (nArgs > 2) {
        reg_key key;
        LSTATUS s = RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\") _T(VENDOR_NAME_STR) _T("\\") _T(PRODUCT_NAME_STR), 0, KEY_READ, key);
        if (s != ERROR_SUCCESS) {
            OutputDebugStr(_T("Product registry key cannot be opened (error %u).\n"), s);
            return 3;
        }

        wstring lang;
        s = RegQueryStringValue(key, _T("Language"), lang);
        if (s != ERROR_SUCCESS) {
            OutputDebugStr(_T("Error reading registry value (error %u).\n"), s);
            return 3;
        }

        if (_wcsicmp(pwcArglist[2], lang.c_str()) != 0) {
            OutputDebugStr(_T("Different language (%ls, %ls).\n"), pwcArglist[2], lang.c_str());
            return 3;
        }
    }

    return 0;
}


_Use_decl_annotations_
int CALLBACK WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    _CrtSetDbgFlag(_crtDbgFlag | _CRTDBG_ALLOC_MEM_DF | _CRTDBG_CHECK_ALWAYS_DF | _CRTDBG_CHECK_CRT_DF | _CRTDBG_LEAK_CHECK_DF);

    int res = MsiUseFeature();
    return res;
}
