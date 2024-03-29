/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2022 Amebis
    Copyright © 2016 GÉANT
*/

#include "PCH.h"

#pragma comment(lib, "Wlanapi.lib")
#pragma comment(lib, "Wlanui.lib")

using namespace std;
using namespace winstd;

DWORD (WINAPI *pfnWlanReasonCodeToString)(__in DWORD dwReasonCode, __in DWORD dwBufferSize, __in_ecount(dwBufferSize) PWCHAR pStringBuffer, __reserved PVOID pReserved);


static int DisplayError(_In_z_ _Printf_format_string_ LPCTSTR format, ...)
{
    va_list arg;
    va_start(arg, format);
    tstring msg;
    vsprintf(msg, format, arg);
    va_end(arg);

    return MessageBox(NULL, msg.c_str(), _T("WLANManager"), MB_OK);
}


static int WLANManager()
{
    int nArgs;
    unique_ptr<LPWSTR[], LocalFree_delete<LPWSTR[]> > pwcArglist(CommandLineToArgvW(GetCommandLineW(), &nArgs));
    if (pwcArglist == NULL) {
        DisplayError(_T("%s function failed (error %u)."), _T("CommandLineToArgvW"), GetLastError());
        return 1;
    }

    if (nArgs < 3) {
        DisplayError(_T("Not enough parameters."));
        return -1;
    }

    if (_wcsicmp(pwcArglist[1], L"profile") != 0) {
        DisplayError(_T("Unknown command (%ls)."), pwcArglist[1]);
        return -1;
    }

    wstring interface_name;
    if (nArgs >= 5 && _wcsicmp(pwcArglist[3], L"interface") == 0)
        interface_name = pwcArglist[4];

    // Open WLAN handle.
    DWORD dwNegotiatedVersion;
    wlan_handle wlan;
    DWORD dwResult = WlanOpenHandle(WLAN_API_MAKE_VERSION(2, 0), NULL, &dwNegotiatedVersion, wlan);
    if (dwResult != ERROR_SUCCESS) {
        DisplayError(_T("%s function failed (error %u)."), _T("WlanOpenHandle"), dwResult);
        return 2;
    } else if (dwNegotiatedVersion < WLAN_API_MAKE_VERSION(2, 0)) {
        DisplayError(_T("WlanOpenHandle negotiated unsupported version (expected: %u, negotiated: %u)."), WLAN_API_MAKE_VERSION(2, 0), dwNegotiatedVersion);
        return 3;
    }

    unique_ptr<WLAN_INTERFACE_INFO_LIST, WlanFreeMemory_delete<WLAN_INTERFACE_INFO_LIST> > interfaces;
    {
        // Get a list of WLAN interfaces.
        WLAN_INTERFACE_INFO_LIST *pInterfaceList;
        dwResult = WlanEnumInterfaces(wlan, NULL, &pInterfaceList);
        if (dwResult != ERROR_SUCCESS) {
            DisplayError(_T("%s function failed (error %u)."), _T("WlanEnumInterfaces"), dwResult);
            return 4;
        }
        interfaces.reset(pInterfaceList);
    }

    tstring_guid devclass_net(GUID_DEVCLASS_NET);
    bool profile_found = false;
    for (DWORD i = 0; i < interfaces->dwNumberOfItems; i++) {
        if (interfaces->InterfaceInfo[i].isState == wlan_interface_state_not_ready) {
            // This interface is not ready.
            continue;
        }

        if (!interface_name.empty()) {
            // Read the interface name from registry.
            reg_key key;
            if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, tstring_printf(_T("SYSTEM\\CurrentControlSet\\Control\\Network\\%s\\%s\\Connection"), devclass_net.c_str(), tstring_guid(interfaces->InterfaceInfo[i].InterfaceGuid).c_str()).c_str(), 0, KEY_READ, key) == ERROR_SUCCESS) {
                wstring name;
                if (RegQueryStringValue(key, _T("Name"), name) == ERROR_SUCCESS && _wcsicmp(interface_name.c_str(), name.c_str()) != 0) {
                    // Not the interface we are interested in.
                    continue;
                }
            }
        }

        unique_ptr<WLAN_PROFILE_INFO_LIST, WlanFreeMemory_delete<WLAN_PROFILE_INFO_LIST> > profiles;
        {
            // Get a list of profiles.
            WLAN_PROFILE_INFO_LIST *pProfileList;
            dwResult = WlanGetProfileList(wlan, &(interfaces->InterfaceInfo[i].InterfaceGuid), NULL, &pProfileList);
            if (dwResult != ERROR_SUCCESS) {
                DisplayError(_T("%s function failed (error %u)."), _T("WlanGetProfileList"), dwResult);
                return 4;
            }
            profiles.reset(pProfileList);
        }

        for (DWORD j = 0; j < profiles->dwNumberOfItems; j++)
            if (_wcsicmp(profiles->ProfileInfo[j].strProfileName, pwcArglist[2]) == 0) {
                profile_found = true;
                break;
            }

        if (!profile_found)
            continue;

        // Launch WLAN profile config dialog.
        WLAN_REASON_CODE wlrc = L2_REASON_CODE_SUCCESS;
        #pragma warning(suppress: 6387) // TODO: MSDN nor SAL annotation don't indicate NULL HWND are OK with WlanUIEditProfile().
        dwResult = WlanUIEditProfile(WLAN_UI_API_VERSION, pwcArglist[2], &(interfaces->InterfaceInfo[i].InterfaceGuid), NULL, WLSecurityPage, NULL, &wlrc);
        if (dwResult != ERROR_SUCCESS) {
            // WlanUIEditProfile() displays own error dialog on failure.
            //DisplayError(_T("%s function failed (error %u)."), _T("WlanUIEditProfile"), dwResult);
            return 5;
        } else if (wlrc != WLAN_REASON_CODE_SUCCESS) {
            tstring reason;
            if (WlanReasonCodeToString(wlrc, reason, NULL) == ERROR_SUCCESS)
                DisplayError(_T("%s function failed: %s"), _T("WlanUIEditProfile"), reason.c_str());
            else
                DisplayError(_T("%s function failed (reason code: %u)."), _T("WlanUIEditProfile"), wlrc);
        }

        break;
    }

    if (!profile_found)
        DisplayError(_T("%ls profile not found."), pwcArglist[2]);

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

    // Note: When a debugger is attached to this process, the WlanUIEditProfile() will raise an exception and fail.
    // It was accidentially discovered, that COM initialization resolves this issue.
    com_initializer com_init(NULL);

    {
        // Initialize Windows XP visual styles
        INITCOMMONCONTROLSEX icc;
        icc.dwSize = sizeof(INITCOMMONCONTROLSEX);
        icc.dwICC = ICC_WIN95_CLASSES | ICC_STANDARD_CLASSES | ICC_LINK_CLASS;
        InitCommonControlsEx(&icc);
    }

    pfnWlanReasonCodeToString = WlanReasonCodeToString;

    return WLANManager();
}
