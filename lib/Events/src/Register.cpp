/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2020-2022 Amebis
    Copyright © 2016 GÉANT
*/

#include "PCH.h"

using namespace std;
using namespace winstd;

HINSTANCE g_hInstance;


static void set_value(_In_ HKEY hKey, _In_opt_z_ LPCTSTR lpValueName, _In_ LPCTSTR sValue)
{
    LSTATUS s = RegSetValueEx(hKey, lpValueName, 0, REG_SZ, reinterpret_cast<LPCBYTE>(sValue), (DWORD)((_tcslen(sValue) + 1) * sizeof(tstring::value_type)));
    if (s != ERROR_SUCCESS)
        throw win_runtime_error(s, "RegSetValueEx failed.");
}


static void set_value(_In_ HKEY hKey, _In_opt_z_ LPCTSTR lpValueName, _In_ const tstring &sValue)
{
    LSTATUS s = RegSetValueEx(hKey, lpValueName, 0, REG_SZ, reinterpret_cast<LPCBYTE>(sValue.c_str()), (DWORD)((sValue.length() + 1) * sizeof(tstring::value_type)));
    if (s != ERROR_SUCCESS)
        throw win_runtime_error(s, "RegSetValueEx failed.");
}


static void set_value(_In_ HKEY hKey, _In_opt_z_ LPCTSTR lpValueName, _In_ DWORD dwValue)
{
    LSTATUS s = RegSetValueEx(hKey, lpValueName, 0, REG_DWORD, reinterpret_cast<LPCBYTE>(&dwValue), sizeof(dwValue));
    if (s != ERROR_SUCCESS)
        throw win_runtime_error(s, "RegSetValueEx failed.");
}


BOOL WINAPI DllMain(_In_ HINSTANCE hinstDLL, _In_ DWORD fdwReason, _In_ LPVOID lpvReserved)
{
    UNREFERENCED_PARAMETER(lpvReserved);

    if (fdwReason == DLL_PROCESS_ATTACH) {
#ifdef _DEBUG
        //Sleep(10000);
        _CrtSetDbgFlag(_crtDbgFlag | _CRTDBG_ALLOC_MEM_DF | _CRTDBG_CHECK_ALWAYS_DF | _CRTDBG_CHECK_CRT_DF | _CRTDBG_LEAK_CHECK_DF);
#endif
        g_hInstance = hinstDLL;
    }

    return TRUE;
}


///
/// Registers event source in Windows registry
///
/// \returns S_OK if successful; E_FAIL otherwise
///
STDAPI DllRegisterServer()
{
    try {
        tstring sz, event_provider_name(_T(VENDOR_NAME_STR) _T("-") _T(PRODUCT_NAME_STR) _T("-EAPMethod"));
        tstring_guid event_provider_guid(EAPMETHOD_TRACE_EVENT_PROVIDER);

        // Register event channels.
        reg_key key_channels, key_channels_operational, key_channels_analytic;
        LSTATUS s = RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels"), 0, KEY_CREATE_SUB_KEY, key_channels);
        if (s != ERROR_SUCCESS) throw win_runtime_error(s);
        sprintf(sz, _T("%s/Operational"), event_provider_name.c_str());
        s = RegCreateKeyEx(key_channels, sz.c_str(), NULL, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, key_channels_operational, NULL);
        if (s != ERROR_SUCCESS) throw win_runtime_error(s);
        set_value(key_channels_operational, _T("OwningPublisher")   , event_provider_guid);
        set_value(key_channels_operational, _T("Enabled")           , (DWORD)0);
        set_value(key_channels_operational, _T("Isolation")         , (DWORD)0);
        set_value(key_channels_operational, _T("ChannelAccess")     , _T("O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x7;;;SO)(A;;0x3;;;IU)(A;;0x3;;;SU)(A;;0x3;;;S-1-5-3)(A;;0x3;;;S-1-5-33)(A;;0x1;;;S-1-5-32-573)"));
        set_value(key_channels_operational, _T("MaxSize")           , (DWORD)1048576);
        set_value(key_channels_operational, _T("MaxSizeUpper")      , (DWORD)0);
        set_value(key_channels_operational, _T("Retention")         , (DWORD)0);
        set_value(key_channels_operational, _T("AutoBackupLogFiles"), (DWORD)0);
        set_value(key_channels_operational, _T("Type")              , (DWORD)1);
        sprintf(sz, _T("%s/Analytic"), event_provider_name.c_str());
        s = RegCreateKeyEx(key_channels, sz.c_str(), NULL, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, key_channels_analytic, NULL);
        if (s != ERROR_SUCCESS) throw win_runtime_error(s);
        set_value(key_channels_analytic, _T("OwningPublisher"), event_provider_guid);
        set_value(key_channels_analytic, _T("Enabled")        , (DWORD)0);
        set_value(key_channels_analytic, _T("Isolation")      , (DWORD)0);
        set_value(key_channels_analytic, _T("ChannelAccess")  , _T("O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x7;;;SO)(A;;0x3;;;IU)(A;;0x3;;;SU)(A;;0x3;;;S-1-5-3)(A;;0x3;;;S-1-5-33)(A;;0x1;;;S-1-5-32-573)"));
        set_value(key_channels_analytic, _T("MaxSize")        , (DWORD)1048576);
        set_value(key_channels_analytic, _T("MaxSizeUpper")   , (DWORD)0);
        set_value(key_channels_analytic, _T("Retention")      , (DWORD)4294967295);
        set_value(key_channels_analytic, _T("Type")           , (DWORD)2);

        // Register event publishers.
        reg_key key_publishers, key_event_source;
        s = RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers"), 0, KEY_CREATE_SUB_KEY, key_publishers);
        if (s != ERROR_SUCCESS) throw win_runtime_error(s);
        s = RegCreateKeyEx(key_publishers, event_provider_guid.c_str(), NULL, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, key_event_source, NULL);
        if (s != ERROR_SUCCESS) throw win_runtime_error(s);
        set_value(key_event_source, NULL                  , event_provider_name);
        if (!GetModuleFileName(g_hInstance, sz)) throw win_runtime_error("GetModuleFileName failed.");
        set_value(key_event_source, _T("MessageFileName") , sz);
        set_value(key_event_source, _T("ResourceFileName"), sz);
        set_value(key_event_source, _T("Enabled")         , (DWORD)1);

        // Bind channels and publishers.
        reg_key key_channel_refs, key_channel_refs_operational, key_channel_refs_analytic;
        s = RegCreateKeyEx(key_event_source, _T("ChannelReferences"), NULL, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, key_channel_refs, NULL);
        if (s != ERROR_SUCCESS) throw win_runtime_error(s);
        s = RegCreateKeyEx(key_channel_refs, _T("0"), NULL, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, key_channel_refs_operational, NULL);
        if (s != ERROR_SUCCESS) throw win_runtime_error(s);
        sprintf(sz, _T("%s/Operational"), event_provider_name.c_str());
        set_value(key_channel_refs_operational, NULL       , sz);
        set_value(key_channel_refs_operational, _T("Id")   , (DWORD)16);
        set_value(key_channel_refs_operational, _T("Flags"), (DWORD)0);
        s = RegCreateKeyEx(key_channel_refs, _T("1"), NULL, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, key_channel_refs_analytic, NULL);
        if (s != ERROR_SUCCESS) throw win_runtime_error(s);
        sprintf(sz, _T("%s/Analytic"), event_provider_name.c_str());
        set_value(key_channel_refs_analytic, NULL       , sz);
        set_value(key_channel_refs_analytic, _T("Id")   , (DWORD)17);
        set_value(key_channel_refs_analytic, _T("Flags"), (DWORD)0);
        set_value(key_channel_refs, _T("Count"), (DWORD)2);

        return S_OK;
    } catch(win_runtime_error &err) {
        OutputDebugStr(_T("%hs (error %u)\n"), err.what(), err.number());
        return E_FAIL;
    } catch(...) {
        OutputDebugStr(_T("Registering DLL failed.\n"));
        return E_FAIL;
    }
}


///
/// Unregisters event source from Windows registry
///
/// \returns Always S_OK
///
STDAPI DllUnregisterServer()
{
    // Unregister event publishers.
    try {
        reg_key key_publishers;
        LSTATUS s = RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers"), 0, KEY_READ, key_publishers);
        if (s != ERROR_SUCCESS) throw win_runtime_error(s);
        key_publishers.delete_subkey(tstring_guid(EAPMETHOD_TRACE_EVENT_PROVIDER).c_str());
    } catch(...) {}

    // Unregister event channels.
    try {
        reg_key key_channels;
        LSTATUS s = RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels"), 0, KEY_READ, key_channels);
        if (s != ERROR_SUCCESS) throw win_runtime_error(s);
        key_channels.delete_subkey(_T(VENDOR_NAME_STR) _T("-") _T(PRODUCT_NAME_STR) _T("-EAPMethod/Operational"));
        key_channels.delete_subkey(_T(VENDOR_NAME_STR) _T("-") _T(PRODUCT_NAME_STR) _T("-EAPMethod/Analytic"));
    } catch(...) {}

    return S_OK;
}
