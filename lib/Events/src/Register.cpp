/*
    Copyright 2020-2020 Amebis
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
#endif
        g_hInstance = hinstDLL;
    } else if (fdwReason == DLL_PROCESS_DETACH)
        assert(!_CrtDumpMemoryLeaks());

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
        if (!key_channels.open(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels"), 0, KEY_CREATE_SUB_KEY)) throw win_runtime_error();
        sprintf(sz, _T("%s/Operational"), event_provider_name.c_str());
        if (!key_channels_operational.create(key_channels, sz.c_str(), NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE)) throw win_runtime_error();
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
        if (!key_channels_analytic.create(key_channels, sz.c_str(), NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE)) throw win_runtime_error();
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
        if (!key_publishers.open(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers"), 0, KEY_CREATE_SUB_KEY)) throw win_runtime_error();
        if (!key_event_source.create(key_publishers, event_provider_guid.c_str(), NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE)) throw win_runtime_error();
        set_value(key_event_source, NULL                  , event_provider_name);
        if (!GetModuleFileName(g_hInstance, sz)) throw win_runtime_error("GetModuleFileName failed.");
        set_value(key_event_source, _T("MessageFileName") , sz);
        set_value(key_event_source, _T("ResourceFileName"), sz);
        set_value(key_event_source, _T("Enabled")         , (DWORD)1);

        // Bind channels and publishers.
        reg_key key_channel_refs, key_channel_refs_operational, key_channel_refs_analytic;
        if (!key_channel_refs.create(key_event_source, _T("ChannelReferences"), NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE)) throw win_runtime_error();
        if (!key_channel_refs_operational.create(key_channel_refs, _T("0"), NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE)) throw win_runtime_error();
        sprintf(sz, _T("%s/Operational"), event_provider_name.c_str());
        set_value(key_channel_refs_operational, NULL       , sz);
        set_value(key_channel_refs_operational, _T("Id")   , (DWORD)16);
        set_value(key_channel_refs_operational, _T("Flags"), (DWORD)0);
        if (!key_channel_refs_analytic.create(key_channel_refs, _T("1"), NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE)) throw win_runtime_error();
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
        if (!key_publishers.open(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers"), 0, KEY_READ)) throw win_runtime_error();
        key_publishers.delete_subkey(tstring_guid(EAPMETHOD_TRACE_EVENT_PROVIDER).c_str());
    } catch(...) {}

    // Unregister event channels.
    try {
        reg_key key_channels;
        if (!key_channels.open(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels"), 0, KEY_READ)) throw win_runtime_error();
        key_channels.delete_subkey(_T(VENDOR_NAME_STR) _T("-") _T(PRODUCT_NAME_STR) _T("-EAPMethod/Operational"));
        key_channels.delete_subkey(_T(VENDOR_NAME_STR) _T("-") _T(PRODUCT_NAME_STR) _T("-EAPMethod/Analytic"));
    } catch(...) {}

    return S_OK;
}
