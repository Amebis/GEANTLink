/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2020-2022 Amebis
    Copyright © 2016 GÉANT
*/

#include "PCH_UI.h"

using namespace std;
using namespace winstd;


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


///
/// Registers method UI in EapHost registry
///
/// \returns S_OK if successful; E_FAIL otherwise
///
STDAPI DllRegisterServer()
{
    try {
        tstring sz;
        reg_key key_methods, key_author, key_method;
        if (!key_methods.open(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\services\\EapHost\\Methods"), 0, KEY_CREATE_SUB_KEY)) throw win_runtime_error();
        sprintf(sz, _T("%u"), EAPMETHOD_AUTHOR_ID);
        if (!key_author.create(key_methods, sz.c_str(), NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE)) throw win_runtime_error();
        set_value(key_author, NULL, _T(PRODUCT_NAME_STR));
        sprintf(sz, _T("%u"), EAPMETHOD_TYPE);
        if (!key_method.create(key_author, sz.c_str(), NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE)) throw win_runtime_error();
        if (!GetModuleFileName(g_peer.m_instance, sz)) throw win_runtime_error("GetModuleFileName failed.");
        set_value(key_method, _T("PeerConfigUIPath")        , sz);
        set_value(key_method, _T("PeerIdentityPath")        , sz);
        set_value(key_method, _T("PeerInteractiveUIPath")   , sz);
        set_value(key_method, _T("PeerInvokePasswordDialog"), (DWORD)0);
        set_value(key_method, _T("PeerInvokeUsernameDialog"), (DWORD)0);

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
/// Unregisters method UI from EapHost registry
///
/// \returns Always S_OK
///
STDAPI DllUnregisterServer()
{
    try {
        tstring sz;
        reg_key key_methods;
        if (!key_methods.open(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\services\\EapHost\\Methods"), 0, KEY_READ)) throw win_runtime_error();
        sprintf(sz, _T("%u\\%u"), EAPMETHOD_AUTHOR_ID, EAPMETHOD_TYPE);
        key_methods.delete_subkey(sz.c_str());
    } catch(...) {}
    return S_OK;
}
