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
/// Registers method in EapHost registry
///
/// \returns S_OK if successful; E_FAIL otherwise
///
STDAPI DllRegisterServer()
{
    try {
        tstring sz, sz2;
        reg_key key_methods, key_author, key_method;
        if (!key_methods.open(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\services\\EapHost\\Methods"), 0, KEY_CREATE_SUB_KEY)) throw win_runtime_error();
        sprintf(sz, _T("%u"), EAPMETHOD_AUTHOR_ID);
        if (!key_author.create(key_methods, sz.c_str(), NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE)) throw win_runtime_error();
        set_value(key_author, NULL, _T(PRODUCT_NAME_STR));
        sprintf(sz, _T("%u"), EAPMETHOD_TYPE);
        if (!key_method.create(key_author, sz.c_str(), NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE)) throw win_runtime_error();
        if (!GetModuleFileName(g_peer.m_instance, sz)) throw win_runtime_error("GetModuleFileName failed.");
        sprintf(sz2, _T("@%s,-1"), sz.c_str());
        set_value(key_method, _T("PeerDllPath")     , sz);
        set_value(key_method, _T("PeerFriendlyName"), sz2);
        set_value(key_method, _T("Properties")      , (DWORD)389871807);

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
/// Unregisters method from EapHost registry
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
        if (!key_methods.delete_subkey(sz.c_str())) throw win_runtime_error();
    } catch(...) {}
    return S_OK;
}
