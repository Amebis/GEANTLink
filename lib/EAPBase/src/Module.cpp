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

#include "StdAfx.h"

using namespace std;
using namespace winstd;


//////////////////////////////////////////////////////////////////////
// eap::module
//////////////////////////////////////////////////////////////////////

eap::module::module(eap_type_t eap_method) :
    m_eap_method(eap_method),
    m_instance(NULL)
{
    m_ep.create(&EAPMETHOD_TRACE_EVENT_PROVIDER);
    m_ep.write(&EAPMETHOD_TRACE_EVT_MODULE_LOAD, event_data((unsigned int)m_eap_method), event_data::blank);

    m_heap.create(0, 0, 0);
}


eap::module::~module()
{
    m_ep.write(&EAPMETHOD_TRACE_EVT_MODULE_UNLOAD, event_data((unsigned int)m_eap_method), event_data::blank);
}


EAP_ERROR* eap::module::make_error(_In_ DWORD dwErrorCode, _In_opt_z_ LPCWSTR pszRootCauseString, _In_opt_z_ LPCWSTR pszRepairString, _In_opt_ DWORD dwReasonCode, _In_opt_ LPCGUID pRootCauseGuid, _In_opt_ LPCGUID pRepairGuid, _In_opt_ LPCGUID pHelpLinkGuid) const
{
    // Calculate memory size requirement.
    SIZE_T
        nRootCauseSize    = pszRootCauseString != NULL && pszRootCauseString[0] ? (wcslen(pszRootCauseString) + 1)*sizeof(WCHAR) : 0,
        nRepairStringSize = pszRepairString    != NULL && pszRepairString   [0] ? (wcslen(pszRepairString   ) + 1)*sizeof(WCHAR) : 0,
        nEapErrorSize     = sizeof(EAP_ERROR) + nRootCauseSize + nRepairStringSize;

    EAP_ERROR *pError = (EAP_ERROR*)HeapAlloc(m_heap, 0, nEapErrorSize);
    if (!pError)
        return NULL;
    BYTE *p = (BYTE*)(pError + 1);

    // Fill the error descriptor.
    pError->dwWinError                = dwErrorCode;
    pError->type.eapType.type         = (BYTE)m_eap_method;
    pError->type.eapType.dwVendorId   = 0;
    pError->type.eapType.dwVendorType = 0;
    pError->type.dwAuthorId           = 67532;
    pError->dwReasonCode              = dwReasonCode;
    pError->rootCauseGuid             = pRootCauseGuid != NULL ? *pRootCauseGuid : GUID_NULL;
    pError->repairGuid                = pRepairGuid    != NULL ? *pRepairGuid    : GUID_NULL;
    pError->helpLinkGuid              = pHelpLinkGuid  != NULL ? *pHelpLinkGuid  : GUID_NULL;
    if (nRootCauseSize) {
        pError->pRootCauseString = (LPWSTR)p;
        memcpy(pError->pRootCauseString, pszRootCauseString, nRootCauseSize);
        p += nRootCauseSize;
    } else
        pError->pRootCauseString = NULL;
    if (nRepairStringSize) {
        pError->pRepairString = (LPWSTR)p;
        memcpy(pError->pRepairString, pszRepairString, nRepairStringSize);
        p += nRepairStringSize;
    } else
        pError->pRepairString = NULL;

    return pError;
}


EAP_ERROR* eap::module::make_error(_In_ std::exception &err) const
{
    wstring what;
    MultiByteToWideChar(CP_ACP, 0, err.what(), -1, what);

    {
        win_runtime_error &e(dynamic_cast<win_runtime_error&>(err));
        if (&e)
            return make_error(e.number(), what.c_str());
    }

    {
        com_runtime_error &e(dynamic_cast<com_runtime_error&>(err));
        if (&e)
            return make_error(HRESULT_CODE(e.number()), what.c_str());
    }

    {
        invalid_argument &e(dynamic_cast<invalid_argument&>(err));
        if (&e)
            return make_error(ERROR_INVALID_PARAMETER, what.c_str());
    }

    wstring name;
    MultiByteToWideChar(CP_ACP, 0, typeid(err).name(), -1, name);
    name += L": ";
    name += what;
    return make_error(ERROR_INVALID_DATA, name.c_str());
}


BYTE* eap::module::alloc_memory(_In_ size_t size)
{
    BYTE *p = (BYTE*)HeapAlloc(m_heap, 0, size);
    if (!p)
        throw win_runtime_error(winstd::string_printf(__FUNCTION__ " Error allocating memory for BLOB (%uB).", size));
    return p;
}


void eap::module::free_memory(_In_ BYTE *ptr)
{
#if !EAP_ENCRYPT_BLOBS
    // Since we do security here and some of the BLOBs contain credentials, sanitize every memory block before freeing.
    SecureZeroMemory(ptr, HeapSize(m_heap, 0, ptr));
#endif
    HeapFree(m_heap, 0, ptr);
}


void eap::module::free_error_memory(_In_ EAP_ERROR *err)
{
    // pRootCauseString and pRepairString always trail the ppEapError to reduce number of (de)allocations.
    HeapFree(m_heap, 0, err);
}


void eap::module::log_error(_In_ const EAP_ERROR *err) const
{
    assert(err);

    // Write trace event.
    vector<EVENT_DATA_DESCRIPTOR> evt_desc;
    evt_desc.reserve(8);
    evt_desc.push_back(event_data(err->dwWinError));
    DWORD dwType = err->type.eapType.type;
    evt_desc.push_back(event_data(dwType));
    evt_desc.push_back(event_data(err->dwReasonCode));
    evt_desc.push_back(event_data(&(err->rootCauseGuid), sizeof(GUID)));
    evt_desc.push_back(event_data(&(err->repairGuid), sizeof(GUID)));
    evt_desc.push_back(event_data(&(err->helpLinkGuid), sizeof(GUID)));
    evt_desc.push_back(event_data(err->pRootCauseString));
    evt_desc.push_back(event_data(err->pRepairString));
    m_ep.write(&EAPMETHOD_TRACE_EVT_EAP_ERROR, (ULONG)evt_desc.size(), evt_desc.data());
}


eap::config_method* eap::module::make_config_method()
{
    return NULL;
}


std::vector<unsigned char> eap::module::encrypt(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size, _Out_opt_ HCRYPTHASH hHash) const
{
    // Generate 256-bit AES session key.
    crypt_key key_aes;
    if (!CryptGenKey(hProv, CALG_AES_256, MAKELONG(CRYPT_EXPORTABLE, 256), &key_aes))
        throw win_runtime_error(__FUNCTION__ " CryptGenKey failed.");

    // Import the public RSA key.
    HRSRC res = FindResource(m_instance, MAKEINTRESOURCE(IDR_EAP_KEY_PUBLIC), RT_RCDATA);
    assert(res);
    HGLOBAL res_handle = LoadResource(m_instance, res);
    assert(res_handle);
    crypt_key key_rsa;
    unique_ptr<CERT_PUBLIC_KEY_INFO, LocalFree_delete<CERT_PUBLIC_KEY_INFO> > keyinfo_data;
    DWORD keyinfo_size = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, (const BYTE*)::LockResource(res_handle), ::SizeofResource(m_instance, res), CRYPT_DECODE_ALLOC_FLAG, NULL, &keyinfo_data, &keyinfo_size))
        throw win_runtime_error(__FUNCTION__ " CryptDecodeObjectEx failed.");
    if (!key_rsa.import_public(hProv, X509_ASN_ENCODING, keyinfo_data.get()))
        throw win_runtime_error(__FUNCTION__ " Public key import failed.");

    // Export AES session key encrypted with public RSA key.
    vector<unsigned char, sanitizing_allocator<unsigned char> > buf;
    if (!CryptExportKey(key_aes, key_rsa, SIMPLEBLOB, 0, buf))
        throw win_runtime_error(__FUNCTION__ " CryptExportKey failed.");
    std::vector<unsigned char> enc(buf.begin(), buf.end());

    // Pre-allocate memory to allow space, as encryption will grow the data.
    buf.assign((const unsigned char*)data, (const unsigned char*)data + size);
    DWORD dwBlockLen;
    if (!CryptGetKeyParam(key_aes, KP_BLOCKLEN, dwBlockLen, 0)) dwBlockLen = 0;
    buf.reserve((size + dwBlockLen) / dwBlockLen * dwBlockLen);

    // Encrypt the data using AES key.
    if (!CryptEncrypt(key_aes, hHash, TRUE, 0, buf))
        throw win_runtime_error(__FUNCTION__ " CryptEncrypt failed.");

    // Append encrypted data.
    enc.insert(enc.cend(), buf.begin(), buf.end());
    return enc;
}


std::vector<unsigned char> eap::module::encrypt_md5(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size) const
{
    // Create hash.
    crypt_hash hash;
    if (!hash.create(hProv, CALG_MD5))
        throw win_runtime_error(__FUNCTION__ " Creating MD5 hash failed.");

    // Encrypt data.
    std::vector<unsigned char> enc(std::move(encrypt(hProv, data, size, hash)));

    // Calculate MD5 hash.
    vector<unsigned char> hash_bin;
    if (!CryptGetHashParam(hash, HP_HASHVAL, hash_bin, 0))
        throw invalid_argument(__FUNCTION__ " Calculating MD5 hash failed.");

    // Append hash.
    enc.insert(enc.end(), hash_bin.begin(), hash_bin.end());
    return enc;
}


//////////////////////////////////////////////////////////////////////
// eap::peer
//////////////////////////////////////////////////////////////////////

eap::peer::peer(_In_ eap_type_t eap_method) : module(eap_method)
{
}


void eap::peer::query_credential_input_fields(
    _In_                                   HANDLE                       hUserImpersonationToken,
    _In_                                   DWORD                        dwFlags,
    _In_                                   DWORD                        dwConnectionDataSize,
    _In_count_(dwConnectionDataSize) const BYTE                         *pConnectionData,
    _Inout_                                EAP_CONFIG_INPUT_FIELD_ARRAY *pEapConfigInputFieldsArray) const
{
    UNREFERENCED_PARAMETER(hUserImpersonationToken);
    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(dwConnectionDataSize);
    UNREFERENCED_PARAMETER(pConnectionData);
    UNREFERENCED_PARAMETER(pEapConfigInputFieldsArray);

    throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " Not supported.");
}


void eap::peer::query_user_blob_from_credential_input_fields(
    _In_                                   HANDLE                       hUserImpersonationToken,
    _In_                                   DWORD                        dwFlags,
    _In_                                   DWORD                        dwConnectionDataSize,
    _In_count_(dwConnectionDataSize) const BYTE                         *pConnectionData,
    _In_                             const EAP_CONFIG_INPUT_FIELD_ARRAY *pEapConfigInputFieldArray,
    _Inout_                                DWORD                        *pdwUsersBlobSize,
    _Inout_                                BYTE                         **ppUserBlob) const
{
    UNREFERENCED_PARAMETER(hUserImpersonationToken);
    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(dwConnectionDataSize);
    UNREFERENCED_PARAMETER(pConnectionData);
    UNREFERENCED_PARAMETER(pEapConfigInputFieldArray);
    UNREFERENCED_PARAMETER(pdwUsersBlobSize);
    UNREFERENCED_PARAMETER(ppUserBlob);

    throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " Not supported.");
}


void eap::peer::query_interactive_ui_input_fields(
    _In_                                  DWORD                   dwVersion,
    _In_                                  DWORD                   dwFlags,
    _In_                                  DWORD                   dwUIContextDataSize,
    _In_count_(dwUIContextDataSize) const BYTE                    *pUIContextData,
    _Inout_                               EAP_INTERACTIVE_UI_DATA *pEapInteractiveUIData) const
{
    UNREFERENCED_PARAMETER(dwVersion);
    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(dwUIContextDataSize);
    UNREFERENCED_PARAMETER(pUIContextData);
    UNREFERENCED_PARAMETER(pEapInteractiveUIData);

    throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " Not supported.");
}


void eap::peer::query_ui_blob_from_interactive_ui_input_fields(
    _In_                                  DWORD                   dwVersion,
    _In_                                  DWORD                   dwFlags,
    _In_                                  DWORD                   dwUIContextDataSize,
    _In_count_(dwUIContextDataSize) const BYTE                    *pUIContextData,
    _In_                            const EAP_INTERACTIVE_UI_DATA *pEapInteractiveUIData,
    _Inout_                               DWORD                   *pdwDataFromInteractiveUISize,
    _Inout_                               BYTE                    **ppDataFromInteractiveUI) const
{
    UNREFERENCED_PARAMETER(dwVersion);
    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(dwUIContextDataSize);
    UNREFERENCED_PARAMETER(pUIContextData);
    UNREFERENCED_PARAMETER(pEapInteractiveUIData);
    UNREFERENCED_PARAMETER(pdwDataFromInteractiveUISize);
    UNREFERENCED_PARAMETER(ppDataFromInteractiveUI);

    throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " Not supported.");
}
