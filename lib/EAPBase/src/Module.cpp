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

eap::module::module(type_t eap_method) :
    m_eap_method(eap_method),
    m_instance(NULL)
{
    m_ep.create(&EAPMETHOD_TRACE_EVENT_PROVIDER);
    m_ep.write(&EAPMETHOD_TRACE_EVT_MODULE_LOAD, event_data((BYTE)m_eap_method), event_data::blank);

    m_heap.create(0, 0, 0);
}


eap::module::~module()
{
    m_ep.write(&EAPMETHOD_TRACE_EVT_MODULE_UNLOAD, event_data((BYTE)m_eap_method), event_data::blank);
}


EAP_ERROR* eap::module::make_error(_In_ DWORD dwErrorCode, _In_ DWORD dwReasonCode, _In_ LPCGUID pRootCauseGuid, _In_ LPCGUID pRepairGuid, _In_ LPCGUID pHelpLinkGuid, _In_z_ LPCWSTR pszRootCauseString, _In_z_ LPCWSTR pszRepairString) const
{
    // Calculate memory size requirement.
    SIZE_T
        nRootCauseSize    = pszRootCauseString != NULL && pszRootCauseString[0] ? (wcslen(pszRootCauseString) + 1)*sizeof(WCHAR) : 0,
        nRepairStringSize = pszRepairString    != NULL && pszRepairString   [0] ? (wcslen(pszRepairString   ) + 1)*sizeof(WCHAR) : 0,
        nEapErrorSize = sizeof(EAP_ERROR) + nRootCauseSize + nRepairStringSize;

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

    // Write trace event.
    vector<EVENT_DATA_DESCRIPTOR> evt_desc;
    evt_desc.reserve(8);
    evt_desc.push_back(event_data(pError->dwWinError));
    evt_desc.push_back(event_data(pError->type.eapType.type));
    evt_desc.push_back(event_data(pError->dwReasonCode));
    evt_desc.push_back(event_data(&(pError->rootCauseGuid), sizeof(GUID)));
    evt_desc.push_back(event_data(&(pError->repairGuid), sizeof(GUID)));
    evt_desc.push_back(event_data(&(pError->helpLinkGuid), sizeof(GUID)));
    evt_desc.push_back(event_data(pError->pRootCauseString));
    evt_desc.push_back(event_data(pError->pRepairString));
    m_ep.write(&EAPMETHOD_TRACE_EAP_ERROR, (ULONG)evt_desc.size(), evt_desc.data());

    return pError;
}


BYTE* eap::module::alloc_memory(_In_ size_t size)
{
    return (BYTE*)HeapAlloc(m_heap, 0, size);
}


void eap::module::free_memory(_In_ BYTE *ptr)
{
    ETW_FN_VOID;

    // Since we do security here and some of the BLOBs contain credentials, sanitize every memory block before freeing.
    SecureZeroMemory(ptr, HeapSize(m_heap, 0, ptr));
    HeapFree(m_heap, 0, ptr);
}


void eap::module::free_error_memory(_In_ EAP_ERROR *err)
{
    ETW_FN_VOID;

    // pRootCauseString and pRepairString always trail the ppEapError to reduce number of (de)allocations.
    HeapFree(m_heap, 0, err);
}


DWORD eap::module::encrypt(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size, _Out_ std::vector<unsigned char> &enc, _Out_ EAP_ERROR **ppEapError, _Out_opt_ HCRYPTHASH hHash) const
{
    assert(ppEapError);
    DWORD dwResult;

    // Import the public key.
    HRSRC res = FindResource(m_instance, MAKEINTRESOURCE(IDR_EAP_KEY_PUBLIC), RT_RCDATA);
    assert(res);
    HGLOBAL res_handle = LoadResource(m_instance, res);
    assert(res_handle);
    crypt_key key;
    unique_ptr<CERT_PUBLIC_KEY_INFO, LocalFree_delete<CERT_PUBLIC_KEY_INFO> > keyinfo_data;
    DWORD keyinfo_size = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, (const BYTE*)::LockResource(res_handle), ::SizeofResource(m_instance, res), CRYPT_DECODE_ALLOC_FLAG, NULL, &keyinfo_data, &keyinfo_size)) {
        *ppEapError = make_error(dwResult = GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" CryptDecodeObjectEx failed."), NULL);
        return dwResult;
    }

    if (!key.import_public(hProv, X509_ASN_ENCODING, keyinfo_data.get())) {
        *ppEapError = make_error(dwResult = GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Public key import failed."), NULL);
        return dwResult;
    }

    // Pre-allocate memory to allow space, as encryption will grow the data.
    DWORD dwBlockLen;
    vector<unsigned char, sanitizing_allocator<unsigned char> > buf(size);
    memcpy(buf.data(), data, size);
    if (!CryptGetKeyParam(key, KP_BLOCKLEN, dwBlockLen, 0)) dwBlockLen = 0;
    buf.reserve((size + dwBlockLen - 1) / dwBlockLen * dwBlockLen);

    // Encrypt the data using our public key.
    if (!CryptEncrypt(key, hHash, TRUE, 0, buf)) {
        *ppEapError = make_error(dwResult = GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Encrypting data failed."), NULL);
        return dwResult;
    }

    // Copy encrypted data.
    enc.assign(buf.begin(), buf.end());

    return ERROR_SUCCESS;
}


DWORD eap::module::encrypt_md5(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size, _Out_ std::vector<unsigned char> &enc, _Out_ EAP_ERROR **ppEapError) const
{
    DWORD dwResult;

    // Create hash.
    crypt_hash hash;
    if (!hash.create(hProv, CALG_MD5)) {
        *ppEapError = make_error(dwResult = GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Creating MD5 hash failed."), NULL);
        return dwResult;
    }

    // Encrypt data.
    if ((dwResult = encrypt(hProv, data, size, enc, ppEapError, hash)) != ERROR_SUCCESS)
        return dwResult;

    // Calculate MD5 hash and append it.
    vector<unsigned char> hash_bin;
    if (!CryptGetHashParam(hash, HP_HASHVAL, hash_bin, 0)) {
        *ppEapError = make_error(dwResult = GetLastError(), 0, NULL, NULL, NULL, _T(__FUNCTION__) _T(" Calculating MD5 hash failed."), NULL);
        return dwResult;
    }
    enc.insert(enc.end(), hash_bin.begin(), hash_bin.end());

    return ERROR_SUCCESS;
}
