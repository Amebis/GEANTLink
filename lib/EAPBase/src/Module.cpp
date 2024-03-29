/*
    SPDX-License-Identifier: GPL-3.0-or-later
    Copyright © 2015-2022 Amebis
    Copyright © 2016 GÉANT
*/

#include "PCH.h"

using namespace std;
using namespace winstd;


//////////////////////////////////////////////////////////////////////
// eap::module
//////////////////////////////////////////////////////////////////////

eap::module::module(_In_ eap_type_t eap_method) :
    m_eap_method(eap_method),
    m_instance(NULL),
    m_heap(HeapCreate(0, 0, 0))
{
    m_ep.create(&EAPMETHOD_TRACE_EVENT_PROVIDER);
    m_ep.write(&EAPMETHOD_TRACE_EVT_MODULE_LOAD, event_data((unsigned int)m_eap_method), blank_event_data);
}


eap::module::~module()
{
    m_ep.write(&EAPMETHOD_TRACE_EVT_MODULE_UNLOAD, event_data((unsigned int)m_eap_method), blank_event_data);
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
    pError->type.dwAuthorId           = EAPMETHOD_AUTHOR_ID;
    pError->dwReasonCode              = dwReasonCode;
    pError->rootCauseGuid             = pRootCauseGuid != NULL ? *pRootCauseGuid : GUID_NULL;
    pError->repairGuid                = pRepairGuid    != NULL ? *pRepairGuid    : GUID_NULL;
    pError->helpLinkGuid              = pHelpLinkGuid  != NULL ? *pHelpLinkGuid  : GUID_NULL;
    if (nRootCauseSize) {
        pError->pRootCauseString = const_cast<LPWSTR>(reinterpret_cast<LPCWSTR>(p));
        memcpy(pError->pRootCauseString, pszRootCauseString, nRootCauseSize);
        p += nRootCauseSize;
    } else
        pError->pRootCauseString = NULL;
    if (nRepairStringSize) {
        pError->pRepairString = const_cast<LPWSTR>(reinterpret_cast<LPCWSTR>(p));
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
        eap_runtime_error *e = dynamic_cast<eap_runtime_error*>(&err);
        if (e)
            return make_error(e->number(), e->root_cause(), e->repair(), e->reason(), &e->root_cause_id(), &e->repair_id(), &e->help_link_id());
    }

    {
        win_runtime_error *e = dynamic_cast<win_runtime_error*>(&err);
        if (e)
            return make_error(e->number(), what.c_str());
    }

    {
        com_runtime_error *e = dynamic_cast<com_runtime_error*>(&err);
        if (e)
            return make_error(HRESULT_CODE(e->number()), what.c_str());
    }

    {
        sec_runtime_error *e = dynamic_cast<sec_runtime_error*>(&err);
        if (e)
            return make_error(SCODE_CODE(e->number()), what.c_str());
    }

    {
        invalid_argument *e = dynamic_cast<invalid_argument*>(&err);
        if (e)
            return make_error(ERROR_INVALID_PARAMETER, what.c_str());
    }

    wstring name;
    MultiByteToWideChar(CP_ACP, 0, typeid(err).name(), -1, name);
    name += L": ";
    name += what;
    return make_error(ERROR_INVALID_DATA, name.c_str());
}


EAP_ERROR* eap::module::make_error(_In_ const EAP_ERROR *err) const
{
    return make_error(
        err->dwWinError,
        err->pRootCauseString,
        err->pRepairString,
        err->dwReasonCode,
        &(err->rootCauseGuid),
        &(err->repairGuid),
        &(err->helpLinkGuid));
}


BYTE* eap::module::alloc_memory(_In_ size_t size) const
{
    BYTE *p = (BYTE*)HeapAlloc(m_heap, 0, size);
    if (!p)
        throw win_runtime_error(winstd::string_printf(__FUNCTION__ " Error allocating memory for BLOB (%zu).", size));
    return p;
}


void eap::module::free_memory(_In_ BYTE *ptr) const
{
#if !EAP_ENCRYPT_BLOBS
    // Since we do security here and some of the BLOBs contain credentials, sanitize every memory block before freeing.
    SecureZeroMemory(ptr, HeapSize(m_heap, 0, ptr));
#endif
    HeapFree(m_heap, 0, ptr);
}


void eap::module::free_error_memory(_In_ EAP_ERROR *err) const
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
    evt_desc.push_back(event_data(err->dwWinError      ));
    DWORD dwType = err->type.eapType.type;
    evt_desc.push_back(event_data(dwType               ));
    evt_desc.push_back(event_data(err->dwReasonCode    ));
    evt_desc.push_back(event_data(err->rootCauseGuid   ));
    evt_desc.push_back(event_data(err->repairGuid      ));
    evt_desc.push_back(event_data(err->helpLinkGuid    ));
    evt_desc.push_back(event_data(err->pRootCauseString));
    evt_desc.push_back(event_data(err->pRepairString   ));
    m_ep.write(&EAPMETHOD_TRACE_EVT_EAP_ERROR, (ULONG)evt_desc.size(), evt_desc.data());
}


std::vector<unsigned char> eap::module::encrypt(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size, _In_opt_ HCRYPTHASH hHash) const
{
    // Generate 256-bit AES session key.
    crypt_key key_aes;
    if (!CryptGenKey(hProv, CALG_AES_256, MAKELONG(CRYPT_EXPORTABLE, 256), &key_aes))
        throw win_runtime_error(__FUNCTION__ " CryptGenKey failed.");

    // Import the RSA key.
    winstd::crypt_key key_rsa;
    std::unique_ptr<unsigned char[], winstd::LocalFree_delete<unsigned char[]> > keyinfo_data;
    DWORD keyinfo_size = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, s_rsa_key, sizeof(s_rsa_key), CRYPT_DECODE_ALLOC_FLAG, NULL, &keyinfo_data, &keyinfo_size))
        throw winstd::win_runtime_error(__FUNCTION__ " CryptDecodeObjectEx failed.");
    if (!CryptImportKey(hProv, keyinfo_data.get(), keyinfo_size, NULL, 0, key_rsa))
        throw winstd::win_runtime_error(__FUNCTION__ " Key import failed.");

    // Export AES session key encrypted with public RSA key.
    vector<unsigned char, sanitizing_allocator<unsigned char> > buf;
    if (!CryptExportKey(key_aes, key_rsa, SIMPLEBLOB, 0, buf))
        throw win_runtime_error(__FUNCTION__ " CryptExportKey failed.");
    std::vector<unsigned char> enc(buf.begin(), buf.end());

    // Pre-allocate memory to allow space, as encryption will grow the data.
    buf.assign(reinterpret_cast<const unsigned char*>(data), reinterpret_cast<const unsigned char*>(data) + size);
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
    if (!CryptCreateHash(hProv, CALG_MD5, NULL, 0, hash))
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


/// \cond internal
const unsigned char eap::module::s_rsa_key[1191] = {
    0x30, 0x82, 0x04, 0xa3, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xb5, 0x70, 0x43, 0x1a,
    0x1d, 0x2b, 0xa1, 0x9e, 0x6a, 0x1c, 0xac, 0x80, 0x4b, 0x15, 0xb1, 0x4b, 0xc8, 0x9b, 0xc5, 0xf4,
    0x28, 0xad, 0x6c, 0x1d, 0x67, 0xb5, 0xbb, 0xde, 0x5c, 0x75, 0xb4, 0x66, 0x2a, 0xcc, 0x4c, 0x5e,
    0x55, 0xd4, 0x97, 0xb1, 0xbc, 0xf7, 0xe8, 0xb7, 0xe5, 0x92, 0x57, 0x16, 0x85, 0xa1, 0xf7, 0xbb,
    0x74, 0x34, 0xd1, 0x57, 0x19, 0x70, 0x2a, 0x0b, 0xe1, 0xa9, 0x20, 0xb4, 0x78, 0x25, 0x25, 0xf1,
    0x78, 0x3b, 0xf9, 0x2a, 0xf8, 0x8c, 0xa5, 0xee, 0x52, 0x95, 0xc2, 0x15, 0x28, 0x30, 0x37, 0x8a,
    0xe2, 0x9b, 0x98, 0x47, 0x05, 0xfd, 0xbb, 0xb3, 0xa3, 0xf2, 0x1b, 0xe3, 0x61, 0xe2, 0xaf, 0xab,
    0x8c, 0x58, 0x5f, 0x49, 0x2a, 0x51, 0x0b, 0xcf, 0x54, 0xd5, 0xdc, 0x27, 0xd8, 0xf9, 0xea, 0xf0,
    0xc4, 0x06, 0xbf, 0x54, 0x85, 0xab, 0x22, 0x12, 0x30, 0x2c, 0xff, 0x46, 0xf0, 0x9c, 0xfc, 0x34,
    0xb0, 0x66, 0x9f, 0x4c, 0x9c, 0x35, 0x19, 0x05, 0xaf, 0xef, 0xa0, 0x73, 0x2c, 0x0e, 0xc2, 0xc7,
    0x0b, 0x5e, 0x11, 0x40, 0xac, 0xc4, 0x27, 0x6b, 0xc3, 0x4e, 0x9e, 0x42, 0x57, 0x02, 0xfb, 0xf0,
    0x60, 0xde, 0x9f, 0xd9, 0xda, 0xe1, 0x94, 0x7f, 0xb4, 0xae, 0xac, 0x9d, 0xfb, 0x09, 0x79, 0x24,
    0x0e, 0xb0, 0x22, 0xac, 0x94, 0xad, 0x32, 0x91, 0xad, 0x30, 0xef, 0x6d, 0x26, 0xa8, 0x7a, 0x4a,
    0x50, 0xc4, 0x20, 0xa3, 0xd3, 0xff, 0xd9, 0xfe, 0xbc, 0x5a, 0x88, 0xc0, 0x6d, 0xe3, 0xa1, 0xad,
    0x25, 0x22, 0xcf, 0x99, 0x5f, 0xd0, 0xc4, 0xa1, 0xe6, 0xaa, 0x80, 0x31, 0x31, 0x07, 0x09, 0x80,
    0xda, 0x47, 0x77, 0xd4, 0x52, 0x26, 0xf9, 0x44, 0xbb, 0xd3, 0x1a, 0xab, 0x86, 0x17, 0xa0, 0x2a,
    0x9e, 0x55, 0xcd, 0xde, 0x0f, 0x4c, 0x4b, 0xd4, 0x76, 0x13, 0x47, 0xb7, 0x02, 0x03, 0x01, 0x00,
    0x01, 0x02, 0x82, 0x01, 0x01, 0x00, 0x85, 0x0f, 0xda, 0xb6, 0x49, 0x14, 0x59, 0x87, 0xf3, 0x2c,
    0x2a, 0x3a, 0x40, 0x56, 0x9d, 0x5b, 0x05, 0xb9, 0x70, 0x18, 0x9a, 0xc8, 0x6c, 0x94, 0xb8, 0x1d,
    0x68, 0xb5, 0x2f, 0xbb, 0xc6, 0xdc, 0x72, 0xa0, 0xb7, 0x95, 0x2b, 0x7f, 0x28, 0xec, 0xd9, 0xb8,
    0x3a, 0x3c, 0xbb, 0xa9, 0x72, 0x22, 0xfb, 0x48, 0x08, 0x85, 0xba, 0x38, 0x8e, 0x1a, 0x41, 0x76,
    0xa7, 0xef, 0x64, 0xc4, 0x83, 0x4e, 0xb7, 0x1a, 0x0f, 0x54, 0xa2, 0xa7, 0xe1, 0x19, 0x69, 0x84,
    0xc4, 0xa0, 0x1e, 0x82, 0xe3, 0xfe, 0x5e, 0x25, 0xd6, 0x66, 0x0d, 0xc0, 0xac, 0x91, 0xd1, 0xcb,
    0xfe, 0x9f, 0x45, 0x29, 0xe6, 0xd8, 0x00, 0x4e, 0x9e, 0x24, 0xc2, 0x5d, 0x81, 0x2c, 0x08, 0x53,
    0xbd, 0xc4, 0x84, 0xe3, 0xfe, 0x7c, 0x5e, 0xbd, 0x12, 0x57, 0x16, 0x7c, 0x18, 0x4f, 0x65, 0x64,
    0x57, 0x2d, 0x5d, 0x95, 0x72, 0x74, 0x99, 0x1a, 0xbd, 0x43, 0x6e, 0x65, 0xf8, 0xc9, 0x7b, 0xc1,
    0x01, 0x0c, 0x30, 0xd5, 0x90, 0x39, 0x01, 0xe3, 0x90, 0xaa, 0xd7, 0x50, 0xc3, 0x50, 0x74, 0x3f,
    0xe6, 0xa6, 0x5f, 0xc2, 0x9b, 0x90, 0xc5, 0x21, 0xe1, 0x42, 0xb3, 0x2d, 0x75, 0xec, 0x79, 0xe8,
    0x60, 0xe5, 0xcd, 0x37, 0xd9, 0xe3, 0xe3, 0x3b, 0x36, 0xcc, 0xc7, 0x43, 0x36, 0xb7, 0x60, 0x9f,
    0x90, 0x00, 0x1f, 0xec, 0x7c, 0x81, 0x4a, 0x70, 0xa5, 0x60, 0x92, 0x2d, 0xab, 0x9b, 0xed, 0x22,
    0x58, 0x73, 0x61, 0x85, 0x46, 0x6b, 0x1c, 0xc5, 0xbb, 0xad, 0xcf, 0xd3, 0x86, 0x97, 0xdf, 0xa3,
    0x4a, 0x99, 0x9a, 0x3e, 0x72, 0x47, 0xbd, 0xab, 0xd9, 0xbc, 0x03, 0x39, 0x3b, 0xfb, 0x84, 0xbf,
    0xdb, 0x4c, 0x29, 0x58, 0x00, 0x0f, 0xa9, 0x05, 0x74, 0x15, 0x7e, 0xd9, 0x8e, 0xc3, 0xc0, 0x46,
    0x65, 0xdc, 0x0f, 0x26, 0xfa, 0xb1, 0x02, 0x81, 0x81, 0x00, 0xd9, 0x79, 0xf5, 0xfe, 0x8e, 0x6a,
    0xd5, 0xb6, 0x22, 0x75, 0x41, 0x53, 0x83, 0xd6, 0x68, 0xbf, 0x27, 0xe9, 0x02, 0xa9, 0xe5, 0xc3,
    0xae, 0x8a, 0xef, 0x25, 0xb7, 0x67, 0x42, 0xca, 0x70, 0x67, 0xd3, 0x74, 0xd4, 0x49, 0x2c, 0xd4,
    0x39, 0xae, 0xe2, 0x9c, 0x2e, 0xd8, 0x81, 0xa3, 0x2b, 0x9b, 0x7a, 0xb7, 0x77, 0xb9, 0x97, 0x3e,
    0x28, 0x23, 0xd6, 0xc5, 0xe6, 0x6c, 0xa1, 0x2c, 0xb3, 0x54, 0x7b, 0xc2, 0x56, 0x36, 0x35, 0x74,
    0x19, 0x81, 0x4d, 0x11, 0x90, 0x4d, 0xf2, 0x75, 0xe4, 0xdd, 0x67, 0x1a, 0x0b, 0xef, 0xbe, 0x1a,
    0x0c, 0x62, 0xfb, 0xd3, 0x39, 0xcc, 0x05, 0xb4, 0x77, 0x46, 0x54, 0x0f, 0x0d, 0x94, 0xf7, 0xe9,
    0x4b, 0x6b, 0xa9, 0x65, 0x63, 0x92, 0xb4, 0x21, 0x0e, 0x8a, 0x6b, 0xa6, 0xaa, 0xdf, 0xb2, 0xc4,
    0x20, 0x68, 0x62, 0x3f, 0x6d, 0xf8, 0xfb, 0xcb, 0xff, 0x4f, 0x02, 0x81, 0x81, 0x00, 0xd5, 0x94,
    0x11, 0x8f, 0x9c, 0x9d, 0x77, 0xb4, 0x19, 0x0a, 0xad, 0xc1, 0x5d, 0x16, 0x10, 0x68, 0x60, 0x4f,
    0xba, 0xce, 0x80, 0xe7, 0x6d, 0x82, 0xb6, 0x19, 0xfe, 0x47, 0x03, 0xe4, 0x02, 0x49, 0x93, 0x37,
    0x73, 0x5a, 0x75, 0x81, 0x7e, 0xdd, 0xce, 0xd7, 0xf3, 0xd2, 0xa9, 0x67, 0x48, 0x15, 0x4d, 0x76,
    0xc0, 0x76, 0x0f, 0xcb, 0x6d, 0xea, 0x61, 0xec, 0x57, 0xee, 0xfe, 0xe0, 0xe7, 0x20, 0x5b, 0xee,
    0x54, 0x18, 0x28, 0x36, 0x33, 0x99, 0xf0, 0x91, 0x14, 0x3e, 0x00, 0x33, 0xcc, 0xf4, 0xc8, 0x94,
    0xf8, 0x0a, 0x38, 0xbc, 0x61, 0x6c, 0x8c, 0x2f, 0xfb, 0x45, 0x11, 0x25, 0xf2, 0xa4, 0x44, 0xa0,
    0x76, 0xfb, 0x62, 0x56, 0x56, 0x5a, 0xe7, 0x16, 0x9f, 0xf8, 0x47, 0xf6, 0x58, 0x4c, 0x3d, 0xab,
    0x47, 0xf3, 0xd2, 0xfe, 0x36, 0xea, 0x3a, 0x0f, 0x1e, 0x73, 0xe9, 0x84, 0xd7, 0x19, 0x02, 0x81,
    0x80, 0x03, 0x63, 0x58, 0x06, 0xc0, 0x37, 0x3f, 0xdf, 0x17, 0x88, 0x56, 0x1d, 0x33, 0xf7, 0x9a,
    0x28, 0x28, 0x3a, 0x04, 0x15, 0x9b, 0x83, 0xc1, 0xeb, 0x5e, 0x30, 0x6b, 0x3c, 0x0b, 0x99, 0x55,
    0xc8, 0xf8, 0x4d, 0x60, 0xa5, 0x47, 0x32, 0x83, 0x37, 0x8b, 0x46, 0x3d, 0xa0, 0x97, 0xdc, 0x6f,
    0xe8, 0x7b, 0x2f, 0xf2, 0x88, 0x8c, 0xa7, 0xa6, 0x3e, 0x70, 0xb1, 0x22, 0x96, 0xdc, 0xa7, 0xf2,
    0x9f, 0x45, 0x52, 0x50, 0xbf, 0x85, 0x73, 0xaa, 0x96, 0x0e, 0x1a, 0x50, 0xf2, 0x35, 0xed, 0xca,
    0x43, 0xfc, 0xc0, 0x36, 0x21, 0x65, 0x07, 0xc8, 0xdb, 0x9d, 0xea, 0xbb, 0x82, 0xc7, 0x2f, 0xf9,
    0x8f, 0xb9, 0xed, 0x86, 0x1b, 0xa5, 0x05, 0x18, 0x6c, 0xb3, 0xf5, 0xe5, 0x68, 0x3a, 0xb0, 0x2d,
    0x26, 0xd0, 0xe8, 0x86, 0xce, 0xf7, 0x5d, 0x00, 0xd8, 0x3f, 0x77, 0x97, 0x82, 0x02, 0x82, 0x3a,
    0x17, 0x02, 0x81, 0x80, 0x2c, 0x31, 0xa4, 0x64, 0x9c, 0x1a, 0xb5, 0x5f, 0x4d, 0xe3, 0x38, 0xcb,
    0x0f, 0x30, 0xf6, 0x9a, 0x32, 0x7b, 0xad, 0x02, 0xf8, 0x07, 0x6b, 0x50, 0xa5, 0xcf, 0xc1, 0x1e,
    0xfe, 0xbe, 0x1a, 0x7f, 0x10, 0xf8, 0x63, 0x65, 0x2f, 0x75, 0x69, 0x44, 0x0a, 0x7e, 0x03, 0x14,
    0xef, 0x3a, 0xd0, 0xde, 0x9f, 0x95, 0xd8, 0x03, 0x56, 0x07, 0x59, 0x2a, 0x2b, 0xb3, 0x15, 0x0a,
    0xfe, 0x30, 0x99, 0x82, 0xc7, 0xa3, 0x0c, 0x41, 0xa7, 0x68, 0x77, 0xca, 0xfd, 0xcd, 0x77, 0x6b,
    0xd0, 0xec, 0xe7, 0x17, 0x2b, 0xbe, 0x2f, 0x89, 0x25, 0xee, 0x4d, 0x16, 0x81, 0xf7, 0x97, 0xbd,
    0xd5, 0xeb, 0x8d, 0x46, 0xd2, 0x70, 0x85, 0xce, 0x44, 0xad, 0xea, 0xd6, 0x8a, 0x84, 0xd2, 0xfb,
    0x34, 0x20, 0xd4, 0x6a, 0x8a, 0x44, 0x3b, 0xf2, 0x47, 0x11, 0x95, 0x59, 0x68, 0x44, 0x22, 0xa0,
    0x07, 0x8d, 0x16, 0x59, 0x02, 0x81, 0x80, 0x4f, 0xe8, 0xc7, 0x9a, 0xee, 0x2a, 0x81, 0xf6, 0x2f,
    0x01, 0x71, 0xba, 0xdb, 0xf0, 0x91, 0x6b, 0x08, 0xd9, 0x2b, 0x2b, 0x1d, 0x5f, 0xd8, 0x09, 0x8c,
    0x71, 0x44, 0xde, 0xaf, 0xae, 0x25, 0xac, 0xd2, 0xa1, 0xc5, 0x6f, 0xd8, 0xf6, 0x9a, 0xc7, 0x47,
    0x6b, 0xd5, 0xa0, 0x11, 0x64, 0xf1, 0xbb, 0x25, 0x3b, 0x03, 0x6b, 0x6f, 0xd7, 0x77, 0xfd, 0x91,
    0x71, 0xe0, 0xe9, 0xcf, 0x79, 0x0b, 0x0e, 0x57, 0x98, 0xd7, 0x42, 0x8f, 0x53, 0x51, 0x77, 0xd9,
    0x29, 0x9e, 0xed, 0x49, 0x2c, 0x37, 0xd5, 0xca, 0x5b, 0xc6, 0xb6, 0xd0, 0x6a, 0x1f, 0x4f, 0x2f,
    0x06, 0xf7, 0xf3, 0x4f, 0x73, 0x36, 0xff, 0x2f, 0x1b, 0x4e, 0x6a, 0x7e, 0xa7, 0x68, 0xa3, 0xae,
    0x0a, 0x8b, 0xeb, 0xbc, 0xb6, 0x96, 0x75, 0xe9, 0x1c, 0xae, 0x65, 0xff, 0xa1, 0x75, 0xa2, 0x1c,
    0xee, 0xdd, 0xf3, 0xc9, 0x62, 0x6b, 0x0a
};
/// \endcond


//////////////////////////////////////////////////////////////////////
// eap::peer
//////////////////////////////////////////////////////////////////////

eap::peer::peer(_In_ eap_type_t eap_method) : module(eap_method)
{
}


void eap::peer::initialize()
{
}


void eap::peer::shutdown()
{
}


void eap::peer::get_identity(
    _In_                                   DWORD  dwFlags,
    _In_count_(dwConnectionDataSize) const BYTE   *pConnectionData,
    _In_                                   DWORD  dwConnectionDataSize,
    _In_count_(dwUserDataSize)       const BYTE   *pUserData,
    _In_                                   DWORD  dwUserDataSize,
    _Out_                                  BYTE   **ppUserDataOut,
    _Out_                                  DWORD  *pdwUserDataOutSize,
    _In_                                   HANDLE hTokenImpersonateUser,
    _Out_                                  BOOL   *pfInvokeUI,
    _Out_                                  WCHAR  **ppwszIdentity)
{
    assert(ppUserDataOut);
    assert(pdwUserDataOutSize);
    assert(pfInvokeUI);
    assert(ppwszIdentity);

    // Unpack configuration.
    config_connection cfg(*this);
    unpack(cfg, pConnectionData, dwConnectionDataSize);

    // Switch user context.
    user_impersonator impersonating(hTokenImpersonateUser);

    // Combine credentials.
    credentials_connection cred_out(*this, cfg);
    auto cfg_method = combine_credentials(dwFlags, cfg, pUserData, dwUserDataSize, cred_out);

    if (cfg_method) {
        // No UI will be necessary.
        *pfInvokeUI = FALSE;
    } else {
        // Credentials missing or incomplete.
        if ((dwFlags & EAP_FLAG_MACHINE_AUTH) == 0) {
            // Per-user authentication, request UI.
            log_event(&EAPMETHOD_TRACE_EVT_CRED_INVOKE_UI2, blank_event_data);
            *ppUserDataOut = NULL;
            *pdwUserDataOutSize = 0;
            *pfInvokeUI = TRUE;
            *ppwszIdentity = NULL;
            return;
        } else {
            // Per-machine authentication, cannot use UI.
            throw win_runtime_error(ERROR_NO_SUCH_USER, __FUNCTION__ " Credentials for per-machine authentication not available.");
        }
    }

    // Build our identity. ;)
    wstring identity(std::move(cfg_method->get_public_identity(*cred_out.m_cred.get())));
    log_event(&EAPMETHOD_TRACE_EVT_CRED_OUTER_ID1, event_data((unsigned int)cfg_method->get_method_id()), event_data(identity), blank_event_data);
    size_t size = sizeof(WCHAR)*(identity.length() + 1);
    *ppwszIdentity = (WCHAR*)alloc_memory(size);
    memcpy(*ppwszIdentity, identity.c_str(), size);

    // Pack credentials.
    pack(cred_out, ppUserDataOut, pdwUserDataOutSize);
}


void eap::peer::credentials_xml2blob(
    _In_                                   DWORD       dwFlags,
    _In_                                   IXMLDOMNode *pConfigRoot,
    _In_count_(dwConnectionDataSize) const BYTE        *pConnectionData,
    _In_                                   DWORD       dwConnectionDataSize,
    _Out_                                  BYTE        **ppCredentialsOut,
    _Out_                                  DWORD       *pdwCredentialsOutSize)
{
    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(pConnectionData);
    UNREFERENCED_PARAMETER(dwConnectionDataSize);

    // Load credentials from XML.
    unique_ptr<config_method> cfg(make_config());
    unique_ptr<credentials> cred(cfg->make_credentials());
    cred->load(pConfigRoot);

    // Pack credentials.
    pack(*cred, ppCredentialsOut, pdwCredentialsOutSize);
}


void eap::peer::query_credential_input_fields(
    _In_                                   HANDLE                       hUserImpersonationToken,
    _In_                                   DWORD                        dwFlags,
    _In_                                   DWORD                        dwConnectionDataSize,
    _In_count_(dwConnectionDataSize) const BYTE                         *pConnectionData,
    _Out_                                  EAP_CONFIG_INPUT_FIELD_ARRAY *pEapConfigInputFieldsArray) const
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
    _Out_                                  DWORD                        *pdwUsersBlobSize,
    _Out_                                  BYTE                         **ppUserBlob) const
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
    _Out_                                 EAP_INTERACTIVE_UI_DATA *pEapInteractiveUIData) const
{
    UNREFERENCED_PARAMETER(dwVersion);
    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(dwUIContextDataSize);
    UNREFERENCED_PARAMETER(pUIContextData);
    UNREFERENCED_PARAMETER(pEapInteractiveUIData);

    throw win_runtime_error(ERROR_NOT_SUPPORTED, __FUNCTION__ " Not supported.");
}


void eap::peer::query_ui_blob_from_interactive_ui_input_fields(
    _In_                                                        DWORD                   dwVersion,
    _In_                                                        DWORD                   dwFlags,
    _In_                                                        DWORD                   dwUIContextDataSize,
    _In_count_(dwUIContextDataSize)                       const BYTE                    *pUIContextData,
    _In_                                                  const EAP_INTERACTIVE_UI_DATA *pEapInteractiveUIData,
    _Out_                                                       DWORD                   *pdwDataFromInteractiveUISize,
    _Outptr_result_buffer_(*pdwDataFromInteractiveUISize)       BYTE                    **ppDataFromInteractiveUI) const
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


EAP_SESSION_HANDLE eap::peer::begin_session(
    _In_                                   DWORD              dwFlags,
    _In_                           const   EapAttributes      *pAttributeArray,
    _In_                                   HANDLE             hTokenImpersonateUser,
    _In_count_(dwConnectionDataSize) const BYTE               *pConnectionData,
    _In_                                   DWORD              dwConnectionDataSize,
    _In_count_(dwUserDataSize)       const BYTE               *pUserData,
    _In_                                   DWORD              dwUserDataSize,
    _In_                                   DWORD              dwMaxSendPacketSize)
{
    // Create new session.
    unique_ptr<session> s(new session(*this));

    // Unpack configuration.
    unpack(s->m_cfg, pConnectionData, dwConnectionDataSize);

    if (dwUserDataSize) {
        // Unpack credentials.
        unpack(s->m_cred, pUserData, dwUserDataSize);
    } else {
        // Regenerate user credentials.
        user_impersonator impersonating(hTokenImpersonateUser);
        auto cfg_method = combine_credentials(dwFlags, s->m_cfg, pUserData, dwUserDataSize, s->m_cred);
        if (!cfg_method) {
            // Credentials missing or incomplete.
            throw invalid_argument(__FUNCTION__ " Credentials are not available.");
        }
    }

    // Look-up the provider.
    config_method *cfg_method;
    for (auto cfg_prov = s->m_cfg.m_providers.begin(), cfg_prov_end = s->m_cfg.m_providers.end();; ++cfg_prov) {
        if (cfg_prov != cfg_prov_end) {
            if (s->m_cred.match(*cfg_prov)) {
                // Matching provider found.
                if (cfg_prov->m_methods.empty())
                    throw invalid_argument(string_printf(__FUNCTION__ " %ls provider has no methods.", cfg_prov->get_id().c_str()));
                cfg_method = cfg_prov->m_methods.front().get();
                break;
            }
        } else
            throw invalid_argument(string_printf(__FUNCTION__ " Credentials do not match to any provider within this connection configuration (provider: %ls).", s->m_cred.get_id().c_str()));
    }

    // We have configuration, we have credentials, create method.
    s->m_method.reset(make_method(*cfg_method, *s->m_cred.m_cred));

    // Initialize method.
    s->m_method->begin_session(dwFlags, pAttributeArray, hTokenImpersonateUser, dwMaxSendPacketSize);

    return s.release();
}


void eap::peer::end_session(_In_ EAP_SESSION_HANDLE hSession)
{
    assert(hSession);

    // End the session.
    auto s = static_cast<session*>(hSession);
    s->m_method->end_session();
    delete s;
}


void eap::peer::process_request_packet(
    _In_                                       EAP_SESSION_HANDLE  hSession,
    _In_bytecount_(dwReceivedPacketSize) const EapPacket           *pReceivedPacket,
    _In_                                       DWORD               dwReceivedPacketSize,
    _Out_                                      EapPeerMethodOutput *pEapOutput)
{
    assert(dwReceivedPacketSize == ntohs(*(WORD*)pReceivedPacket->Length));
    assert(pEapOutput);
    pEapOutput->action              = static_cast<session*>(hSession)->m_method->process_request_packet(pReceivedPacket, dwReceivedPacketSize);
    pEapOutput->fAllowNotifications = TRUE;
}


void eap::peer::get_response_packet(
    _In_                                   EAP_SESSION_HANDLE hSession,
    _Out_bytecapcount_(*pdwSendPacketSize) EapPacket          *pSendPacket,
    _Inout_                                DWORD              *pdwSendPacketSize)
{
    assert(pdwSendPacketSize);
    assert(pSendPacket || !*pdwSendPacketSize);

    sanitizing_blob packet;
    static_cast<session*>(hSession)->m_method->get_response_packet(packet, *pdwSendPacketSize);
    assert(packet.size() <= *pdwSendPacketSize);

    memcpy(pSendPacket, packet.data(), *pdwSendPacketSize = (DWORD)packet.size());
}


void eap::peer::get_result(
    _In_    EAP_SESSION_HANDLE        hSession,
    _In_    EapPeerMethodResultReason reason,
    _Inout_ EapPeerMethodResult       *pResult)
{
    auto s = static_cast<session*>(hSession);

    s->m_method->get_result(reason, pResult);

    // Do not report failure to EapHost, as it will not save updated configuration then. But we need it to save it, to alert user on next connection attempt.
    // EapHost should be aware of the failed condition.
    pResult->fIsSuccess          = TRUE;
    pResult->dwFailureReasonCode = ERROR_SUCCESS;

    if (pResult->fSaveConnectionData) {
        pack(s->m_cfg, &pResult->pConnectionData, &pResult->dwSizeofConnectionData);
        if (s->m_blob_cfg)
            free_memory(s->m_blob_cfg);
        s->m_blob_cfg = pResult->pConnectionData;
    }

#if EAP_USE_NATIVE_CREDENTIAL_CACHE
    pResult->fSaveUserData = TRUE;
    pack(s->m_cred, &pResult->pUserData, &pResult->dwSizeofUserData);
    if (s->m_blob_cred)
        free_memory(s->m_blob_cred);
    s->m_blob_cred = pResult->pUserData;
#endif
}


void eap::peer::get_ui_context(
    _In_  EAP_SESSION_HANDLE hSession,
    _Out_ BYTE               **ppUIContextData,
    _Out_ DWORD              *pdwUIContextDataSize)
{
    assert(ppUIContextData);
    assert(pdwUIContextDataSize);

    auto s = static_cast<session*>(hSession);

    // Get context data from method.
    ui_context ctx(s->m_cfg, s->m_cred);
    s->m_method->get_ui_context(ctx.m_data);

    // Pack context data.
    pack(ctx, ppUIContextData, pdwUIContextDataSize);
    if (s->m_blob_ui_ctx)
        free_memory(s->m_blob_ui_ctx);
    s->m_blob_ui_ctx = *ppUIContextData;
}


void eap::peer::set_ui_context(
    _In_                                  EAP_SESSION_HANDLE  hSession,
    _In_count_(dwUIContextDataSize) const BYTE                *pUIContextData,
    _In_                                  DWORD               dwUIContextDataSize,
    _Out_                                 EapPeerMethodOutput *pEapOutput)
{
    assert(pEapOutput);

    sanitizing_blob data(std::move(unpack(pUIContextData, dwUIContextDataSize)));
    pEapOutput->action              = static_cast<session*>(hSession)->m_method->set_ui_context(data.data(), (DWORD)data.size());
    pEapOutput->fAllowNotifications = TRUE;
}


void eap::peer::get_response_attributes(
    _In_  EAP_SESSION_HANDLE hSession,
    _Out_ EapAttributes      *pAttribs)
{
    static_cast<session*>(hSession)->m_method->get_response_attributes(pAttribs);
}


void eap::peer::set_response_attributes(
    _In_       EAP_SESSION_HANDLE  hSession,
    _In_ const EapAttributes       *pAttribs,
    _Out_      EapPeerMethodOutput *pEapOutput)
{
    assert(pEapOutput);
    pEapOutput->action              = static_cast<session*>(hSession)->m_method->set_response_attributes(pAttribs);
    pEapOutput->fAllowNotifications = TRUE;
}


//////////////////////////////////////////////////////////////////////
// eap::peer::session
//////////////////////////////////////////////////////////////////////

eap::peer::session::session(_In_ module &mod) :
    m_module(mod),
    m_cfg(mod),
    m_cred(mod, m_cfg),
    m_blob_cfg(NULL),
#if EAP_USE_NATIVE_CREDENTIAL_CACHE
    m_blob_cred(NULL),
#endif
    m_blob_ui_ctx(NULL)
{}


eap::peer::session::~session()
{
    if (m_blob_cfg)
        m_module.free_memory(m_blob_cfg);

#if EAP_USE_NATIVE_CREDENTIAL_CACHE
    if (m_blob_cred)
        m_module.free_memory(m_blob_cred);
#endif

    if (m_blob_ui_ctx)
        m_module.free_memory(m_blob_ui_ctx);
}
