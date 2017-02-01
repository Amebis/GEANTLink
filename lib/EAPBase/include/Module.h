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

namespace eap
{
    ///
    /// EAP module base class
    ///
    /// Provides basic services to EAP methods.
    ///
    class module;

    ///
    /// EAP peer base class
    ///
    /// A group of methods all EAP peers must or should implement.
    ///
    class peer;
}

#pragma once

#include "EAP.h"

#include <WinStd/Crypt.h>
#include <WinStd/ETW.h>
#include <WinStd/Win.h>

#include <Windows.h>
#include <eaptypes.h> // Must include after <Windows.h>
extern "C" {
#include <eapmethodpeerapis.h>
}
#include <sal.h>
#include <tchar.h>

#include <EventsETW.h> // Must include after <Windows.h>

#include <exception>


namespace eap
{
    class module
    {
        WINSTD_NONCOPYABLE(module)

    public:
        ///
        /// Constructs a module for the given EAP type
        ///
        /// \param[in] eap_method  EAP method type ID
        ///
        module(_In_ winstd::eap_type_t eap_method = winstd::eap_type_undefined);

        ///
        /// Destructs the module
        ///
        virtual ~module();

        /// \name Memory management
        /// @{

        ///
        /// Allocate a EAP_ERROR and fill it according to dwErrorCode
        ///
        EAP_ERROR* make_error(_In_ DWORD dwErrorCode, _In_opt_z_ LPCWSTR pszRootCauseString = NULL, _In_opt_z_ LPCWSTR pszRepairString = NULL, _In_opt_ DWORD dwReasonCode = 0, _In_opt_ LPCGUID pRootCauseGuid = NULL, _In_opt_ LPCGUID pRepairGuid = NULL, _In_opt_ LPCGUID pHelpLinkGuid = NULL) const;

        ///
        /// Allocate a EAP_ERROR and fill it according to exception
        ///
        EAP_ERROR* make_error(_In_ std::exception &err) const;

        ///
        /// Allocate BLOB
        ///
        BYTE* alloc_memory(_In_ size_t size);

        ///
        /// Free BLOB allocated with this peer
        ///
        void free_memory(_In_ BYTE *ptr);

        ///
        /// Free EAP_ERROR allocated with `make_error()` method
        ///
        void free_error_memory(_In_ EAP_ERROR *err);

        ///
        /// Makes a new method config
        ///
        virtual config_method* make_config_method();

        /// @}

        /// \name Logging
        /// @{

        ///
        /// Writes EAPMETHOD_TRACE_EVT_FN_CALL and returns auto event writer class
        ///
        /// \param[in] pszFnName  Function name
        ///
        /// \returns A new auto event writer that writes EAPMETHOD_TRACE_EVT_FN_RETURN event on destruction
        ///
        inline winstd::event_fn_auto get_event_fn_auto(_In_z_ LPCSTR pszFnName) const
        {
            return winstd::event_fn_auto(m_ep, &EAPMETHOD_TRACE_EVT_FN_CALL, &EAPMETHOD_TRACE_EVT_FN_RETURN, pszFnName);
        }

        ///
        /// Writes EAPMETHOD_TRACE_EVT_FN_CALL and returns auto event writer class
        ///
        /// \param[in] pszFnName  Function name
        ///
        /// \returns A new auto event writer that writes EAPMETHOD_TRACE_EVT_FN_RETURN_DWORD event on destruction
        ///
        inline winstd::event_fn_auto_ret<DWORD> get_event_fn_auto(_In_z_ LPCSTR pszFnName, _In_ DWORD &result) const
        {
            return winstd::event_fn_auto_ret<DWORD>(m_ep, &EAPMETHOD_TRACE_EVT_FN_CALL, &EAPMETHOD_TRACE_EVT_FN_RETURN_DWORD, pszFnName, result);
        }

        ///
        /// Logs error
        ///
        void log_error(_In_ const EAP_ERROR *err) const;

        ///
        /// Logs Unicode string config value
        ///
        inline void log_config(_In_z_ LPCWSTR name, _In_z_ LPCWSTR value) const
        {
            EVENT_DATA_DESCRIPTOR desc[] = {
                winstd::event_data(name ),
                winstd::event_data(value)
            };

            m_ep.write(&EAPMETHOD_TRACE_EVT_CFG_VALUE_UNICODE_STRING, _countof(desc), desc);
        }

        ///
        /// Logs string list config value
        ///
        template<class _Traits, class _Ax, class _Ax_list>
        inline void log_config(_In_z_ LPCWSTR name, _In_ const std::list<std::basic_string<char, _Traits, _Ax>, _Ax_list> &value) const
        {
            // Prepare a table of event data descriptors.
            std::vector<EVENT_DATA_DESCRIPTOR> desc;
            size_t count = value.size();
            desc.reserve(count + 2);
            desc.push_back(winstd::event_data(              name ));
            desc.push_back(winstd::event_data((unsigned int)count));
            for (auto v = value.cbegin(), v_end = value.cend(); v != v_end; ++v)
                desc.push_back(winstd::event_data(*v));

            m_ep.write(&EAPMETHOD_TRACE_EVT_CFG_VALUE_ANSI_STRING_ARRAY, (ULONG)desc.size(), desc.data());
        }

        ///
        /// Logs Unicode string list config value
        ///
        template<class _Traits, class _Ax, class _Ax_list>
        inline void log_config(_In_z_ LPCWSTR name, _In_ const std::list<std::basic_string<wchar_t, _Traits, _Ax>, _Ax_list> &value) const
        {
            // Prepare a table of event data descriptors.
            std::vector<EVENT_DATA_DESCRIPTOR> desc;
            size_t count = value.size();
            desc.reserve(count + 2);
            desc.push_back(winstd::event_data(              name ));
            desc.push_back(winstd::event_data((unsigned int)count));
            for (auto v = value.cbegin(), v_end = value.cend(); v != v_end; ++v)
                desc.push_back(winstd::event_data(*v));

            m_ep.write(&EAPMETHOD_TRACE_EVT_CFG_VALUE_UNICODE_STRING_ARRAY, (ULONG)desc.size(), desc.data());
        }

        ///
        /// Logs boolean config value
        ///
        inline void log_config(_In_z_ LPCWSTR name, _In_ bool value) const
        {
            EVENT_DATA_DESCRIPTOR desc[] = {
                winstd::event_data(     name ),
                winstd::event_data((int)value)
            };

            m_ep.write(&EAPMETHOD_TRACE_EVT_CFG_VALUE_BOOL, _countof(desc), desc);
        }

        ///
        /// Logs binary config value
        ///
        inline void log_config(_In_z_ LPCWSTR name, _In_bytecount_(size) const void *data, _In_ ULONG size) const
        {
            EVENT_DATA_DESCRIPTOR desc[] = {
                winstd::event_data(      name),
                winstd::event_data(      size),
                winstd::event_data(data, size)
            };

            m_ep.write(&EAPMETHOD_TRACE_EVT_CFG_VALUE_BINARY, _countof(desc), desc);
        }

        ///
        /// Discretely logs Unicode string config value
        ///
        /// If \c _DEBUG is set the value is masked.
        ///
        inline void log_config_discrete(_In_z_ LPCWSTR name, _In_z_ LPCWSTR value) const
        {
#ifdef __DANGEROUS__LOG_CONFIDENTIAL_DATA
#pragma message (__FILE__ "(" STRING(__LINE__) "): Warning: !!! DANGER !!!  Passwords and certificates will be logged as a clear-text. Please, consider undefining __DANGEROUS__LOG_CONFIDENTIAL_DATA.")
            log_config(name, value);
#else
            log_config(name, value ? value[0] ? L"********" : L"" : NULL);
#endif
        }

        ///
        /// Discretely logs binary config value
        ///
        /// If \c _DEBUG is set the value is masked.
        ///
        inline void log_config_discrete(_In_z_ LPCWSTR name, _In_bytecount_(size) const void *data, _In_ ULONG size) const
        {
#ifdef __DANGEROUS__LOG_CONFIDENTIAL_DATA
#pragma message (__FILE__ "(" STRING(__LINE__) "): Warning: !!! DANGER !!!  Passwords and certificates will be logged as a clear-text. Please, consider undefining __DANGEROUS__LOG_CONFIDENTIAL_DATA.")
            log_config(name, data, size);
#else
            log_config(name, data ? size ? L"********" : L"" : NULL);
#endif
        }

        ///
        /// Logs event
        ///
        inline void log_event(_In_ PCEVENT_DESCRIPTOR EventDescriptor, ...) const
        {
            va_list arg;
            va_start(arg, EventDescriptor);
            m_ep.write(EventDescriptor, arg);
            va_end(arg);
        }

        /// @}

        /// \name Encryption
        /// @{

        ///
        /// Encrypts data
        ///
        /// \param[in ] hProv  Handle of cryptographics provider
        /// \param[in ] data   Pointer to data to encrypt
        /// \param[in ] size   Size of \p data in bytes
        /// \param[out] enc    Encrypted data
        /// \param[out] hHash  Handle of hashing object
        ///
        /// \returns Encrypted data
        ///
        std::vector<unsigned char> encrypt(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size, _Out_opt_ HCRYPTHASH hHash = NULL) const;


        ///
        /// Encrypts a string
        ///
        /// \param[in ] hProv  Handle of cryptographics provider
        /// \param[in ] val    String to encrypt
        /// \param[out] hHash  Handle of hashing object
        ///
        /// \returns Encrypted data
        ///
        template<class _Elem, class _Traits, class _Ax>
        std::vector<unsigned char> encrypt(_In_ HCRYPTPROV hProv, _In_ const std::basic_string<_Elem, _Traits, _Ax> &val, _Out_opt_ HCRYPTHASH hHash = NULL) const
        {
            return encrypt(hProv, val.c_str(), val.length()*sizeof(_Elem), hHash);
        }


        ///
        /// Encrypts a wide string
        ///
        /// \param[in ] hProv  Handle of cryptographics provider
        /// \param[in ] val    String to encrypt
        /// \param[out] hHash  Handle of hashing object
        ///
        /// \returns Encrypted data
        ///
        template<class _Traits, class _Ax>
        std::vector<unsigned char> encrypt(_In_ HCRYPTPROV hProv, _In_ const std::basic_string<wchar_t, _Traits, _Ax> &val, _Out_opt_ HCRYPTHASH hHash = NULL) const
        {
            winstd::sanitizing_string val_utf8;
            WideCharToMultiByte(CP_UTF8, 0, val, val_utf8, NULL, NULL);
            return encrypt(hProv, val_utf8, hHash);
        }


        ///
        /// Encrypts data and add MD5 hash for integrity check
        ///
        /// \param[in ] hProv  Handle of cryptographics provider
        /// \param[in ] data   Pointer to data to encrypt
        /// \param[in ] size   Size of \p data in bytes
        ///
        /// \returns Encrypted data with 16B MD5 hash appended
        ///
        std::vector<unsigned char> encrypt_md5(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size) const;


        ///
        /// Encrypts a string and add MD5 hash for integrity check
        ///
        /// \param[in ] hProv  Handle of cryptographics provider
        /// \param[in ] val    String to encrypt
        ///
        /// \returns Encrypted data with 16B MD5 hash appended
        ///
        template<class _Elem, class _Traits, class _Ax>
        std::vector<unsigned char> encrypt_md5(_In_ HCRYPTPROV hProv, _In_ const std::basic_string<_Elem, _Traits, _Ax> &val) const
        {
            return encrypt_md5(hProv, val.c_str(), val.length()*sizeof(_Elem));
        }


        ///
        /// Encrypts a wide string and add MD5 hash for integrity check
        ///
        /// \param[in ] hProv  Handle of cryptographics provider
        /// \param[in ] val    String to encrypt
        ///
        /// \returns Encrypted data with 16B MD5 hash appended
        ///
        template<class _Traits, class _Ax>
        std::vector<unsigned char> encrypt_md5(_In_ HCRYPTPROV hProv, _In_ const std::basic_string<wchar_t, _Traits, _Ax> &val) const
        {
            winstd::sanitizing_string val_utf8;
            WideCharToMultiByte(CP_UTF8, 0, val, val_utf8, NULL, NULL);
            return encrypt_md5(hProv, val_utf8);
        }


        ///
        /// Decrypts data
        ///
        /// \param[in ] hProv  Handle of cryptographics provider
        /// \param[in ] data   Pointer to data to decrypt
        /// \param[in ] size   Size of \p data in bytes
        /// \param[out] hHash  Handle of hashing object
        ///
        /// \returns Decrypted data
        ///
        template<class _Ty, class _Ax>
        std::vector<_Ty, _Ax> decrypt(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size, _Out_opt_ HCRYPTHASH hHash = NULL) const
        {
            // Import the private RSA key.
            HRSRC res = FindResource(m_instance, MAKEINTRESOURCE(IDR_EAP_KEY_PRIVATE), RT_RCDATA);
            assert(res);
            HGLOBAL res_handle = LoadResource(m_instance, res);
            assert(res_handle);
            winstd::crypt_key key_rsa;
            std::unique_ptr<unsigned char[], winstd::LocalFree_delete<unsigned char[]> > keyinfo_data;
            DWORD keyinfo_size = 0;
            if (!CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, (const BYTE*)::LockResource(res_handle), ::SizeofResource(m_instance, res), CRYPT_DECODE_ALLOC_FLAG, NULL, &keyinfo_data, &keyinfo_size))
                throw winstd::win_runtime_error(__FUNCTION__ " CryptDecodeObjectEx failed.");
            if (!key_rsa.import(hProv, keyinfo_data.get(), keyinfo_size, NULL, 0))
                throw winstd::win_runtime_error(__FUNCTION__ " Private key import failed.");

            // Import the 256-bit AES session key.
            winstd::crypt_key key_aes;
            if (!CryptImportKey(hProv, reinterpret_cast<LPCBYTE>(data), 268, key_rsa, 0, &key_aes))
                throw winstd::win_runtime_error(__FUNCTION__ " CryptImportKey failed.");

            // Decrypt the data using AES session key.
            std::vector<unsigned char, winstd::sanitizing_allocator<unsigned char> > buf;
            buf.assign(reinterpret_cast<const unsigned char*>(data) + 268, reinterpret_cast<const unsigned char*>(data) + size);
            if (!CryptDecrypt(key_aes, hHash, TRUE, 0, buf))
                throw winstd::win_runtime_error(__FUNCTION__ " CryptDecrypt failed.");

            std::vector<_Ty, _Ax> buf_res;
            buf_res.assign(buf.cbegin(), buf.cend());
            return buf_res;
        }


        ///
        /// Decrypts a string
        ///
        /// \param[in ] hProv  Handle of cryptographics provider
        /// \param[in ] data   Pointer to data to decrypt
        /// \param[in ] size   Size of \p data in bytes
        /// \param[out] hHash  Handle of hashing object
        ///
        /// \returns Decrypted string
        ///
        template<class _Elem, class _Traits, class _Ax>
        std::basic_string<_Elem, _Traits, _Ax> decrypt_str(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size, _Out_opt_ HCRYPTHASH hHash = NULL) const
        {
            std::vector<_Elem, sanitizing_allocator<_Elem> > buf(std::move(decrypt(hProv, data, size, hHash)));
            return std::basic_string<_Elem, _Traits, _Ax>(buf.data(), buf.size());
        }


        ///
        /// Decrypts a wide string
        ///
        /// \param[in ] hProv  Handle of cryptographics provider
        /// \param[in ] data   Pointer to data to decrypt
        /// \param[in ] size   Size of \p data in bytes
        /// \param[out] hHash  Handle of hashing object
        ///
        /// \returns Decrypted string
        ///
        template<class _Traits, class _Ax>
        std::basic_string<wchar_t, _Traits, _Ax> decrypt_str(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size, _Out_opt_ HCRYPTHASH hHash = NULL) const
        {
            winstd::sanitizing_string buf(std::move(decrypt_str(hProv, data, size, hHash)));
            std::basic_string<wchar_t, _Traits, _Ax> dec;
            MultiByteToWideChar(CP_UTF8, 0, buf, dec);
            return dec;
        }


        ///
        /// Decrypts data with MD5 integrity check
        ///
        /// \param[in ] hProv  Handle of cryptographics provider
        /// \param[in ] data   Pointer to data with 16B MD5 hash appended to decrypt
        /// \param[in ] size   Size of \p data in bytes
        ///
        /// \returns Decrypted data
        ///
        template<class _Ty, class _Ax>
        std::vector<_Ty, _Ax> decrypt_md5(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size) const
        {
            // Create hash.
            winstd::crypt_hash hash;
            if (!hash.create(hProv, CALG_MD5))
                throw winstd::win_runtime_error(__FUNCTION__ " Creating MD5 hash failed.");
            DWORD dwHashSize;
            CryptGetHashParam(hash, HP_HASHSIZE, dwHashSize, 0);
            if (size < dwHashSize)
                throw std::invalid_argument(__FUNCTION__ " Encrypted data too short.");
            size_t enc_size = size - dwHashSize;

            // Decrypt data.
            std::vector<_Ty, _Ax> dec(std::move(decrypt<_Ty, _Ax>(hProv, data, enc_size, hash)));

            // Calculate MD5 hash and verify it.
            std::vector<unsigned char> hash_bin;
            if (!CryptGetHashParam(hash, HP_HASHVAL, hash_bin, 0))
                throw winstd::win_runtime_error(__FUNCTION__ " Calculating MD5 hash failed.");
            if (memcmp(reinterpret_cast<const unsigned char*>(data) + enc_size, hash_bin.data(), dwHashSize) != 0)
                throw std::invalid_argument(__FUNCTION__ " Invalid encrypted data.");

            return dec;
        }


        ///
        /// Decrypts a string with MD5 integrity check
        ///
        /// \param[in ] hProv  Handle of cryptographics provider
        /// \param[in ] data   Pointer to data with 16B MD5 hash appended to decrypt
        /// \param[in ] size   Size of \p data in bytes
        ///
        /// \returns Decrypted string
        ///
        template<class _Elem, class _Traits, class _Ax>
        std::basic_string<_Elem, _Traits, _Ax> decrypt_str_md5(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size) const
        {
            std::vector<_Elem, sanitizing_allocator<_Elem> > buf(std::move(decrypt_md5<_Elem, sanitizing_allocator<_Elem> >(hProv, data, size)));
            return std::basic_string<_Elem, _Traits, _Ax>(buf.data(), buf.size());
        }


        ///
        /// Decrypts a wide string with MD5 integrity check
        ///
        /// \param[in ] hProv  Handle of cryptographics provider
        /// \param[in ] data   Pointer to data with 16B MD5 hash appended to decrypt
        /// \param[in ] size   Size of \p data in bytes
        ///
        /// \returns Decrypted string
        ///
        template<class _Traits, class _Ax>
        std::basic_string<wchar_t, _Traits, _Ax> decrypt_str_md5(_In_ HCRYPTPROV hProv, _In_bytecount_(size) const void *data, _In_ size_t size) const
        {
            winstd::sanitizing_string buf(std::move(decrypt_str_md5<char, std::char_traits<char>, sanitizing_allocator<char> >(hProv, data, size)));
            std::basic_string<wchar_t, _Traits, _Ax> dec;
            MultiByteToWideChar(CP_UTF8, 0, buf, dec);
            return dec;
        }

        /// @}

        /// \name BLOB management
        /// @{

        ///
        /// Decrypts a BLOB
        ///
        /// \note When EAP_ENCRYPT_BLOBS is defined non-zero, the BLOB is decrypted; otherwise, it is copied only.
        ///
        /// \param[in   ] pDataIn       Pointer to encrypted BLOB
        /// \param[in   ] dwDataInSize  Size of \p pDataIn
        /// \param[out  ] ppEapError    Pointer to error descriptor in case of failure. Free using `module::free_error_memory()`.
        ///
        /// \returns
        /// - \c true if succeeded
        /// - \c false otherwise. See \p ppEapError for details.
        ///
        /// \returns Encrypted BLOB
        ///
        sanitizing_blob unpack(
            _In_count_(dwDataInSize) const BYTE  *pDataIn,
            _In_                           DWORD dwDataInSize)
        {
#if EAP_ENCRYPT_BLOBS
            // Prepare cryptographics provider.
            winstd::crypt_prov cp;
            if (!cp.create(NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
                throw winstd::win_runtime_error(__FUNCTION__ " CryptAcquireContext failed.");

            // Decrypt data.
            return std::move(decrypt_md5<unsigned char, winstd::sanitizing_allocator<unsigned char> >(cp, pDataIn, dwDataInSize));
#else
            return sanitizing_blob(pDataIn, pDataIn + dwDataInSize);
#endif
        }


        ///
        /// Decrypts and unpacks the BLOB
        ///
        /// \note When EAP_ENCRYPT_BLOBS is defined non-zero, the BLOB is decrypted and unpacked to the \p record; otherwise, it is unpacked to the \p record only.
        ///
        /// \param[out] record        Object to unpack to
        /// \param[in ] pDataIn       Pointer to encrypted BLOB
        /// \param[in ] dwDataInSize  Size of \p pDataIn
        ///
        template<class T>
        void unpack(
            _Out_                          T     &record,
            _In_count_(dwDataInSize) const BYTE  *pDataIn,
            _In_                           DWORD dwDataInSize)
        {
#if EAP_ENCRYPT_BLOBS
            // Prepare cryptographics provider.
            winstd::crypt_prov cp;
            if (!cp.create(NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
                throw winstd::win_runtime_error(__FUNCTION__ " CryptAcquireContext failed.");

            // Decrypt data.
            std::vector<unsigned char, winstd::sanitizing_allocator<unsigned char> > data(std::move(decrypt_md5<unsigned char, winstd::sanitizing_allocator<unsigned char> >(cp, pDataIn, dwDataInSize)));

            cursor_in cursor = { data.data(), data.data() + data.size() };
#else
            cursor_in cursor = { pDataIn, pDataIn + dwDataInSize };
#endif
            cursor >> record;
            assert(cursor.ptr == cursor.ptr_end);
        }


        ///
        /// Encrypts a BLOB
        ///
        /// \note When EAP_ENCRYPT_BLOBS is defined non-zero, the BLOB is encrypted; otherwise, it is copied only.
        ///
        /// \param[in ] data            BLOB to encrypt
        /// \param[out] ppDataOut       Pointer to pointer to receive encrypted BLOB. Pointer must be freed using `module::free_memory()`.
        /// \param[out] pdwDataOutSize  Pointer to \p ppDataOut size
        ///
        void pack(
            _In_  const sanitizing_blob &data,
            _Out_       BYTE            **ppDataOut,
            _Out_       DWORD           *pdwDataOutSize)
        {
            assert(ppDataOut);
            assert(pdwDataOutSize);

#if EAP_ENCRYPT_BLOBS
            // Prepare cryptographics provider.
            winstd::crypt_prov cp;
            if (!cp.create(NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
                throw winstd::win_runtime_error(__FUNCTION__ " CryptAcquireContext failed.");

            // Encrypt BLOB.
            std::vector<unsigned char> data_enc(std::move(encrypt_md5(cp, data.data(), data.size())));

            // Copy encrypted BLOB to output.
            *pdwDataOutSize = (DWORD)data_enc.size();
            *ppDataOut = alloc_memory(*pdwDataOutSize);
            memcpy(*ppDataOut, data_enc.data(), *pdwDataOutSize);
#else
            // Allocate and copy BLOB.
            *pdwDataOutSize = (DWORD)data.size();
            memcpy(*ppDataOut = alloc_memory(*pdwDataOutSize), data.data(), *pdwDataOutSize);
#endif
        }


        ///
        /// Packs and encrypts to the BLOB
        ///
        /// \note When EAP_ENCRYPT_BLOBS is defined non-zero, the \p record is packed and encrypted; otherwise, it is packed to an unencrypted BLOB only.
        ///
        /// \param[in ] record          Object to pack
        /// \param[out] ppDataOut       Pointer to pointer to receive encrypted BLOB. Pointer must be freed using `module::free_memory()`.
        /// \param[out] pdwDataOutSize  Pointer to \p ppDataOut size
        ///
        template<class T>
        void pack(
            _In_  const T     &record,
            _Out_       BYTE  **ppDataOut,
            _Out_       DWORD *pdwDataOutSize)
        {
            assert(ppDataOut);
            assert(pdwDataOutSize);

#if EAP_ENCRYPT_BLOBS
            // Allocate BLOB.
            std::vector<unsigned char, winstd::sanitizing_allocator<unsigned char> > data;
            data.resize(pksizeof(record));

            // Pack to BLOB.
            cursor_out cursor = { data.data(), data.data() + data.size() };
            cursor << record;
            assert(cursor.ptr == cursor.ptr_end);

            // Prepare cryptographics provider.
            winstd::crypt_prov cp;
            if (!cp.create(NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
                throw winstd::win_runtime_error(__FUNCTION__ " CryptAcquireContext failed.");

            // Encrypt BLOB.
            std::vector<unsigned char> data_enc(std::move(encrypt_md5(cp, data.data(), data.size())));

            // Copy encrypted BLOB to output.
            *pdwDataOutSize = (DWORD)data_enc.size();
            *ppDataOut = alloc_memory(*pdwDataOutSize);
            memcpy(*ppDataOut, data_enc.data(), *pdwDataOutSize);
#else
            // Allocate BLOB.
            *pdwDataOutSize = (DWORD)pksizeof(record);
            *ppDataOut = alloc_memory(*pdwDataOutSize);

            // Pack to BLOB.
            cursor_out cursor = { *ppDataOut, *ppDataOut + *pdwDataOutSize };
            cursor << record;
            assert(cursor.ptr == cursor.ptr_end);
            *pdwDataOutSize = cursor.ptr - *ppDataOut;
#endif
        }

        /// @}

    public:
        HINSTANCE m_instance;                   ///< Windows module instance
        const winstd::eap_type_t m_eap_method;  ///< EAP method type

    protected:
        winstd::heap m_heap;                    ///< Heap
        mutable winstd::event_provider m_ep;    ///< Event Provider
    };


    class peer : public module
    {
        WINSTD_NONCOPYABLE(peer)

    public:
        ///
        /// Constructs a EAP peer module for the given EAP type
        ///
        /// \param[in] eap_method  EAP method type ID
        ///
        peer(_In_ winstd::eap_type_t eap_method);

        ///
        /// Initializes an EAP peer method for EapHost.
        ///
        /// \sa [EapPeerGetInfo function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363613.aspx)
        ///
        virtual void initialize() = 0;

        ///
        /// Shuts down the EAP method and prepares to unload its corresponding DLL.
        ///
        /// \sa [EapPeerShutdown function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363627.aspx)
        ///
        virtual void shutdown() = 0;

        ///
        /// Returns the user data and user identity after being called by EapHost.
        ///
        /// \sa [EapPeerGetIdentity function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363607.aspx)
        ///
        virtual void get_identity(
            _In_                                   DWORD  dwFlags,
            _In_count_(dwConnectionDataSize) const BYTE   *pConnectionData,
            _In_                                   DWORD  dwConnectionDataSize,
            _In_count_(dwUserDataSize)       const BYTE   *pUserData,
            _In_                                   DWORD  dwUserDataSize,
            _Inout_                                BYTE   **ppUserDataOut,
            _Inout_                                DWORD  *pdwUserDataOutSize,
            _In_                                   HANDLE hTokenImpersonateUser,
            _Inout_                                BOOL   *pfInvokeUI,
            _Inout_                                WCHAR  **ppwszIdentity) = 0;

        ///
        /// Defines the implementation of an EAP method-specific function that retrieves the properties of an EAP method given the connection and user data.
        ///
        /// \sa [EapPeerGetMethodProperties function](https://msdn.microsoft.com/en-us/library/windows/desktop/hh706636.aspx)
        ///
        virtual void get_method_properties(
            _In_                                   DWORD                     dwVersion,
            _In_                                   DWORD                     dwFlags,
            _In_                                   HANDLE                    hUserImpersonationToken,
            _In_count_(dwConnectionDataSize) const BYTE                      *pConnectionData,
            _In_                                   DWORD                     dwConnectionDataSize,
            _In_count_(dwUserDataSize)       const BYTE                      *pUserData,
            _In_                                   DWORD                     dwUserDataSize,
            _Inout_                                EAP_METHOD_PROPERTY_ARRAY *pMethodPropertyArray) = 0;

        ///
        /// Converts XML into the configuration BLOB. The XML based credentials can come from group policy or from a system administrator.
        ///
        /// \sa [EapPeerCredentialsXml2Blob function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363603.aspx)
        ///
        virtual void credentials_xml2blob(
            _In_                                   DWORD       dwFlags,
            _In_                                   IXMLDOMNode *pConfigRoot,
            _In_count_(dwConnectionDataSize) const BYTE        *pConnectionData,
            _In_                                   DWORD       dwConnectionDataSize,
            _Inout_                                BYTE        **ppCredentialsOut,
            _Inout_                                DWORD       *pdwCredentialsOutSize) = 0;

        ///
        /// Defines the implementation of an EAP method-specific function that obtains the EAP Single-Sign-On (SSO) credential input fields for an EAP method.
        ///
        /// \sa [EapPeerQueryCredentialInputFields function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363622.aspx)
        ///
        virtual void query_credential_input_fields(
            _In_                                   HANDLE                       hUserImpersonationToken,
            _In_                                   DWORD                        dwFlags,
            _In_                                   DWORD                        dwConnectionDataSize,
            _In_count_(dwConnectionDataSize) const BYTE                         *pConnectionData,
            _Inout_                                EAP_CONFIG_INPUT_FIELD_ARRAY *pEapConfigInputFieldsArray) const;

        ///
        /// Defines the implementation of an EAP method function that obtains the user BLOB data provided in an interactive Single-Sign-On (SSO) UI raised on the supplicant.
        ///
        /// \sa [EapPeerQueryUserBlobFromCredentialInputFields function](https://msdn.microsoft.com/en-us/library/windows/desktop/bb204697.aspx)
        ///
        virtual void query_user_blob_from_credential_input_fields(
            _In_                                   HANDLE                       hUserImpersonationToken,
            _In_                                   DWORD                        dwFlags,
            _In_                                   DWORD                        dwConnectionDataSize,
            _In_count_(dwConnectionDataSize) const BYTE                         *pConnectionData,
            _In_                             const EAP_CONFIG_INPUT_FIELD_ARRAY *pEapConfigInputFieldArray,
            _Inout_                                DWORD                        *pdwUsersBlobSize,
            _Inout_                                BYTE                         **ppUserBlob) const;

        ///
        /// Defines the implementation of an EAP method API that provides the input fields for interactive UI components to be raised on the supplicant.
        ///
        /// \sa [EapPeerQueryInteractiveUIInputFields function](https://msdn.microsoft.com/en-us/library/windows/desktop/bb204695.aspx)
        ///
        virtual void query_interactive_ui_input_fields(
            _In_                                  DWORD                   dwVersion,
            _In_                                  DWORD                   dwFlags,
            _In_                                  DWORD                   dwUIContextDataSize,
            _In_count_(dwUIContextDataSize) const BYTE                    *pUIContextData,
            _Inout_                               EAP_INTERACTIVE_UI_DATA *pEapInteractiveUIData) const;

        ///
        /// Converts user information into a user BLOB that can be consumed by EapHost run-time functions.
        ///
        /// \sa [EapPeerQueryUIBlobFromInteractiveUIInputFields function](https://msdn.microsoft.com/en-us/library/windows/desktop/bb204696.aspx)
        ///
        virtual void query_ui_blob_from_interactive_ui_input_fields(
            _In_                                  DWORD                   dwVersion,
            _In_                                  DWORD                   dwFlags,
            _In_                                  DWORD                   dwUIContextDataSize,
            _In_count_(dwUIContextDataSize) const BYTE                    *pUIContextData,
            _In_                            const EAP_INTERACTIVE_UI_DATA *pEapInteractiveUIData,
            _Inout_                               DWORD                   *pdwDataFromInteractiveUISize,
            _Inout_                               BYTE                    **ppDataFromInteractiveUI) const;

        /// \name Session management
        /// @{

        ///
        /// Starts an EAP authentication session on the peer EapHost using the EAP method.
        ///
        /// \sa [EapPeerBeginSession function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363600.aspx)
        ///
        /// \returns Session handle
        ///
        virtual EAP_SESSION_HANDLE begin_session(
            _In_                                   DWORD         dwFlags,
            _In_                             const EapAttributes *pAttributeArray,
            _In_                                   HANDLE        hTokenImpersonateUser,
            _In_count_(dwConnectionDataSize) const BYTE          *pConnectionData,
            _In_                                   DWORD         dwConnectionDataSize,
            _In_count_(dwUserDataSize)       const BYTE          *pUserData,
            _In_                                   DWORD         dwUserDataSize,
            _In_                                   DWORD         dwMaxSendPacketSize) = 0;

        ///
        /// Ends an EAP authentication session for the EAP method.
        ///
        /// \sa [EapPeerEndSession function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363604.aspx)
        ///
        virtual void end_session(_In_ EAP_SESSION_HANDLE hSession) = 0;

        ///
        /// Processes a packet received by EapHost from a supplicant.
        ///
        /// \sa [EapPeerProcessRequestPacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363621.aspx)
        ///
        virtual void process_request_packet(
            _In_                                       EAP_SESSION_HANDLE  hSession,
            _In_bytecount_(dwReceivedPacketSize) const EapPacket           *pReceivedPacket,
            _In_                                       DWORD               dwReceivedPacketSize,
            _Out_                                      EapPeerMethodOutput *pEapOutput) = 0;

        ///
        /// Obtains a response packet from the EAP method.
        ///
        /// \sa [EapPeerGetResponsePacket function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363610.aspx)
        ///
        virtual void get_response_packet(
            _In_                               EAP_SESSION_HANDLE hSession,
            _Inout_bytecap_(*dwSendPacketSize) EapPacket          *pSendPacket,
            _Inout_                            DWORD              *pdwSendPacketSize) = 0;

        ///
        /// Obtains the result of an authentication session from the EAP method.
        ///
        /// \sa [EapPeerGetResult function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363611.aspx)
        ///
        virtual void get_result(
            _In_    EAP_SESSION_HANDLE        hSession,
            _In_    EapPeerMethodResultReason reason,
            _Inout_ EapPeerMethodResult       *pResult) = 0;

        ///
        /// Obtains the user interface context from the EAP method.
        ///
        /// \note This function is always followed by the `EapPeerInvokeInteractiveUI()` function, which is followed by the `EapPeerSetUIContext()` function.
        ///
        /// \sa [EapPeerGetUIContext function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363612.aspx)
        ///
        virtual void get_ui_context(
            _In_    EAP_SESSION_HANDLE hSession,
            _Inout_ BYTE               **ppUIContextData,
            _Inout_ DWORD              *pdwUIContextDataSize) = 0;

        ///
        /// Provides a user interface context to the EAP method.
        ///
        /// \note This function is called after the UI has been raised through the `EapPeerGetUIContext()` function.
        ///
        /// \sa [EapPeerSetUIContext function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363626.aspx)
        ///
        virtual void set_ui_context(
            _In_                                  EAP_SESSION_HANDLE  hSession,
            _In_count_(dwUIContextDataSize) const BYTE                *pUIContextData,
            _In_                                  DWORD               dwUIContextDataSize,
            _Out_                                 EapPeerMethodOutput *pEapOutput) = 0;

        ///
        /// Obtains an array of EAP response attributes from the EAP method.
        ///
        /// \sa [EapPeerGetResponseAttributes function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363609.aspx)
        ///
        virtual void get_response_attributes(
            _In_    EAP_SESSION_HANDLE hSession,
            _Inout_ EapAttributes      *pAttribs) = 0;

        ///
        /// Provides an updated array of EAP response attributes to the EAP method.
        ///
        /// \sa [EapPeerSetResponseAttributes function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363625.aspx)
        ///
        virtual void set_response_attributes(
            _In_       EAP_SESSION_HANDLE  hSession,
            _In_ const EapAttributes       *pAttribs,
            _Out_      EapPeerMethodOutput *pEapOutput) = 0;

        /// @}
    };
}
