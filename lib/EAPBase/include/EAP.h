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

#define IDR_EAP_KEY_PUBLIC  1
#define IDR_EAP_KEY_PRIVATE 2

#ifndef EAP_ENCRYPT_BLOBS
#define EAP_ENCRYPT_BLOBS 1
#endif

#if !defined(RC_INVOKED) && !defined(MIDL_PASS)

#include <WinStd/Crypt.h>

#include <sal.h>

#include <list>
#include <memory>
#include <string>
#include <vector>

namespace eap
{
    ///
    /// EAP method numbers
    ///
    /// \sa [Extensible Authentication Protocol (EAP) Registry (Chapter: Method Types)](https://www.iana.org/assignments/eap-numbers/eap-numbers.xhtml#eap-numbers-4)
    ///
    enum type_t;
}

namespace eapserial
{
    ///
    /// Output BLOB cursor
    ///
    struct cursor_out;

    ///
    /// Input BLOB cursor
    ///
    struct cursor_in;

    ///
    /// Packs a boolean
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     Variable with data to pack
    ///
    inline void pack(_Inout_ cursor_out &cursor, _In_ const bool &val);

    ///
    /// Returns packed size of a boolean
    ///
    /// \param[in] val  Data to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    inline size_t get_pk_size(_In_ const bool &val);

    ///
    /// Unpacks a boolean
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     Variable to receive unpacked value
    ///
    inline void unpack(_Inout_ cursor_in &cursor, _Out_ bool &val);

    ///
    /// Packs a byte
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     Variable with data to pack
    ///
    inline void pack(_Inout_ cursor_out &cursor, _In_ const unsigned char &val);

    ///
    /// Returns packed size of a byte
    ///
    /// \param[in] val  Data to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    inline size_t get_pk_size(_In_ const unsigned char &val);

    ///
    /// Unpacks a byte
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     Variable to receive unpacked value
    ///
    inline void unpack(_Inout_ cursor_in &cursor, _Out_ unsigned char &val);

    ///
    /// Packs an unsigned int
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     Variable with data to pack
    ///
    inline void pack(_Inout_ cursor_out &cursor, _In_ const unsigned int &val);

    ///
    /// Returns packed size of an unsigned int
    ///
    /// \param[in] val  Data to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    inline size_t get_pk_size(_In_ const unsigned int &val);

    ///
    /// Unpacks an unsigned int
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     Variable to receive unpacked value
    ///
    inline void unpack(_Inout_ cursor_in &cursor, _Out_ unsigned int &val);

#ifdef _WIN64
    ///
    /// Packs a size_t
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     Variable with data to pack
    ///
    inline void pack(_Inout_ cursor_out &cursor, _In_ const size_t &val);

    ///
    /// Returns packed size of a size_t
    ///
    /// \param[in] val  Data to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    inline size_t get_pk_size(_In_ const size_t &val);

    ///
    /// Unpacks a size_t
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     Variable to receive unpacked value
    ///
    inline void unpack(_Inout_ cursor_in &cursor, _Out_ size_t &val);
#endif

    ///
    /// Packs a string
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     String to pack
    ///
    template<class _Elem, class _Traits, class _Ax> inline void pack(_Inout_ cursor_out &cursor, _In_ const std::basic_string<_Elem, _Traits, _Ax> &val);

    ///
    /// Returns packed size of a string
    ///
    /// \param[in] val  String to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    template<class _Elem, class _Traits, class _Ax> inline size_t get_pk_size(const std::basic_string<_Elem, _Traits, _Ax> &val);

    ///
    /// Unpacks a string
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     String to unpack to
    ///
    template<class _Elem, class _Traits, class _Ax> inline void unpack(_Inout_ cursor_in &cursor, _Out_ std::basic_string<_Elem, _Traits, _Ax> &val);

    ///
    /// Packs a wide string
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     String to pack
    ///
    template<class _Traits, class _Ax> inline void pack(_Inout_ cursor_out &cursor, _In_ const std::basic_string<wchar_t, _Traits, _Ax> &val);

    ///
    /// Returns packed size of a wide string
    ///
    /// \param[in] val  String to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    template<class _Traits, class _Ax> inline size_t get_pk_size(const std::basic_string<wchar_t, _Traits, _Ax> &val);

    ///
    /// Unpacks a wide string
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     String to unpack to
    ///
    template<class _Traits, class _Ax> inline void unpack(_Inout_ cursor_in &cursor, _Out_ std::basic_string<wchar_t, _Traits, _Ax> &val);

    ///
    /// Packs a vector
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     Vector to pack
    ///
    template<class _Ty, class _Ax> inline void pack(_Inout_ cursor_out &cursor, _In_ const std::vector<_Ty, _Ax> &val);

    ///
    /// Returns packed size of a vector
    ///
    /// \param[in] val  Vector to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    template<class _Ty, class _Ax> inline size_t get_pk_size(const std::vector<_Ty, _Ax> &val);

    ///
    /// Unpacks a vector
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     Vector to unpack to
    ///
    template<class _Ty, class _Ax> inline void unpack(_Inout_ cursor_in &cursor, _Out_ std::vector<_Ty, _Ax> &val);

    ///
    /// Packs a list
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     List to pack
    ///
    template<class _Ty, class _Ax> inline void pack(_Inout_ cursor_out &cursor, _In_ const std::list<_Ty, _Ax> &val);

    ///
    /// Returns packed size of a list
    ///
    /// \param[in] val  List to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    template<class _Ty, class _Ax> inline size_t get_pk_size(const std::list<_Ty, _Ax> &val);

    ///
    /// Unpacks a list
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     List to unpack to
    ///
    template<class _Ty, class _Ax> inline void unpack(_Inout_ cursor_in &cursor, _Out_ std::list<_Ty, _Ax> &val);

    ///
    /// Packs a std::unique_ptr
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     std::unique_ptr to pack
    ///
    template<class _Ty, class _Dx> inline void pack(_Inout_ cursor_out &cursor, _In_ const std::unique_ptr<_Ty, _Dx> &val);

    ///
    /// Returns packed size of a std::unique_ptr
    ///
    /// \param[in] val  std::unique_ptr to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    template<class _Ty, class _Dx> inline size_t get_pk_size(const std::unique_ptr<_Ty, _Dx> &val);

    /////
    ///// Unpacks a std::unique_ptr
    /////
    ///// \note Not generally unpackable, since we do not know, how to create a new instance of unique_ptr.
    /////
    ///// \param[inout] cursor  Memory cursor
    ///// \param[out]   val     std::unique_ptr to unpack to
    /////
    //template<class _Ty, class _Dx> inline void unpack(_Inout_ cursor_in &cursor, _Out_ std::unique_ptr<_Ty, _Dx> &val);

    ///
    /// Packs a certificate context
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     Certificate context to pack
    ///
    inline void pack(_Inout_ cursor_out &cursor, _In_ const winstd::cert_context &val);

    ///
    /// Returns packed size of a certificate context
    ///
    /// \param[in] val  Certificate context to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    inline size_t get_pk_size(const winstd::cert_context &val);

    ///
    /// Unpacks a certificate context
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     Certificate context to unpack to
    ///
    inline void unpack(_Inout_ cursor_in &cursor, _Out_ winstd::cert_context &val);

    ///
    /// Packs an EAP method type
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[in]    val     EAP method type to pack
    ///
    inline void pack(_Inout_ cursor_out &cursor, _In_ const eap::type_t &val);

    ///
    /// Returns packed size of an EAP method type
    ///
    /// \param[in] val  EAP method type to pack
    ///
    /// \returns Size of data when packed (in bytes)
    ///
    inline size_t get_pk_size(const eap::type_t &val);

    ///
    /// Unpacks an EAP method type
    ///
    /// \param[inout] cursor  Memory cursor
    /// \param[out]   val     EAP method type to unpack to
    ///
    inline void unpack(_Inout_ cursor_in &cursor, _Out_ eap::type_t &val);
}

#pragma once


namespace eap
{
    enum type_t {
        type_undefined = 0,      ///< Undefined EAP type
        type_tls       = 13,     ///< EAP-TLS
        type_ttls      = 21,     ///< EAP-TTLS
        type_peap      = 25,     ///< EAP-PEAP
        type_mschapv2  = 26,     ///< EAP-MSCHAPv2
        type_pap       = 192,    ///< PAP (Not actually an EAP method; Moved to the Unassigned area)
    };
}


namespace eapserial
{
    struct cursor_out
    {
        typedef unsigned char *ptr_type;

        ptr_type ptr;       ///< Pointer to first data unwritten
        ptr_type ptr_end;   ///< Pointer to the end of available memory
    };

    struct cursor_in
    {
        typedef const unsigned char *ptr_type;

        ptr_type ptr;       ///< Pointer to first data unread
        ptr_type ptr_end;   ///< Pointer to the end of BLOB
    };


    inline void pack(_Inout_ cursor_out &cursor, _In_ const bool &val)
    {
        cursor_out::ptr_type ptr_end = cursor.ptr + 1;
        assert(ptr_end <= cursor.ptr_end);
        *cursor.ptr = val ? 1 : 0;
        cursor.ptr = ptr_end;
    }


    inline size_t get_pk_size(_In_ const bool &val)
    {
        UNREFERENCED_PARAMETER(val);
        return sizeof(unsigned char);
    }


    inline void unpack(_Inout_ cursor_in &cursor, _Out_ bool &val)
    {
        cursor_in::ptr_type ptr_end = cursor.ptr + 1;
        assert(ptr_end <= cursor.ptr_end);
        val = *cursor.ptr ? true : false;
        cursor.ptr = ptr_end;
    }


    inline void pack(_Inout_ cursor_out &cursor, _In_ const unsigned char &val)
    {
        cursor_out::ptr_type ptr_end = cursor.ptr + 1;
        assert(ptr_end <= cursor.ptr_end);
        *cursor.ptr = val;
        cursor.ptr = ptr_end;
    }


    inline size_t get_pk_size(_In_ const unsigned char &val)
    {
        UNREFERENCED_PARAMETER(val);
        return sizeof(unsigned char);
    }


    inline void unpack(_Inout_ cursor_in &cursor, _Out_ unsigned char &val)
    {
        cursor_in::ptr_type ptr_end = cursor.ptr + 1;
        assert(ptr_end <= cursor.ptr_end);
        val = *cursor.ptr;
        cursor.ptr = ptr_end;
    }


    inline void pack(_Inout_ cursor_out &cursor, _In_ const unsigned int &val)
    {
        cursor_out::ptr_type ptr_end = cursor.ptr + sizeof(unsigned int);
        assert(ptr_end <= cursor.ptr_end);
        *(unsigned int*)cursor.ptr = val;
        cursor.ptr = ptr_end;
    }


    inline size_t get_pk_size(_In_ const unsigned int &val)
    {
        UNREFERENCED_PARAMETER(val);
        return sizeof(unsigned int);
    }


    inline void unpack(_Inout_ cursor_in &cursor, _Out_ unsigned int &val)
    {
        cursor_in::ptr_type ptr_end = cursor.ptr + sizeof(unsigned int);
        assert(ptr_end <= cursor.ptr_end);
        val = *(unsigned int*)cursor.ptr;
        cursor.ptr = ptr_end;
    }


#ifdef _WIN64
    inline void pack(_Inout_ cursor_out &cursor, _In_ const size_t &val)
    {
        cursor_out::ptr_type ptr_end = cursor.ptr + sizeof(size_t);
        assert(ptr_end <= cursor.ptr_end);
        *(size_t*)cursor.ptr = val;
        cursor.ptr = ptr_end;
    }


    inline size_t get_pk_size(_In_ const size_t &val)
    {
        UNREFERENCED_PARAMETER(val);
        return sizeof(size_t);
    }


    inline void unpack(_Inout_ cursor_in &cursor, _Out_ size_t &val)
    {
        cursor_in::ptr_type ptr_end = cursor.ptr + sizeof(size_t);
        assert(ptr_end <= cursor.ptr_end);
        val = *(size_t*)cursor.ptr;
        cursor.ptr = ptr_end;
    }
#endif


    template<class _Elem, class _Traits, class _Ax>
    inline void pack(_Inout_ cursor_out &cursor, _In_ const std::basic_string<_Elem, _Traits, _Ax> &val)
    {
        std::basic_string<_Elem, _Traits, _Ax>::size_type count = val.length();
        assert(strlen(val.c_str()) == count); // String should not contain zero terminators.
        size_t size = sizeof(_Elem)*(count + 1);
        cursor_out::ptr_type ptr_end = cursor.ptr + size;
        assert(ptr_end <= cursor.ptr_end);
        memcpy(cursor.ptr, (const _Elem*)val.c_str(), size);
        cursor.ptr = ptr_end;
    }


    template<class _Elem, class _Traits, class _Ax>
    inline size_t get_pk_size(const std::basic_string<_Elem, _Traits, _Ax> &val)
    {
        return sizeof(_Elem)*(val.length() + 1);
    }


    template<class _Elem, class _Traits, class _Ax>
    inline void unpack(_Inout_ cursor_in &cursor, _Out_ std::basic_string<_Elem, _Traits, _Ax> &val)
    {
        size_t count_max = cursor.ptr_end - cursor.ptr;
        std::basic_string<_Elem, _Traits, _Ax>::size_type count = strnlen((const _Elem*&)cursor.ptr, count_max);
        assert(count < count_max); // String should be zero terminated.
        val.assign((const _Elem*&)cursor.ptr, count);
        cursor.ptr += sizeof(_Elem)*(count + 1);
    }


    template<class _Traits, class _Ax>
    inline void pack(_Inout_ cursor_out &cursor, _In_ const std::basic_string<wchar_t, _Traits, _Ax> &val)
    {
        std::string val_utf8;
        WideCharToMultiByte(CP_UTF8, 0, val.c_str(), (int)val.length(), val_utf8, NULL, NULL);
        pack(cursor, val_utf8);
    }


    template<class _Traits, class _Ax>
    inline size_t get_pk_size(const std::basic_string<wchar_t, _Traits, _Ax> &val)
    {
        return sizeof(char)*(WideCharToMultiByte(CP_UTF8, 0, val.c_str(), (int)val.length(), NULL, 0, NULL, NULL) + 1);
    }


    template<class _Traits, class _Ax>
    inline void unpack(_Inout_ cursor_in &cursor, _Out_ std::basic_string<wchar_t, _Traits, _Ax> &val)
    {
        std::string val_utf8;
        unpack(cursor, val_utf8);
        MultiByteToWideChar(CP_UTF8, 0, val_utf8.c_str(), (int)val_utf8.length(), val);
    }


    template<class _Ty, class _Ax>
    inline void pack(_Inout_ cursor_out &cursor, _In_ const std::vector<_Ty, _Ax> &val)
    {
        std::vector<_Ty, _Ax>::size_type count = val.size();
        pack(cursor, count);

        // Since we do not know wheter vector elements are primitives or objects, iterate instead of memcpy.
        // For performance critical vectors of flat opaque data types write specialized template instantiation.
        for (std::vector<_Ty, _Ax>::size_type i = 0; i < count; i++)
            pack(cursor, val[i]);
    }


    template<class _Ty, class _Ax>
    inline size_t get_pk_size(const std::vector<_Ty, _Ax> &val)
    {
        // Since we do not know wheter vector elements are primitives or objects, iterate instead of sizeof().
        // For performance critical vectors of flat opaque data types write specialized template instantiation.
        std::vector<_Ty, _Ax>::size_type count = val.size();
        size_t size = get_pk_size(count);
        for (std::vector<_Ty, _Ax>::size_type i = 0; i < count; i++)
            size += get_pk_size(val[i]);
        return size;
    }


    template<class _Ty, class _Ax>
    inline void unpack(_Inout_ cursor_in &cursor, _Out_ std::vector<_Ty, _Ax> &val)
    {
        std::vector<_Ty, _Ax>::size_type count;
        unpack(cursor, count);

        // Since we do not know wheter vector elements are primitives or objects, iterate instead of assign().
        // For performance critical vectors of flat opaque data types write specialized template instantiation.
        val.clear();
        val.reserve(count);
        for (std::vector<_Ty, _Ax>::size_type i = 0; i < count; i++) {
            _Ty el;
            unpack(cursor, el);
            val.push_back(el);
        }
    }


    template<class _Ty, class _Ax>
    inline void pack(_Inout_ cursor_out &cursor, _In_ const std::list<_Ty, _Ax> &val)
    {
        std::list<_Ty, _Ax>::size_type count = val.size();
        pack(cursor, count);

        // Since we do not know wheter list elements are primitives or objects, iterate instead of memcpy.
        // For performance critical vectors of flat opaque data types write specialized template instantiation.
        for (std::list<_Ty, _Ax>::const_iterator i = val.cbegin(), i_end = val.cend(); i != i_end; ++i)
            pack(cursor, *i);
    }


    template<class _Ty, class _Ax>
    inline size_t get_pk_size(const std::list<_Ty, _Ax> &val)
    {
        // Since we do not know wheter list elements are primitives or objects, iterate instead of sizeof().
        // For performance critical vectors of flat opaque data types write specialized template instantiation.
        std::list<_Ty, _Ax>::size_type count = val.size();
        size_t size = get_pk_size(count);
        for (std::list<_Ty, _Ax>::const_iterator i = val.cbegin(), i_end = val.cend(); i != i_end; ++i)
            size += get_pk_size(*i);
        return size;
    }


    template<class _Ty, class _Ax>
    inline void unpack(_Inout_ cursor_in &cursor, _Out_ std::list<_Ty, _Ax> &val)
    {
        std::list<_Ty, _Ax>::size_type count;
        unpack(cursor, count);

        // Since we do not know wheter list elements are primitives or objects, iterate instead of assign().
        // For performance critical vectors of flat opaque data types write specialized template instantiation.
        val.clear();
        for (std::list<_Ty, _Ax>::size_type i = 0; i < count; i++) {
            _Ty el;
            unpack(cursor, el);
            val.push_back(el);
        }
    }


    template<class _Ty, class _Dx>
    inline void pack(_Inout_ cursor_out &cursor, _In_ const std::unique_ptr<_Ty, _Dx> &val)
    {
        if (val) {
            pack(cursor, true);
            pack(cursor, *val);
        } else
            pack(cursor, false);
    }


    template<class _Ty, class _Dx>
    inline size_t get_pk_size(const std::unique_ptr<_Ty, _Dx> &val)
    {
        return
            val ?
                get_pk_size(true) +
                get_pk_size(*val) :
                get_pk_size(false);
    }


    inline void pack(_Inout_ cursor_out &cursor, _In_ const winstd::cert_context &val)
    {
        if (val) {
            pack(cursor, (unsigned int)val->dwCertEncodingType);
            pack(cursor, (unsigned int)val->cbCertEncoded     );
            cursor_out::ptr_type ptr_end = cursor.ptr + val->cbCertEncoded;
            assert(ptr_end <= cursor.ptr_end);
            memcpy(cursor.ptr, val->pbCertEncoded, val->cbCertEncoded);
            cursor.ptr = ptr_end;
        } else {
            pack(cursor, (unsigned int)0);
            pack(cursor, (unsigned int)0);
        }
    }


    inline size_t get_pk_size(const winstd::cert_context &val)
    {
        return
            val ?
                get_pk_size((unsigned int)val->dwCertEncodingType) +
                get_pk_size((unsigned int)val->cbCertEncoded     ) +
                val->cbCertEncoded :
                get_pk_size((unsigned int)0) +
                get_pk_size((unsigned int)0);
    }


    inline void unpack(_Inout_ cursor_in &cursor, _Out_ winstd::cert_context &val)
    {
        DWORD dwCertEncodingType;
        unpack(cursor, (unsigned int&)dwCertEncodingType);

        DWORD dwCertEncodedSize;
        unpack(cursor, (unsigned int&)dwCertEncodedSize);

        if (dwCertEncodedSize) {
            cursor_in::ptr_type ptr_end = cursor.ptr + dwCertEncodedSize;
            assert(ptr_end <= cursor.ptr_end);
            val.create(dwCertEncodingType, (BYTE*)cursor.ptr, dwCertEncodedSize);
            cursor.ptr = ptr_end;
        } else
            val.free();
    }


    inline void pack(_Inout_ cursor_out &cursor, _In_ const eap::type_t &val)
    {
        pack(cursor, (unsigned char)val);
    }


    inline size_t get_pk_size(_In_ const eap::type_t &val)
    {
        return get_pk_size((unsigned char)val);
    }


    inline void unpack(_Inout_ cursor_in &cursor, _Out_ eap::type_t &val)
    {
        unsigned char t;
        unpack(cursor, t);
        val = (eap::type_t)t;
    }
}

#endif
