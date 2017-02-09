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

///
/// \defgroup EAPBaseStream  Memory Packaging
/// Simple serialization/deserialization of data to/from memory opaque BLOBs
///
/// @{
#ifndef EAP_ENCRYPT_BLOBS
///
/// Encrypt BLOBs leaving our module
///
#define EAP_ENCRYPT_BLOBS 1
#endif
/// @}

///
/// \defgroup EAPBaseModule  Modules
/// Modules
///
/// @{
#ifndef __DANGEROUS__LOG_CONFIDENTIAL_DATA
///
/// Output passwords and other confidential information to event log
///
#define __DANGEROUS__LOG_CONFIDENTIAL_DATA 0
#endif
/// @}

///
/// \defgroup EAPBaseCred  Credentials
/// Credential management
///
/// @{
#ifndef EAP_USE_NATIVE_CREDENTIAL_CACHE
///
/// Use EapHost credential cache
///
#define EAP_USE_NATIVE_CREDENTIAL_CACHE 0
#endif
/// @}

#define _HOST_LOW_ENDIAN

#if !defined(RC_INVOKED) && !defined(MIDL_PASS)

#include <WinStd/Common.h>
#include <WinStd/Crypt.h>
#include <WinStd/EAP.h>

#include <sal.h>

#include <list>
#include <memory>
#include <string>
#include <vector>

namespace eap
{
    struct cursor_out;
    struct cursor_in;

    class packable;

    template<size_t N> struct WINSTD_NOVTABLE sanitizing_blob_f;
    template<size_t N> struct WINSTD_NOVTABLE sanitizing_blob_zf;

    ///
    /// \defgroup EAPBaseSanitizing  Sanitizing memory
    /// Secure memory erasing after use
    ///
    /// @{

    ///
    /// Sanitizing dynamically allocated BLOB
    ///
    typedef std::vector<unsigned char, winstd::sanitizing_allocator<unsigned char> > sanitizing_blob;

    ///
    /// Sanitizing BLOB of fixed size (zero initialized in _DEBUG version, non-initialized in release version)
    ///
#ifdef _DEBUG
    #define sanitizing_blob_xf sanitizing_blob_zf
#else
    #define sanitizing_blob_xf sanitizing_blob_f
#endif

    /// @}

    /// \addtogroup EAPBaseDiameter
    /// @{

    enum diameter_avp_flags_t;
    struct diameter_avp_header;
    struct diameter_avp_header_ven;

    ///
    /// Appends Diameter AVP to response packet
    ///
    /// \param[in   ] code    AVP code
    /// \param[in   ] flags   AVP flags
    /// \param[in   ] data    AVP data (<16777212B)
    /// \param[in   ] size    Size of \p data in bytes
    /// \param[inout] packet  Response packet to append data to
    ///
    void diameter_avp_append(
        _In_                       unsigned int    code,
        _In_                       unsigned char   flags,
        _In_bytecount_(size) const void            *data,
        _In_                       unsigned int    size,
        _Inout_                    sanitizing_blob &packet);

    ///
    /// Appends Diameter AVP to response packet
    ///
    /// \param[in   ] code       AVP code
    /// \param[in   ] vendor_id  Vendor-ID
    /// \param[in   ] flags      AVP flags
    /// \param[in   ] data       AVP data (<16777212B)
    /// \param[in   ] size       Size of \p data in bytes
    /// \param[inout] packet     Response packet to append data to
    ///
    void diameter_avp_append(
        _In_                       unsigned int    code,
        _In_                       unsigned int    vendor_id,
        _In_                       unsigned char   flags,
        _In_bytecount_(size) const void            *data,
        _In_                       unsigned int    size,
        _Inout_                    sanitizing_blob &packet);

    /// @}
}

/// \addtogroup EAPBaseStream
/// @{

///
/// Packs a boolean
///
/// \param[inout] cursor  Memory cursor
/// \param[in]    val     Variable with data to pack
///
inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const bool &val);

///
/// Returns packed size of a boolean
///
/// \param[in] val  Data to pack
///
/// \returns Size of data when packed (in bytes)
///
inline size_t pksizeof(_In_ const bool &val);

///
/// Unpacks a boolean
///
/// \param[inout] cursor  Memory cursor
/// \param[out]   val     Variable to receive unpacked value
///
inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ bool &val);

///
/// Packs a byte
///
/// \param[inout] cursor  Memory cursor
/// \param[in]    val     Variable with data to pack
///
inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const unsigned char &val);

///
/// Returns packed size of a byte
///
/// \param[in] val  Data to pack
///
/// \returns Size of data when packed (in bytes)
///
inline size_t pksizeof(_In_ const unsigned char &val);

///
/// Unpacks a byte
///
/// \param[inout] cursor  Memory cursor
/// \param[out]   val     Variable to receive unpacked value
///
inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ unsigned char &val);

///
/// Packs an unsigned int
///
/// \param[inout] cursor  Memory cursor
/// \param[in]    val     Variable with data to pack
///
inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const unsigned int &val);

///
/// Returns packed size of an unsigned int
///
/// \param[in] val  Data to pack
///
/// \returns Size of data when packed (in bytes)
///
inline size_t pksizeof(_In_ const unsigned int &val);

///
/// Unpacks an unsigned int
///
/// \param[inout] cursor  Memory cursor
/// \param[out]   val     Variable to receive unpacked value
///
inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ unsigned int &val);

#ifdef _WIN64
///
/// Packs a size_t
///
/// \param[inout] cursor  Memory cursor
/// \param[in]    val     Variable with data to pack
///
inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const size_t &val);

///
/// Returns packed size of a size_t
///
/// \param[in] val  Data to pack
///
/// \returns Size of data when packed (in bytes)
///
inline size_t pksizeof(_In_ const size_t &val);

///
/// Unpacks a size_t
///
/// \param[inout] cursor  Memory cursor
/// \param[out]   val     Variable to receive unpacked value
///
inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ size_t &val);
#endif

///
/// Packs a string
///
/// \param[inout] cursor  Memory cursor
/// \param[in]    val     String to pack
///
template<class _Elem, class _Traits, class _Ax> inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const std::basic_string<_Elem, _Traits, _Ax> &val);

///
/// Returns packed size of a string
///
/// \param[in] val  String to pack
///
/// \returns Size of data when packed (in bytes)
///
template<class _Elem, class _Traits, class _Ax> inline size_t pksizeof(_In_ const std::basic_string<_Elem, _Traits, _Ax> &val);

///
/// Unpacks a string
///
/// \param[inout] cursor  Memory cursor
/// \param[out]   val     String to unpack to
///
template<class _Elem, class _Traits, class _Ax> inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ std::basic_string<_Elem, _Traits, _Ax> &val);

///
/// Packs a wide string
///
/// \param[inout] cursor  Memory cursor
/// \param[in]    val     String to pack
///
template<class _Traits, class _Ax> inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const std::basic_string<wchar_t, _Traits, _Ax> &val);

///
/// Returns packed size of a wide string
///
/// \param[in] val  String to pack
///
/// \returns Size of data when packed (in bytes)
///
template<class _Traits, class _Ax> inline size_t pksizeof(_In_ const std::basic_string<wchar_t, _Traits, _Ax> &val);

///
/// Unpacks a wide string
///
/// \param[inout] cursor  Memory cursor
/// \param[out]   val     String to unpack to
///
template<class _Traits, class _Ax> inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ std::basic_string<wchar_t, _Traits, _Ax> &val);

///
/// Packs a vector
///
/// \param[inout] cursor  Memory cursor
/// \param[in]    val     Vector to pack
///
template<class _Ty, class _Ax> inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const std::vector<_Ty, _Ax> &val);

///
/// Returns packed size of a vector
///
/// \param[in] val  Vector to pack
///
/// \returns Size of data when packed (in bytes)
///
template<class _Ty, class _Ax> inline size_t pksizeof(_In_ const std::vector<_Ty, _Ax> &val);

///
/// Unpacks a vector
///
/// \param[inout] cursor  Memory cursor
/// \param[out]   val     Vector to unpack to
///
template<class _Ty, class _Ax> inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ std::vector<_Ty, _Ax> &val);

///
/// Packs a list
///
/// \param[inout] cursor  Memory cursor
/// \param[in]    val     List to pack
///
template<class _Ty, class _Ax> inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const std::list<_Ty, _Ax> &val);

///
/// Returns packed size of a list
///
/// \param[in] val  List to pack
///
/// \returns Size of data when packed (in bytes)
///
template<class _Ty, class _Ax> inline size_t pksizeof(_In_ const std::list<_Ty, _Ax> &val);

///
/// Unpacks a list
///
/// \param[inout] cursor  Memory cursor
/// \param[out]   val     List to unpack to
///
template<class _Ty, class _Ax> inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ std::list<_Ty, _Ax> &val);

///
/// Packs a std::unique_ptr
///
/// \param[inout] cursor  Memory cursor
/// \param[in]    val     std::unique_ptr to pack
///
template<class _Ty, class _Dx> inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const std::unique_ptr<_Ty, _Dx> &val);

///
/// Returns packed size of a std::unique_ptr
///
/// \param[in] val  std::unique_ptr to pack
///
/// \returns Size of data when packed (in bytes)
///
template<class _Ty, class _Dx> inline size_t pksizeof(_In_ const std::unique_ptr<_Ty, _Dx> &val);

// std::unique_ptr<> is generally not unpackable, since we do not know, how to create a new instance of unique_ptr.
//template<class _Ty, class _Dx> inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ std::unique_ptr<_Ty, _Dx> &val);

///
/// Packs a certificate context
///
/// \param[inout] cursor  Memory cursor
/// \param[in]    val     Certificate context to pack
///
inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const winstd::cert_context &val);

///
/// Returns packed size of a certificate context
///
/// \param[in] val  Certificate context to pack
///
/// \returns Size of data when packed (in bytes)
///
inline size_t pksizeof(_In_ const winstd::cert_context &val);

///
/// Unpacks a certificate context
///
/// \param[inout] cursor  Memory cursor
/// \param[out]   val     Certificate context to unpack to
///
inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ winstd::cert_context &val);

///
/// Packs an EAP method type
///
/// \param[inout] cursor  Memory cursor
/// \param[in]    val     EAP method type to pack
///
inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const winstd::eap_type_t &val);

///
/// Returns packed size of an EAP method type
///
/// \param[in] val  EAP method type to pack
///
/// \returns Size of data when packed (in bytes)
///
inline size_t pksizeof(_In_ const winstd::eap_type_t &val);

///
/// Unpacks an EAP method type
///
/// \param[inout] cursor  Memory cursor
/// \param[out]   val     EAP method type to unpack to
///
inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ winstd::eap_type_t &val);

///
/// Packs a BLOB
///
/// \param[inout] cursor  Memory cursor
/// \param[in]    val     Variable with data to pack
///
template<size_t N> inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const eap::sanitizing_blob_f<N> &val);

///
/// Returns packed size of a BLOB
///
/// \param[in] val  Data to pack
///
/// \returns Size of data when packed (in bytes)
///
template<size_t N> inline size_t pksizeof(_In_ const eap::sanitizing_blob_f<N> &val);

///
/// Unpacks a BLOB
///
/// \param[inout] cursor  Memory cursor
/// \param[out]   val     Variable to receive unpacked value
///
template<size_t N> inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ eap::sanitizing_blob_f<N> &val);

///
/// Packs a GUID
///
/// \param[inout] cursor  Memory cursor
/// \param[in]    val     Variable with data to pack
///
inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const GUID &val);

///
/// Returns packed size of a GUID
///
/// \param[in] val  Data to pack
///
/// \returns Size of data when packed (in bytes)
///
inline size_t pksizeof(_In_ const GUID &val);

///
/// Unpacks a GUID
///
/// \param[inout] cursor  Memory cursor
/// \param[out]   val     Variable to receive unpacked value
///
inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ GUID &val);

///
/// Packs a EAP_METHOD_TYPE
///
/// \param[inout] cursor  Memory cursor
/// \param[in]    val     Variable with data to pack
///
inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const EAP_METHOD_TYPE &val);

///
/// Returns packed size of a EAP_METHOD_TYPE
///
/// \param[in] val  Data to pack
///
/// \returns Size of data when packed (in bytes)
///
inline size_t pksizeof(_In_ const EAP_METHOD_TYPE &val);

///
/// Unpacks a EAP_METHOD_TYPE
///
/// \param[inout] cursor  Memory cursor
/// \param[out]   val     Variable to receive unpacked value
///
inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ EAP_METHOD_TYPE &val);

///
/// Packs a packable object
///
/// \param[inout] cursor  Memory cursor
/// \param[in]    val     Object to pack
///
inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const eap::packable &val);

///
/// Returns packed size of a packable object
///
/// \param[in] val  Object to pack
///
/// \returns Size of data when packed (in bytes)
///
inline size_t pksizeof(_In_ const eap::packable &val);

///
/// Unpacks a packable object
///
/// \param[inout] cursor  Memory cursor
/// \param[out]   val     Object to unpack to
///
inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ eap::packable &val);

/// @}

///
/// \defgroup EAPBaseConversion  Data conversion
/// Data conversion
///
/// @{

#ifndef htonll
///
/// Converts an unsigned __int64 from host to TCP/IP network byte order.
///
/// \param[in] val  A 64-bit unsigned number in host byte order
///
/// \returns The value in TCP/IP's network byte order
///
inline unsigned __int64 htonll(unsigned __int64 val);
#endif

///
/// Converts a 24-bit integer from host to TCP/IP network byte order.
///
/// \param[in ] val  A 24-bit unsigned number in host byte order
/// \param[out] out  A 24-bit unsigned number in network byte order
///
inline void hton24(_In_ unsigned int val, _Out_ unsigned char out[3]);

///
/// Converts a 24-bit integer from TCP/IP network to host byte order.
///
/// \param[in] val  A 24-bit unsigned number in network byte order
///
/// \returns A 24-bit unsigned number in host byte order
///
inline unsigned int ntoh24(_In_ const unsigned char val[3]);

/// @}

#pragma once


namespace eap
{
    /// \addtogroup EAPBaseStream
    /// @{

    ///
    /// Output BLOB cursor
    ///
    struct cursor_out
    {
        ///
        /// Pointer to output data type
        ///
        typedef unsigned char *ptr_type;

        ptr_type ptr;       ///< Pointer to first data unwritten
        ptr_type ptr_end;   ///< Pointer to the end of available memory
    };


    ///
    /// Input BLOB cursor
    ///
    struct cursor_in
    {
        ///
        /// Pointer to input data type
        ///
        typedef const unsigned char *ptr_type;

        ptr_type ptr;       ///< Pointer to first data unread
        ptr_type ptr_end;   ///< Pointer to the end of BLOB
    };


    ///
    /// Base class for all packable data classes
    ///
    class packable
    {
    public:
        ///
        /// Constructs configuration
        ///
        packable();

        /// \name BLOB management
        /// @{

        ///
        /// Packs this object
        ///
        /// \param[inout] cursor  Memory cursor
        ///
        virtual void operator<<(_Inout_ cursor_out &cursor) const;

        ///
        /// Returns packed size of this object
        ///
        /// \returns Size of data when packed (in bytes)
        ///
        virtual size_t get_pk_size() const;

        ///
        /// Unpacks this object
        ///
        /// \param[inout] cursor  Memory cursor
        ///
        virtual void operator>>(_Inout_ cursor_in &cursor);

        /// @}
    };

    /// @}

    /// \addtogroup EAPBaseSanitizing
    /// @{

#pragma pack(push)
#pragma pack(1)

    ///
    /// Sanitizing BLOB of fixed size
    ///
    template<size_t N> struct WINSTD_NOVTABLE sanitizing_blob_f<N>
    {
        unsigned char data[N]; ///< BLOB data

        ///
        /// Constructor
        ///
        inline sanitizing_blob_f()
        {
        }

        ///
        /// Copies a BLOB
        ///
        /// \param[in] other  BLOB to copy from
        ///
        inline sanitizing_blob_f(_In_ const sanitizing_blob_f<N> &other)
        {
            memcpy(data, other.data, N);
        }

        ///
        /// Moves the BLOB
        ///
        /// \param[inout] other  Zero-initialized BLOB to move from
        ///
        inline sanitizing_blob_f(_Inout_ sanitizing_blob_zf<N> &&other)
        {
            memcpy(data, other.data, N);
            memset(other.data, 0, N);
        }

        ///
        /// Destructor
        ///
        inline ~sanitizing_blob_f()
        {
            SecureZeroMemory(data, N);
        }

        ///
        /// Copies a BLOB
        ///
        /// \param[in] other  BLOB to copy from
        ///
        /// \returns Reference to this object
        ///
        inline sanitizing_blob_f& operator=(_In_ const sanitizing_blob_f<N> &other)
        {
            if (this != std::addressof(other))
                memcpy(data, other.data, N);
            return *this;
        }

        ///
        /// Moves the BLOB
        ///
        /// \param[inout] other  Zero-initialized BLOB to copy from
        ///
        /// \returns Reference to this object
        ///
        inline sanitizing_blob_f& operator=(_Inout_ sanitizing_blob_zf<N> &&other)
        {
            if (this != std::addressof(other)) {
                memcpy(data, other.data, N);
                memset(other.data, 0, N);
            }
            return *this;
        }

        ///
        /// Is BLOB not equal to?
        ///
        /// \param[in] other  BLOB to compare against
        ///
        /// \returns
        /// - \c true when BLOBs are not equal;
        /// - \c false otherwise
        ///
        inline bool operator!=(_In_ const sanitizing_blob_f<N> &other) const
        {
            return !operator==(other);
        }

        ///
        /// Is BLOB equal to?
        ///
        /// \param[in] other  BLOB to compare against
        ///
        /// \returns
        /// - \c true when BLOBs are equal;
        /// - \c false otherwise
        ///
        inline bool operator==(_In_ const sanitizing_blob_f<N> &other) const
        {
            for (size_t i = 0; i < N; i++)
                if (data[i] != other.data[i]) return false;
            return true;
        }

        ///
        /// Is BLOB empty?
        ///
        /// \returns
        /// - \c true when BLOB is all-zero;
        /// - \c false otherwise
        ///
        inline bool empty() const
        {
            for (size_t i = 0; i < N; i++)
                if (data[i]) return false;
            return true;
        }

        ///
        /// Zero the BLOB
        ///
        inline void clear()
        {
            memset(data, 0, N);
        }
    };


    ///
    /// Sanitizing BLOB of fixed size (zero initialized)
    ///
    template<size_t N> struct WINSTD_NOVTABLE sanitizing_blob_zf<N> : sanitizing_blob_f<N>
    {
        ///
        /// Constructor
        ///
        inline sanitizing_blob_zf() : sanitizing_blob_f<N>()
        {
            memset(data, 0, N);
        }

        ///
        /// Copies a BLOB
        ///
        /// \param[in] other  BLOB to copy from
        ///
        inline sanitizing_blob_zf(_In_ const sanitizing_blob_f<N> &other) :
            sanitizing_blob_f<N>(other)
        {
        }

        ///
        /// Moves the BLOB
        ///
        /// \param[inout] other  Zero-initialized BLOB to move from
        ///
        inline sanitizing_blob_zf(_Inout_ sanitizing_blob_zf<N> &&other) :
            sanitizing_blob_f<N>(std::move(other))
        {
        }
    };
#pragma pack(pop)

    /// @}

    ///
    /// \defgroup EAPBaseDiameter  Diameter
    /// Diameter authentication protocol
    ///
    /// @{

    ///
    /// Diameter AVP flags
    ///
    #pragma warning(suppress: 4480)
    enum diameter_avp_flags_t : unsigned char {
        diameter_avp_flag_vendor    = 0x80, ///< Vendor-ID present
        diameter_avp_flag_mandatory = 0x40, ///< Mandatory
        diameter_avp_flag_protected = 0x20, ///< Protected
    };


#pragma pack(push)
#pragma pack(1)

    ///
    /// Diameter AVP header
    ///
    struct diameter_avp_header
    {
        unsigned char code[4];      ///< AVP Code
        unsigned char flags;        ///< AVP Flags
        unsigned char length[3];    ///< AVP Length
    };


    ///
    /// Diameter AVP header with Vendor-ID
    ///
    struct diameter_avp_header_ven : public diameter_avp_header
    {
        unsigned char vendor[4];    ///< Vendor-ID
    };

#pragma pack(pop)

    /// @}
}


inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const bool &val)
{
    auto ptr_end = cursor.ptr + 1;
    assert(ptr_end <= cursor.ptr_end);
    *cursor.ptr = val ? 1 : 0;
    cursor.ptr = ptr_end;
}


inline size_t pksizeof(_In_ const bool &val)
{
    UNREFERENCED_PARAMETER(val);
    return sizeof(unsigned char);
}


inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ bool &val)
{
    auto ptr_end = cursor.ptr + 1;
    assert(ptr_end <= cursor.ptr_end);
    val = *cursor.ptr ? true : false;
    cursor.ptr = ptr_end;
}


inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const unsigned char &val)
{
    auto ptr_end = cursor.ptr + 1;
    assert(ptr_end <= cursor.ptr_end);
    *cursor.ptr = val;
    cursor.ptr = ptr_end;
}


inline size_t pksizeof(_In_ const unsigned char &val)
{
    UNREFERENCED_PARAMETER(val);
    return sizeof(unsigned char);
}


inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ unsigned char &val)
{
    auto ptr_end = cursor.ptr + 1;
    assert(ptr_end <= cursor.ptr_end);
    val = *cursor.ptr;
    cursor.ptr = ptr_end;
}


inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const unsigned int &val)
{
    auto ptr_end = cursor.ptr + sizeof(unsigned int);
    assert(ptr_end <= cursor.ptr_end);
    *reinterpret_cast<unsigned int*>(cursor.ptr) = val;
    cursor.ptr = ptr_end;
}


inline size_t pksizeof(_In_ const unsigned int &val)
{
    UNREFERENCED_PARAMETER(val);
    return sizeof(unsigned int);
}


inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ unsigned int &val)
{
    auto ptr_end = cursor.ptr + sizeof(unsigned int);
    assert(ptr_end <= cursor.ptr_end);
    val = *reinterpret_cast<const unsigned int*>(cursor.ptr);
    cursor.ptr = ptr_end;
}


#ifdef _WIN64
inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const size_t &val)
{
    auto ptr_end = cursor.ptr + sizeof(size_t);
    assert(ptr_end <= cursor.ptr_end);
    *(size_t*)cursor.ptr = val;
    cursor.ptr = ptr_end;
}


inline size_t pksizeof(_In_ const size_t &val)
{
    UNREFERENCED_PARAMETER(val);
    return sizeof(size_t);
}


inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ size_t &val)
{
    auto ptr_end = cursor.ptr + sizeof(size_t);
    assert(ptr_end <= cursor.ptr_end);
    val = *(size_t*)cursor.ptr;
    cursor.ptr = ptr_end;
}
#endif


template<class _Elem, class _Traits, class _Ax>
inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const std::basic_string<_Elem, _Traits, _Ax> &val)
{
    size_t count = val.length();
    assert(strlen(val.c_str()) == count); // String should not contain zero terminators.
    size_t size = sizeof(_Elem)*(count + 1);
    auto ptr_end = cursor.ptr + size;
    assert(ptr_end <= cursor.ptr_end);
    memcpy(cursor.ptr, (const _Elem*)val.c_str(), size);
    cursor.ptr = ptr_end;
}


template<class _Elem, class _Traits, class _Ax>
inline size_t pksizeof(_In_ const std::basic_string<_Elem, _Traits, _Ax> &val)
{
    return sizeof(_Elem)*(val.length() + 1);
}


template<class _Elem, class _Traits, class _Ax>
inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ std::basic_string<_Elem, _Traits, _Ax> &val)
{
    size_t count_max = cursor.ptr_end - cursor.ptr;
    size_t count = strnlen((const _Elem*&)cursor.ptr, count_max);
    assert(count < count_max); // String should be zero terminated.
    val.assign((const _Elem*&)cursor.ptr, count);
    cursor.ptr += sizeof(_Elem)*(count + 1);
}


template<class _Traits, class _Ax>
inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const std::basic_string<wchar_t, _Traits, _Ax> &val)
{
    std::string val_utf8;
    WideCharToMultiByte(CP_UTF8, 0, val, val_utf8, NULL, NULL);
    cursor << val_utf8;
}


template<class _Traits, class _Ax>
inline size_t pksizeof(_In_ const std::basic_string<wchar_t, _Traits, _Ax> &val)
{
    return sizeof(char)*(WideCharToMultiByte(CP_UTF8, 0, val.c_str(), (int)val.length(), NULL, 0, NULL, NULL) + 1);
}


template<class _Traits, class _Ax>
inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ std::basic_string<wchar_t, _Traits, _Ax> &val)
{
    std::string val_utf8;
    cursor >> val_utf8;
    MultiByteToWideChar(CP_UTF8, 0, val_utf8, val);
}


template<class _Ty, class _Ax>
inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const std::vector<_Ty, _Ax> &val)
{
    auto count = val.size();
    cursor << count;

    // Since we do not know wheter vector elements are primitives or objects, iterate instead of memcpy.
    // For performance critical vectors of flat opaque data types write specialized template instantiation.
    for (auto i = val.cbegin(), i_end = val.cend(); i != i_end; ++i)
        cursor << *i;
}


template<class _Ty, class _Ax>
inline size_t pksizeof(_In_ const std::vector<_Ty, _Ax> &val)
{
    // Since we do not know wheter vector elements are primitives or objects, iterate instead of sizeof().
    // For performance critical vectors of flat opaque data types write specialized template instantiation.
    auto count = val.size();
    size_t size = pksizeof(count);
    for (auto i = val.cbegin(), i_end = val.cend(); i != i_end; ++i)
        size += pksizeof(*i);
    return size;
}


template<class _Ty, class _Ax>
inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ std::vector<_Ty, _Ax> &val)
{
    std::vector<_Ty, _Ax>::size_type i, count;
    cursor >> count;

    // Since we do not know wheter vector elements are primitives or objects, iterate instead of assign().
    // For performance critical vectors of flat opaque data types write specialized template instantiation.
    val.clear();
    val.reserve(count);
    for (i = 0; i < count; i++) {
        _Ty el;
        cursor >> el;
        val.push_back(el);
    }
}


template<class _Ty, class _Ax>
inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const std::list<_Ty, _Ax> &val)
{
    auto count = val.size();
    cursor << count;

    // Since we do not know wheter list elements are primitives or objects, iterate instead of memcpy.
    // For performance critical vectors of flat opaque data types write specialized template instantiation.
    for (auto i = val.cbegin(), i_end = val.cend(); i != i_end; ++i)
        cursor << *i;
}


template<class _Ty, class _Ax>
inline size_t pksizeof(_In_ const std::list<_Ty, _Ax> &val)
{
    // Since we do not know wheter list elements are primitives or objects, iterate instead of sizeof().
    // For performance critical vectors of flat opaque data types write specialized template instantiation.
    auto count = val.size();
    size_t size = pksizeof(count);
    for (auto i = val.cbegin(), i_end = val.cend(); i != i_end; ++i)
        size += pksizeof(*i);
    return size;
}


template<class _Ty, class _Ax>
inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ std::list<_Ty, _Ax> &val)
{
    std::list<_Ty, _Ax>::size_type i, count;
    cursor >> count;

    val.clear();
    for (i = 0; i < count; i++) {
        _Ty el;
        cursor >> el;
        val.push_back(el);
    }
}


template<class _Ty, class _Dx>
inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const std::unique_ptr<_Ty, _Dx> &val)
{
    if (val) {
        cursor << true;
        cursor << *val;
    } else
        cursor << false;
}


template<class _Ty, class _Dx>
inline size_t pksizeof(_In_ const std::unique_ptr<_Ty, _Dx> &val)
{
    return
        val ?
            pksizeof(true) +
            pksizeof(*val) :
            pksizeof(false);
}


inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const winstd::cert_context &val)
{
    if (val) {
        cursor << (unsigned int)val->dwCertEncodingType;
        cursor << (unsigned int)val->cbCertEncoded     ;
        auto ptr_end = cursor.ptr + val->cbCertEncoded;
        assert(ptr_end <= cursor.ptr_end);
        memcpy(cursor.ptr, val->pbCertEncoded, val->cbCertEncoded);
        cursor.ptr = ptr_end;
    } else {
        cursor << (unsigned int)0;
        cursor << (unsigned int)0;
    }
}


inline size_t pksizeof(_In_ const winstd::cert_context &val)
{
    return
        val ?
            pksizeof((unsigned int)val->dwCertEncodingType) +
            pksizeof((unsigned int)val->cbCertEncoded     ) +
            val->cbCertEncoded :
            pksizeof((unsigned int)0) +
            pksizeof((unsigned int)0);
}


inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ winstd::cert_context &val)
{
    DWORD dwCertEncodingType;
    assert(sizeof(dwCertEncodingType) == sizeof(unsigned int));
    cursor >> (unsigned int&)dwCertEncodingType;

    DWORD dwCertEncodedSize;
    assert(sizeof(dwCertEncodingType) == sizeof(unsigned int));
    cursor >> (unsigned int&)dwCertEncodedSize;

    if (dwCertEncodedSize) {
        auto ptr_end = cursor.ptr + dwCertEncodedSize;
        assert(ptr_end <= cursor.ptr_end);
        val.create(dwCertEncodingType, (BYTE*)cursor.ptr, dwCertEncodedSize);
        cursor.ptr = ptr_end;
    } else
        val.free();
}


inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const winstd::eap_type_t &val)
{
    cursor << (unsigned char)val;
}


inline size_t pksizeof(_In_ const winstd::eap_type_t &val)
{
    return pksizeof((unsigned char)val);
}


inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ winstd::eap_type_t &val)
{
    val = (winstd::eap_type_t)0; // Reset higher bytes to zero before reading to lower byte.
    cursor >> (unsigned char&)val;
}


template<size_t N>
inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const eap::sanitizing_blob_f<N> &val)
{
    auto ptr_end = cursor.ptr + sizeof(eap::sanitizing_blob_f<N>);
    assert(ptr_end <= cursor.ptr_end);
    memcpy(cursor.ptr, val.data, sizeof(eap::sanitizing_blob_f<N>));
    cursor.ptr = ptr_end;
}


template<size_t N>
inline size_t pksizeof(_In_ const eap::sanitizing_blob_f<N> &val)
{
    UNREFERENCED_PARAMETER(val);
    return sizeof(eap::sanitizing_blob_f<N>);
}


template<size_t N>
inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ eap::sanitizing_blob_f<N> &val)
{
    auto ptr_end = cursor.ptr + sizeof(eap::sanitizing_blob_f<N>);
    assert(ptr_end <= cursor.ptr_end);
    memcpy(val.data, cursor.ptr, sizeof(eap::sanitizing_blob_f<N>));
    cursor.ptr = ptr_end;
}


inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const GUID &val)
{
    auto ptr_end = cursor.ptr + sizeof(GUID);
    assert(ptr_end <= cursor.ptr_end);
    memcpy(cursor.ptr, &val, sizeof(GUID));
    cursor.ptr = ptr_end;
}


inline size_t pksizeof(_In_ const GUID &val)
{
    UNREFERENCED_PARAMETER(val);
    return sizeof(GUID);
}


inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ GUID &val)
{
    auto ptr_end = cursor.ptr + sizeof(GUID);
    assert(ptr_end <= cursor.ptr_end);
    memcpy(&val, cursor.ptr, sizeof(GUID));
    cursor.ptr = ptr_end;
}


inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const EAP_METHOD_TYPE &val)
{
    auto ptr_end = cursor.ptr + sizeof(EAP_METHOD_TYPE);
    assert(ptr_end <= cursor.ptr_end);
    memcpy(cursor.ptr, &val, sizeof(EAP_METHOD_TYPE));
    cursor.ptr = ptr_end;
}


inline size_t pksizeof(_In_ const EAP_METHOD_TYPE &val)
{
    UNREFERENCED_PARAMETER(val);
    return sizeof(EAP_METHOD_TYPE);
}


inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ EAP_METHOD_TYPE &val)
{
    auto ptr_end = cursor.ptr + sizeof(EAP_METHOD_TYPE);
    assert(ptr_end <= cursor.ptr_end);
    memcpy(&val, cursor.ptr, sizeof(EAP_METHOD_TYPE));
    cursor.ptr = ptr_end;
}


inline void operator<<(_Inout_ eap::cursor_out &cursor, _In_ const eap::packable &val)
{
    val.operator<<(cursor);
}


inline size_t pksizeof(_In_ const eap::packable &val)
{
    return val.get_pk_size();
}


inline void operator>>(_Inout_ eap::cursor_in &cursor, _Out_ eap::packable &val)
{
    val.operator>>(cursor);
}


#ifndef htonll

inline unsigned __int64 htonll(unsigned __int64 val)
{
    return
        (unsigned __int64)htonl((u_long)((val >> 32) & 0xffffffff))       |
        (unsigned __int64)htonl((u_long)((val      ) & 0xffffffff)) << 32;
}

#endif


inline void hton24(_In_ unsigned int val, _Out_ unsigned char out[3])
{
    assert(val <= 0xffffff);
    out[0] = (val >> 16) & 0xff;
    out[1] = (val >>  8) & 0xff;
    out[2] = (val      ) & 0xff;
}


inline unsigned int ntoh24(_In_ const unsigned char val[3])
{
    return
        (((unsigned int)val[0]) << 16) |
        (((unsigned int)val[1]) <<  8) |
        (((unsigned int)val[2])      );
}

#endif
