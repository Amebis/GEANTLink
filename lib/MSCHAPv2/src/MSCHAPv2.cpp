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
// eap::create_des_key
//////////////////////////////////////////////////////////////////////

crypt_key eap::create_des_key(_In_ HCRYPTPROV cp, _In_count_(size) const unsigned char *key, _In_ size_t size)
{
    // Prepare exported key BLOB.
    struct key_blob_prefix {
        PUBLICKEYSTRUC header;
        DWORD size;
    } static const s_prefix = {
        {
            PLAINTEXTKEYBLOB,
            CUR_BLOB_VERSION,
            0,
            CALG_DES,
        },
        8,
    };
    sanitizing_blob key_blob;
    key_blob.reserve(sizeof(key_blob_prefix) + 8);
    key_blob.assign(reinterpret_cast<const unsigned char*>(&s_prefix), reinterpret_cast<const unsigned char*>(&s_prefix + 1));

    // Inject parity bits.
    unsigned char out = 0, parity = 1;
    size_t i = 0, j = 7, bits = std::min<size_t>(size * 8, 56);
    for (; i < bits; i++) {
        unsigned char bit = (key[i/8] & (1 << (7 - i%8))) ? 1 : 0;
        parity ^= bit;
        out |= bit << j;
        if (--j == 0) {
            out |= parity;
            key_blob.push_back(out);
            out = 0; parity = 1; j = 7;
        }
    }
    for (; i < 56; i++) {
        if (--j == 0) {
            out |= parity;
            key_blob.push_back(out);
            out = 0; parity = 1; j = 7;
        }
    }

    // Import key.
    crypt_key k;
    if (!k.import(cp, key_blob.data(), (DWORD)key_blob.size(), NULL, 0))
        throw winstd::win_runtime_error(__FUNCTION__ " Error importing key 1/3.");
    return k;
}



//////////////////////////////////////////////////////////////////////
// eap::challenge_mschapv2
//////////////////////////////////////////////////////////////////////

void eap::challenge_mschapv2::randomize(_In_ HCRYPTPROV cp)
{
    if (!CryptGenRandom(cp, sizeof(data), data))
        throw win_runtime_error(__FUNCTION__ " Error creating randomness.");
}


//////////////////////////////////////////////////////////////////////
// eap::challenge_hash
//////////////////////////////////////////////////////////////////////

eap::challenge_hash::challenge_hash()
{
}


eap::challenge_hash::challenge_hash(
    _In_         HCRYPTPROV         cp,
    _In_   const sanitizing_blob    &challenge_server,
    _In_   const challenge_mschapv2 &challenge_client,
    _In_z_ const char               *username)
{
    crypt_hash hash;
    if (!hash.create(cp, CALG_SHA))
        throw win_runtime_error(__FUNCTION__ " Creating SHA hash failed.");
    if (!CryptHashData(hash, (const BYTE*)&challenge_client      , (DWORD)sizeof(challenge_client), 0) ||
        !CryptHashData(hash,              challenge_server.data(), (DWORD)challenge_server.size() , 0) ||
        !CryptHashData(hash, (const BYTE*)username               , (DWORD)strlen(username)        , 0))
        throw win_runtime_error(__FUNCTION__ " Error hashing data.");
    unsigned char hash_val[20];
    DWORD size_hash_val = sizeof(hash_val);
    if (!CryptGetHashParam(hash, HP_HASHVAL, hash_val, &size_hash_val, 0))
        throw win_runtime_error(__FUNCTION__ " Error hashing data.");
    memcpy(data, hash_val, sizeof(data));
    SecureZeroMemory(hash_val, size_hash_val);
}


eap::challenge_hash::challenge_hash(_In_ const sanitizing_blob_f<8> &other) :
    sanitizing_blob_xf<8>(other)
{
}


#ifdef _DEBUG

eap::challenge_hash::challenge_hash(_Inout_ sanitizing_blob_zf<8> &&other) :
    sanitizing_blob_xf<8>(std::move(other))
{
}

#endif


//////////////////////////////////////////////////////////////////////
// eap::nt_password_hash
//////////////////////////////////////////////////////////////////////

eap::nt_password_hash::nt_password_hash()
{
}


eap::nt_password_hash::nt_password_hash(
    _In_         HCRYPTPROV cp,
    _In_z_ const wchar_t    *password)
{
    crypt_hash hash;
    if (!hash.create(cp, CALG_MD4))
        throw win_runtime_error(__FUNCTION__ " Creating MD4 hash failed.");
    if (!CryptHashData(hash, (const BYTE*)password, (DWORD)(wcslen(password) * sizeof(wchar_t)), 0))
        throw win_runtime_error(__FUNCTION__ " Error hashing data.");
    DWORD size_data = sizeof(data);
    if (!CryptGetHashParam(hash, HP_HASHVAL, data, &size_data, 0))
        throw win_runtime_error(__FUNCTION__ " Error hashing data.");
}


eap::nt_password_hash::nt_password_hash(
    _In_       HCRYPTPROV       cp,
    _In_ const nt_password_hash &pwd_hash)
{
    crypt_hash hash;
    if (!hash.create(cp, CALG_MD4))
        throw win_runtime_error(__FUNCTION__ " Creating MD4 hash failed.");
    if (!CryptHashData(hash, (const BYTE*)&pwd_hash, (DWORD)sizeof(pwd_hash), 0))
        throw win_runtime_error(__FUNCTION__ " Error hashing data.");
    DWORD size_data = sizeof(data);
    if (!CryptGetHashParam(hash, HP_HASHVAL, data, &size_data, 0))
        throw win_runtime_error(__FUNCTION__ " Error hashing data.");
}


eap::nt_password_hash::nt_password_hash(_In_ const sanitizing_blob_f<16> &other) :
    sanitizing_blob_xf<16>(other)
{
}


#ifdef _DEBUG

eap::nt_password_hash::nt_password_hash(_Inout_ sanitizing_blob_zf<16> &&other) :
    sanitizing_blob_xf<16>(std::move(other))
{
}

#endif


//////////////////////////////////////////////////////////////////////
// eap::nt_response
//////////////////////////////////////////////////////////////////////

eap::nt_response::nt_response()
{
}


eap::nt_response::nt_response(
    _In_         HCRYPTPROV         cp,
    _In_   const sanitizing_blob    &challenge_server,
    _In_   const challenge_mschapv2 &challenge_client,
    _In_z_ const char               *username,
    _In_z_ const wchar_t            *password)
{
    challenge_hash challenge(cp, challenge_server, challenge_client, username);
    nt_password_hash hash_pwd(cp, password);

    // Prepare exported key BLOB.
    crypt_key key;
    DWORD size_data_enc;
    static const DWORD mode_ecb = CRYPT_MODE_ECB;

    // DesEncrypt(Challenge, 1st 7-octets of ZPasswordHash, giving 1st 8-octets of Response)
    key = create_des_key(cp, reinterpret_cast<const unsigned char*>(&hash_pwd), 7);
    if (!CryptSetKeyParam(key, KP_MODE, (const BYTE*)&mode_ecb, 0))
        throw win_runtime_error(__FUNCTION__ " Error setting ECB mode.");
    memcpy(data, &challenge, 8);
    size_data_enc = 8;
    if (!CryptEncrypt(key, NULL, FALSE, 0, data, &size_data_enc, 8))
        throw win_runtime_error(__FUNCTION__ " Error encrypting message 1/3.");

    // DesEncrypt(Challenge, 2nd 7-octets of ZPasswordHash, giving 2nd 8-octets of Response)
    key = create_des_key(cp, reinterpret_cast<const unsigned char*>(&hash_pwd) + 7, 7);
    if (!CryptSetKeyParam(key, KP_MODE, (const BYTE*)&mode_ecb, 0))
        throw win_runtime_error(__FUNCTION__ " Error setting ECB mode.");
    memcpy(data + 8, &challenge, 8);
    size_data_enc = 8;
    if (!CryptEncrypt(key, NULL, FALSE, 0, data + 8, &size_data_enc, 8))
        throw win_runtime_error(__FUNCTION__ " Error encrypting message 2/3.");

    // DesEncrypt(Challenge, 2nd 7-octets of ZPasswordHash, giving 2nd 8-octets of Response)
    key = create_des_key(cp, reinterpret_cast<const unsigned char*>(&hash_pwd) + 14, 2);
    if (!CryptSetKeyParam(key, KP_MODE, (const BYTE*)&mode_ecb, 0))
        throw win_runtime_error(__FUNCTION__ " Error setting ECB mode.");
    memcpy(data + 16, &challenge, 8);
    size_data_enc = 8;
    if (!CryptEncrypt(key, NULL, FALSE, 0, data + 16, &size_data_enc, 8))
        throw win_runtime_error(__FUNCTION__ " Error encrypting message 3/3.");
}


eap::nt_response::nt_response(_In_ const sanitizing_blob_f<24> &other) :
    sanitizing_blob_xf<24>(other)
{
}


#ifdef _DEBUG

eap::nt_response::nt_response(_Inout_ sanitizing_blob_zf<24> &&other) :
    sanitizing_blob_xf<24>(std::move(other))
{
}

#endif


//////////////////////////////////////////////////////////////////////
// eap::authenticator_response
//////////////////////////////////////////////////////////////////////

eap::authenticator_response::authenticator_response()
{
}


eap::authenticator_response::authenticator_response(
    _In_         HCRYPTPROV         cp,
    _In_   const sanitizing_blob    &challenge_server,
    _In_   const challenge_mschapv2 &challenge_client,
    _In_z_ const char               *username,
    _In_z_ const wchar_t            *password,
    _In_   const nt_response        &nt_resp)
{
    static const unsigned char s_magic1[39] = {
        0x4d, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
        0x65, 0x72, 0x20, 0x74, 0x6f, 0x20, 0x63, 0x6c, 0x69, 0x65,
        0x6e, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67,
        0x20, 0x63, 0x6f, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x74
    };
    nt_password_hash hash_hash_pwd(cp, nt_password_hash(cp, password));

    crypt_hash hash;
    if (!hash.create(cp, CALG_SHA))
        throw win_runtime_error(__FUNCTION__ " Creating SHA hash failed.");
    if (!CryptHashData(hash, (const BYTE*)&hash_hash_pwd, (DWORD)sizeof(hash_hash_pwd), 0) ||
        !CryptHashData(hash, (const BYTE*)&nt_resp      , (DWORD)sizeof(nt_resp      ), 0) ||
        !CryptHashData(hash,              s_magic1      , (DWORD)sizeof(s_magic1     ), 0))
        throw win_runtime_error(__FUNCTION__ " Error hashing data.");
    unsigned char hash_val[20];
    DWORD size_hash_val = sizeof(hash_val);
    if (!CryptGetHashParam(hash, HP_HASHVAL, hash_val, &size_hash_val, 0))
        throw win_runtime_error(__FUNCTION__ " Error hashing data.");

    static const unsigned char s_magic2[41] = {
        0x50, 0x61, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x6d, 0x61, 0x6b,
        0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x6d, 0x6f,
        0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6e, 0x20, 0x6f, 0x6e,
        0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f,
        0x6e
    };
    challenge_hash challenge(cp, challenge_server, challenge_client, username);

    if (!hash.create(cp, CALG_SHA))
        throw win_runtime_error(__FUNCTION__ " Creating SHA hash failed.");
    if (!CryptHashData(hash,              hash_val  ,        size_hash_val    , 0) ||
        !CryptHashData(hash, (const BYTE*)&challenge, (DWORD)sizeof(challenge), 0) ||
        !CryptHashData(hash,              s_magic2  , (DWORD)sizeof(s_magic2 ), 0))
        throw win_runtime_error(__FUNCTION__ " Error hashing data.");
    size_hash_val = sizeof(data);
    if (!CryptGetHashParam(hash, HP_HASHVAL, data, &size_hash_val, 0))
        throw win_runtime_error(__FUNCTION__ " Error hashing data.");
}


eap::authenticator_response::authenticator_response(_In_ const sanitizing_blob_f<20> &other) :
    sanitizing_blob_xf<20>(other)
{
}


#ifdef _DEBUG

eap::authenticator_response::authenticator_response(_Inout_ sanitizing_blob_zf<20> &&other) :
    sanitizing_blob_xf<20>(std::move(other))
{
}

#endif
