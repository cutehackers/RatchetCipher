/*
 * BeCrypto, end to end encryption base library
 *
 * Identity KeyPair (Curve25519 key pair)
 *  - public
 *  - private
 * Signed Key (Curve25519 key pair)
 *  - public
 *  - private
 * One-Time Keys (Curve25519 key pair)
 *  - public
 *  - private
 *
 * 세션은 한번 맺어지면 다시 인스톨이 되거나 디바이스가 변경되지 않는 한 다시 사용될 다시 맺을 필요가 없다.
 *
 */

#ifndef RATCHET_RATCHET_H
#define RATCHET_RATCHET_H

#include "sodium/include/sodium.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * max bytes of hkdf sha256
 */
#define max_kdf_hkdf_sha256_bytes (0xff * crypto_auth_hmacsha256_BYTES)

/**
* total message key size (32-byte cipher key, 32-byte HMAC-SHA256 key, 16-byte IV)
*/
#define ratchet_cipher_key_bytes (ratchet_cipher_message_key_bytes + ratchet_cipher_hash_key_bytes + ratchet_cipher_iv_bytes)

/**
 * cipher key size. same as crypto_auth_hmacsha256_BYTES
 */
#define ratchet_cipher_message_key_bytes 32U

/**
 * HMAC-SHA256 key size
 */
#define ratchet_cipher_hash_key_bytes 32U

/**
 * cipher IV, initial vector size
 */
#define ratchet_cipher_iv_bytes 16U

/**
 * total session header size
 */
#define ratchet_session_header_bytes (crypto_kx_PUBLICKEYBYTES + (2 * sizeof(unsigned long long)))

typedef struct {
    unsigned char public_key[crypto_kx_PUBLICKEYBYTES];
    unsigned char secret_key[crypto_kx_SECRETKEYBYTES];
} ratchet_key_pair;

typedef struct {
    unsigned char initiator[crypto_kx_SESSIONKEYBYTES];
    unsigned char recipient[crypto_kx_SESSIONKEYBYTES];
} chain_key_pair;

typedef struct ratchet {
    /**
     * public and private(secret) key pair by Diffie-Hellman
     */
    ratchet_key_pair key_pair;

    /**
     * other's public key
     */
    unsigned char other_public_key[crypto_kx_PUBLICKEYBYTES];

    /**
     * 32-byte root key
     */
    unsigned char root_key[crypto_kx_SESSIONKEYBYTES];

    /**
     * chain key
     */
    chain_key_pair chain_key_pair;

    /**
     * message numbers for sending
     */
    unsigned long long Ns;

    /**
     * message numbers for receiving
     */
    unsigned long long Nr;

    /**
     * Number of messages in previous sending chain
     */
    unsigned long long PN;

    /**
     * Dictionary of skipped-over message keys, indexed by ratchet public key and message number.
     * Raises an exception if too many elements are stored.
     */
    //skipped

} ratchet;

/**
 * message header contents
 */
typedef struct {
    uint8_t self_public_key[crypto_kx_PUBLICKEYBYTES];
    unsigned long long PN;
    unsigned long long Ns;
} ratchet_session_header_contents;

/**
 * sequence of message header
 *
 * public key (32 bytes) | PN (8 bytes) | Ns (8 bytes)
 */
typedef union {
    uint8_t bytes[ratchet_session_header_bytes];
    ratchet_session_header_contents contents;
} ratchet_session_header;

/**
 * ratchet cipher keys
 */
typedef struct {
    uint8_t message_key[ratchet_cipher_message_key_bytes];
    uint8_t hash_key[ratchet_cipher_hash_key_bytes];
    uint8_t iv[ratchet_cipher_iv_bytes];
} ratchet_cipher_keys;

/**
 * generate DH key pair
 * @param keyPair out, generated Diffie-Hellman key pair, public key, secret(private) key, will be
 *  contained.
 */
void ratchet_create_key_pair(ratchet_key_pair *key_pair);
void ratchet_create_key_pair_buffer(uint8_t public_key[crypto_kx_PUBLICKEYBYTES], uint8_t secret_key[crypto_kx_SECRETKEYBYTES]);

/**
 * generate DH key pair with seed
 * @param keyPair out, generated Diffie-Hellman key pair will be contained.
 * @package seed in seed data to generate key pair
 */
void ratchet_create_seed_key_pair(
    ratchet_key_pair *key_pair,
    const unsigned char seed[crypto_kx_SEEDBYTES]
);

/**
 * create a shared secret key for sender(initiator)
 * @param out
 * @param self_public_key
 * @param self_secret_key
 * @param recipient_public_key
 * @return 0 if success otherwise -1
 */
int
ratchet_create_shared_secret_for_initiator(
    uint8_t out[crypto_kx_SESSIONKEYBYTES],
    const uint8_t self_public_key[crypto_kx_PUBLICKEYBYTES],
    const uint8_t self_secret_key[crypto_kx_SECRETKEYBYTES],
    const uint8_t recipient_public_key[crypto_kx_PUBLICKEYBYTES]
);

/**
 * create a shared secret key for receiver(recipient)
 * @param out
 * @param self_public_key
 * @param self_secret_key
 * @param initiator_public_key
 * @return 0 if success otherwise -1
 */
int
ratchet_create_shared_secret_for_recipient(
    uint8_t out[crypto_kx_SESSIONKEYBYTES],
    const uint8_t self_public_key[crypto_kx_PUBLICKEYBYTES],
    const uint8_t self_secret_key[crypto_kx_SECRETKEYBYTES],
    const uint8_t initiator_public_key[crypto_kx_PUBLICKEYBYTES]
);

/**
 * generate chain key pair with other's public key
 * @param ratchet ratchet state variables
 * @param sk shared secret key
 * @param recipient_public_key other's public key
 */
void
ratchet_session_setup_for_initiator(
    ratchet *ratchet,
    uint8_t *sk,
    uint8_t *recipient_public_key
);

/**
 * initialize ratchet session state for receiver
 * @param ratchet state variables
 * @param sk shared secret key
 * @param key_pair dh initial key pair for
 */
void ratchet_session_setup_for_recipient(
    ratchet *ratchet,
    uint8_t *sk
);

/**
 * creates a ratchet chain key at a time with only sodium api for sender
 * @param ratchet
 * @param other_public_key
 */
void
ratchet_setup_chain_key_pair_for_initiator(ratchet *ratchet, const unsigned char *other_public_key);

/**
 * creates a ratchet chain key at a time with only sodium api for receiver
 * @param ratchet
 * @param other_public_key
 */
void
ratchet_setup_chain_key_pair_for_recipient(ratchet *ratchet, const unsigned char *other_public_key);

/**
 * Diffie-Hellman calculation for sender
 * state(q ‖ pk1 ‖ pk2) where pk1 == my public key, pk2 == other's public key
 */
int
ratchet_initiator_dh(
    uint8_t *out,
    const uint8_t *self_secret_key,
    const uint8_t *self_public_key,
    const uint8_t *recipient_public_key
);

/**
 * Diffie-Hellman calculation for sender
 * state(q ‖ pk1 ‖ pk2) where pk1 == my public key, pk2 == other's public key
 * @param out
 * @param self_secret_key
 * @param self_public_key
 * @param initiator_public_key
 * @return
 */
int
ratchet_recipient_dh(
    uint8_t *out,
    const uint8_t *self_secret_key,
    const uint8_t *self_public_key,
    const uint8_t *initiator_public_key
);

/**
 * KDF_RK(rk, dh_out), rk as salt, dh_out as input material.
 * HKDF-SHA-256 using the root key (rk) as HKDF salt, the output of a Diffie-Hellman (dh_out) as
 * HKDF input material and "OMEMO Root Chain" as HKDF info.
 * @param [out] root_key out, new root key
 * @param [out] chain_key out, new chain key
 * @param sk shared secret key
 * @param in input material of HKDF. the output of a Diffie-Hellman
 */
int ratchet_hkdf_root_keys(
    uint8_t root_key[crypto_auth_hmacsha256_BYTES],
    uint8_t chain_key[crypto_auth_hmacsha256_BYTES],
    uint8_t sk[crypto_auth_hmacsha256_KEYBYTES],
    uint8_t in[crypto_kx_SESSIONKEYBYTES]
);

/**
 * KDF_CK(ck)
 * Calculating a message key from an chain key and after that update the chain key.
 * HMAC-SHA-256 using a chain key (ck) as the HMAC key, a single byte constant 0x01 as HMAC input to
 * produce the next message key (mk) and a single byte constant 0x02 as HMAC input to produce the
 * next chain key.
 *
 * chain_key -> extract -> secret -> expand -> chain key(message-key, hash-key, iv)
 *
 * @param chain_key [in, out] 32-byte chain key
 * @param cipher_keys [out] cipher key sets.
 */
void
ratchet_hkdf_chain_keys(
    uint8_t chain_key[crypto_auth_hmacsha256_BYTES],
    ratchet_cipher_keys *cipher_keys
);

/**
 *
 * @param out
 * @param salt
 * @param salt_length
 * @param in
 * @param in_length
 * @return always 0
 */
int
ratchet_hkdf_sha256_extract(
    uint8_t out[crypto_auth_hmacsha256_BYTES],
    const uint8_t *salt,
    size_t salt_length,
    const uint8_t *in,
    size_t in_length
);

/**
 *
 * @param out
 * @param out_length
 * @param info
 * @param info_length
 * @param in
 * @return 0 if success otherwise -1
 */
int
ratchet_hkdf_sha256_expand(
    uint8_t *out,
    size_t out_length,
    const uint8_t *info,
    size_t info_length,
    const uint8_t in[crypto_auth_hmacsha256_BYTES]
);

/**
 * encrypt a message
 * @param ratchet state object
 * @param [out] encrypted encrypted message buffer pointer
 * @param [out] encrypted_length encrypted message length in bytes
 * @param [in] plain plain text
 * @param [in] plain_length plain text length in bytes
 */
void
ratchet_encrypt(
    ratchet *ratchet,
    uint8_t **encrypted,
    unsigned long long *encrypted_length,
    const uint8_t *plain,
    size_t plain_length
);

/**
 * DHs | PN | Ns (48 bytes)
 * @param [out] message header
 * @param self_public_key DHs self public key (32 bytes)
 * @param PN number of messages in previous sending chain. (8 bytes)
 * @param Ns message numbers for sending (8 bytes)
 */
void
ratchet_create_header(
    ratchet_session_header *header,
    ratchet *ratchet
);

void
ratchet_hash(
    uint8_t out[crypto_auth_hmacsha256_BYTES],
    const uint8_t *hash_key,
    size_t hash_key_length,
    const uint8_t *content,
    size_t content_length
);

/**
 * decrypt a message
 * @param ratchet ratchet state object
 * @param [out] decrypted decrypted message buffer pointer
 * @param [out] decrypted_length decrypted message length in bytes
 * @param [in] encrypted encrypted message bytes
 * @param [in] encrypted_length encrypted message length in bytes
 * @return 0 if success
 */
int
ratchet_decrypt(
    ratchet *ratchet,
    uint8_t **decrypted,
    unsigned long long *decrypted_length,
    const uint8_t *encrypted,
    unsigned long long encrypted_length
);

/**
 * perform double ratchet operation for receiver
 * @param ratchet ratchet object for receiver
 * @param header message header for sender
 */
void
ratchet_perform_double_ratchet(ratchet *ratchet, ratchet_session_header *header);

#ifdef __cplusplus
}
#endif

#endif //RATCHET_RATCHET_H
