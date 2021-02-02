#include <jni.h>
#include <string.h>
#include <stdint.h>
#include <android/log.h>

#include "ratchet.h"

#define LOG_TAG "RATCHET>"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/**
 * Diffie-Hellman key exchange
 * https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
 *
 * Header
 *  - pk: DH ratchet public key
 *  - pn: the previous chain length
 *  - n: the message number
 */

void test_ratchet_create_shared_secret_key();
void test_session_setup();

//--------------------------------------------------------------------------------------------------
// RatchetCipher implementation

void test_ratchet_create_shared_secret_key() {
  ratchet_key_pair alice;
  ratchet_key_pair bob;

  // GENERATE_DH()
  ratchet_create_key_pair(&alice);
  ratchet_create_key_pair(&bob);

  // shared secret key
  uint8_t sk_of_alice[crypto_kx_SESSIONKEYBYTES];
  ratchet_create_shared_secret_for_initiator(sk_of_alice, alice.public_key, alice.secret_key,
                                          bob.public_key);

  uint8_t sk_of_bob[crypto_kx_SESSIONKEYBYTES];
  ratchet_create_shared_secret_for_recipient(sk_of_bob, bob.public_key, bob.secret_key,
                                            alice.public_key);

  char hex[65];
  sodium_bin2hex(hex, sizeof hex, sk_of_alice, sizeof sk_of_alice);
  LOGD("alice's shared secret key: %s", hex);
  sodium_bin2hex(hex, sizeof hex, sk_of_bob, sizeof sk_of_bob);
  LOGD("bob's shared secret key: %s", hex);

  if (sodium_memcmp(sk_of_alice, sk_of_bob, crypto_kx_SESSIONKEYBYTES) == 0) {
    LOGD("shared secret key is the same.");
  } else {
    LOGD("shared secret key is different.");
  }
}

void test_session_setup() {
  // key pair from server, basically this process will be done from server side.
  // receiver setup

  // GENERATE_DH()
  ratchet receiver;
  ratchet_create_key_pair(&receiver.key_pair);
  ratchet sender;
  ratchet_create_key_pair(&sender.key_pair);

  // step 2. shared secret key for sender
  uint8_t sk_sender[crypto_kx_SESSIONKEYBYTES];
  ratchet_create_shared_secret_for_initiator(
      sk_sender,
      sender.key_pair.public_key,
      sender.key_pair.secret_key,
      receiver.key_pair.public_key);

  ratchet_session_setup_for_sender(&sender, sk_sender, receiver.key_pair.public_key);

  // receiver. receiver key_pair needs to be set beforehand
  // step 1. shared secret key
  uint8_t sk_receiver[crypto_kx_SESSIONKEYBYTES];
  ratchet_create_shared_secret_for_recipient(
      sk_receiver,
      receiver.key_pair.public_key,
      receiver.key_pair.secret_key,
      sender.key_pair.public_key);

  ratchet_session_setup_for_receiver(&receiver, sk_receiver);

  // encrypt
  uint8_t *encrypted = NULL;
  unsigned long long encrypted_length;
  char *plain = "ratchet cipher sample text.";
  ratchet_encrypt(&sender, &encrypted, &encrypted_length, (const uint8_t*)plain, strlen(plain));

  // decrypt
  char *decrypted = NULL;
  unsigned long long decrypted_length = 0;
  ratchet_decrypt(&receiver, (uint8_t**)&decrypted, &decrypted_length, encrypted, encrypted_length);

  sodium_free(encrypted);
  sodium_free(decrypted);
}

//--------------------------------------------------------------------------------------------------
// ratchet simple key pair by sodium

void
ratchet_setup_chain_key_pair_for_sender(ratchet *ratchet, const unsigned char *other_public_key) {
  /*
   * Compute two shared keys using the server's public key and the client's secret key.
   * aliceReceiveKey will be used by the client to receive data from the server,
   * aliceSendKey will by used by the client to send data to the server.
   */
  if (crypto_kx_server_session_keys(
      ratchet->chain_key_pair.receiver,
      ratchet->chain_key_pair.sender,
      ratchet->key_pair.public_key,
      ratchet->key_pair.secret_key,
      other_public_key) != 0) {
    /* Suspicious server public key, bail out */
    LOGE("error while building session keys for sender");
  }
}

void
ratchet_setup_chain_key_pair_for_receiver(ratchet *ratchet, const unsigned char *other_public_key) {
  /*
   * Compute two shared keys using the server's public key and the client's secret key.
   * client_rx will be used by the client to receive data from the server,
   * client_tx will by used by the client to send data to the server.
   */
  if (crypto_kx_client_session_keys(
      ratchet->chain_key_pair.receiver,
      ratchet->chain_key_pair.sender,
      ratchet->key_pair.public_key,
      ratchet->key_pair.secret_key,
      other_public_key) != 0) {
    /* Suspicious server public key, bail out */
    LOGE("error while building session keys for receiver");
  }
}

//--------------------------------------------------------------------------------------------------
// ratchet implementation

void
ratchet_create_key_pair(ratchet_key_pair *key_pair) {
  crypto_kx_keypair(key_pair->public_key, key_pair->secret_key);
}

void
ratchet_create_seed_key_pair(
    ratchet_key_pair *key_pair,
    const unsigned char seed[crypto_kx_SEEDBYTES]
) {
  crypto_kx_seed_keypair(key_pair->public_key, key_pair->secret_key, seed);
}

int
ratchet_create_shared_secret_for_initiator(
    uint8_t out[crypto_kx_SESSIONKEYBYTES],
    const uint8_t sender_public_key[crypto_kx_PUBLICKEYBYTES],
    const uint8_t sender_secret_key[crypto_kx_SECRETKEYBYTES],
    const uint8_t receiver_public_key[crypto_kx_PUBLICKEYBYTES]
) {
  if (out == NULL) {
    LOGE("dh calculation requires valid out buffer of at least left or right key.");
    return -1;
  }

  uint8_t q[crypto_scalarmult_BYTES];
  uint8_t keys[crypto_kx_SESSIONKEYBYTES];

  if (crypto_scalarmult(q, sender_secret_key, receiver_public_key) != 0) {
    LOGE("error while performing diffie-hellman calculation.");
    return -1;
  }

  crypto_generichash_state state;

  crypto_generichash_init(&state, NULL, 0U, sizeof keys);
  crypto_generichash_update(&state, q, crypto_scalarmult_BYTES);
  sodium_memzero(q, sizeof q);

  crypto_generichash_update(&state, sender_public_key, crypto_kx_PUBLICKEYBYTES);
  crypto_generichash_update(&state, receiver_public_key, crypto_kx_PUBLICKEYBYTES);
  crypto_generichash_final(&state, keys, sizeof keys);
  sodium_memzero(&state, sizeof state);

  int i;
  for (i = 0; i < crypto_kx_SESSIONKEYBYTES; i++) {
    out[i] = keys[i];
  }
  sodium_memzero(keys, sizeof keys);

  return 0;
}

int
ratchet_create_shared_secret_for_recipient(
    uint8_t out[crypto_kx_SESSIONKEYBYTES],
    const uint8_t receiver_public_key[crypto_kx_PUBLICKEYBYTES],
    const uint8_t receiver_secret_key[crypto_kx_SECRETKEYBYTES],
    const uint8_t sender_public_key[crypto_kx_PUBLICKEYBYTES]
) {
  if (out == NULL) {
    LOGE("dh calculation requires valid out buffer of at least left or right key.");
    return -1;
  }

  uint8_t q[crypto_scalarmult_BYTES];
  uint8_t keys[crypto_kx_SESSIONKEYBYTES];

  if (crypto_scalarmult(q, receiver_secret_key, sender_public_key) != 0) {
    LOGE("error while performing diffie-hellman calculation.");
    return -1;
  }

  crypto_generichash_state state;

  crypto_generichash_init(&state, NULL, 0U, sizeof keys);
  crypto_generichash_update(&state, q, crypto_scalarmult_BYTES);
  sodium_memzero(q, sizeof q);

  crypto_generichash_update(&state, sender_public_key, crypto_kx_PUBLICKEYBYTES);
  crypto_generichash_update(&state, receiver_public_key, crypto_kx_PUBLICKEYBYTES);
  crypto_generichash_final(&state, keys, sizeof keys);
  sodium_memzero(&state, sizeof state);

  int i;
  for (i = 0; i < crypto_kx_SESSIONKEYBYTES; i++) {
    out[i] = keys[i];
  }
  sodium_memzero(keys, sizeof keys);

  return 0;
}

void
ratchet_session_setup_for_sender(
    ratchet *ratchet,
    uint8_t sk[crypto_kx_SESSIONKEYBYTES],
    uint8_t *other_public_key
) {
  //memcpy(&ratchet->key_pair, key_pair, sizeof(ratchet_key_pair));

  // state.DHr = bob_dh_public_key
  memcpy(ratchet->other_public_key, other_public_key, crypto_kx_PUBLICKEYBYTES);

  // NOTE, dh for initiator
  // dh output that's going to use as input material of KDF_RK is also performed when
  // decrypting message from a receiver side.
  uint8_t dh[crypto_kx_SESSIONKEYBYTES];
  ratchet_sender_dh(
      dh,
      ratchet->key_pair.secret_key,
      ratchet->key_pair.public_key,
      other_public_key);

  // state.RK, state.CKs = KDF_RK(SK, DH(state.DHs, state.DHr))
  ratchet_hkdf_root_keys(ratchet->root_key, ratchet->chain_key_pair.sender, sk, dh);

  char hex[65];
  sodium_bin2hex(hex, sizeof hex, sk, crypto_kx_SESSIONKEYBYTES);
  LOGD("initiator's session setup, with shared secret key: %s", hex);
  sodium_bin2hex(hex, sizeof hex, ratchet->root_key, crypto_kx_SESSIONKEYBYTES);
  LOGD("  -> root_key: %s", hex);
  sodium_bin2hex(hex, sizeof hex, ratchet->chain_key_pair.sender, crypto_kx_SESSIONKEYBYTES);
  LOGD("  -> chain_key.sender: %s", hex);

  // state.CKr = None
  sodium_memzero(ratchet->chain_key_pair.receiver, crypto_kx_SESSIONKEYBYTES);

  ratchet->Ns = 0;
  ratchet->Nr = 0;
  ratchet->PN = 0;

  //skipped
}

void
ratchet_session_setup_for_receiver(
    ratchet *ratchet,
    uint8_t sk[crypto_kx_SESSIONKEYBYTES]
    //ratchet_key_pair *key_pair
) {
  //memcpy(&ratchet->key_pair, key_pair, sizeof(ratchet_key_pair));
  sodium_memzero(ratchet->other_public_key, crypto_kx_PUBLICKEYBYTES);
  // state.RK = SK
  memcpy(ratchet->root_key, sk, crypto_kx_SESSIONKEYBYTES);

  char hex[65];
  sodium_bin2hex(hex, sizeof hex, sk, crypto_kx_SESSIONKEYBYTES);
  LOGD("recipient's session setup, with shared secret key: %s", hex);
  sodium_bin2hex(hex, sizeof hex, ratchet->root_key, crypto_kx_SESSIONKEYBYTES);
  LOGD("  -> root_key: %s", hex);

  sodium_memzero(ratchet->chain_key_pair.sender, crypto_kx_SESSIONKEYBYTES);
  sodium_memzero(ratchet->chain_key_pair.receiver, crypto_kx_SESSIONKEYBYTES);

  ratchet->Ns = 0;
  ratchet->Nr = 0;
  ratchet->PN = 0;

  //skipped
}

int
ratchet_sender_dh(
    uint8_t out[crypto_kx_SESSIONKEYBYTES],
    const uint8_t self_secret_key[crypto_kx_SECRETKEYBYTES],
    const uint8_t self_public_key[crypto_kx_PUBLICKEYBYTES],
    const uint8_t remote_public_key[crypto_kx_PUBLICKEYBYTES]
) {
  if (out == NULL) {
    LOGE("dh calculation requires valid out buffer");
    return -1;
  }

  uint8_t q[crypto_scalarmult_BYTES];
  uint8_t keys[crypto_kx_SESSIONKEYBYTES];

  if (crypto_scalarmult(q, self_secret_key, remote_public_key) != 0) {
    LOGE("error while performing diffie-hellman calculation.");
    return -1;
  }

  crypto_generichash_state state;
  crypto_generichash_init(&state, NULL, 0U, sizeof keys);
  crypto_generichash_update(&state, q, crypto_scalarmult_BYTES);
  sodium_memzero(q, sizeof q);

  crypto_generichash_update(&state, remote_public_key, crypto_kx_PUBLICKEYBYTES);
  crypto_generichash_update(&state, self_public_key, crypto_kx_PUBLICKEYBYTES);
  crypto_generichash_final(&state, keys, sizeof keys);
  sodium_memzero(&state, sizeof state);

  /*
   * we can create two keys, one for sending another one for receiving
   * ex)
   * int i;
   * for (i = 0; i < crypto_kx_SESSIONKEYBYTES; i++) {
   *   sending[i] = keys[i];
   *   receiving[i] = keys[i + crypto_kx_SESSIONKEYBYTES];
   * }
   */
  memcpy(out, keys, crypto_kx_SESSIONKEYBYTES);
  sodium_memzero(keys, sizeof keys);

  return 0;
}

int
ratchet_receiver_dh(
    uint8_t out[crypto_kx_SESSIONKEYBYTES],
    const uint8_t self_secret_key[crypto_kx_SECRETKEYBYTES],
    const uint8_t self_public_key[crypto_kx_PUBLICKEYBYTES],
    const uint8_t remote_public_key[crypto_kx_PUBLICKEYBYTES]
) {
  if (out == NULL) {
    LOGE("dh calculation requires valid out buffer");
    return -1;
  }

  uint8_t q[crypto_scalarmult_BYTES];
  uint8_t keys[crypto_kx_SESSIONKEYBYTES];

  if (crypto_scalarmult(q, self_secret_key, remote_public_key) != 0) {
    LOGE("error while performing diffie-hellman calculation.");
    return -1;
  }

  crypto_generichash_state state;
  crypto_generichash_init(&state, NULL, 0U, sizeof keys);
  crypto_generichash_update(&state, q, crypto_scalarmult_BYTES);
  sodium_memzero(q, sizeof q);

  crypto_generichash_update(&state, self_public_key, crypto_kx_PUBLICKEYBYTES);
  crypto_generichash_update(&state, remote_public_key, crypto_kx_PUBLICKEYBYTES);
  crypto_generichash_final(&state, keys, sizeof keys);
  sodium_memzero(&state, sizeof state);

  /*
   * we can create two keys, one for sending another one for receiving
   * ex)
   * int i;
   * for (i = 0; i < crypto_kx_SESSIONKEYBYTES; i++) {
   *   sending[i] = keys[i];
   *   receiving[i] = keys[i + crypto_kx_SESSIONKEYBYTES];
   * }
   */
  memcpy(out, keys, crypto_kx_SESSIONKEYBYTES);
  sodium_memzero(keys, sizeof keys);

  return 0;
}

int ratchet_hkdf_root_keys(
    uint8_t root_key[crypto_auth_hmacsha256_BYTES],
    uint8_t chain_key[crypto_auth_hmacsha256_BYTES],
    uint8_t sk[crypto_auth_hmacsha256_KEYBYTES],
    uint8_t in[crypto_kx_SESSIONKEYBYTES]
) {
  // basically [out] buffer is a hash value of HMAC-SHA256 function, but this will be used as a
  // key
  ratchet_hkdf_sha256_extract(
      chain_key,
      sk,
      crypto_auth_hmacsha256_KEYBYTES,
      in,
      crypto_kx_SESSIONKEYBYTES);

  // update root key
  uint8_t buffer[crypto_auth_hmacsha256_BYTES];
  if (ratchet_hkdf_sha256_expand(
      buffer,
      crypto_auth_hmacsha256_BYTES,
      NULL,
      0,
      sk) != 0) {
    return -1;
  }
  memcpy(root_key, buffer, crypto_kx_PUBLICKEYBYTES);

  return 0;
}

void
ratchet_hkdf_chain_keys(
    uint8_t chain_key[crypto_auth_hmacsha256_BYTES],
    ratchet_cipher_keys *cipher_keys
) {
  static const char ratchet_chain_seed[] = "ratchet_chain_seed";

  uint8_t key[crypto_auth_hmacsha256_KEYBYTES];
  sodium_memzero(key, crypto_auth_hmacsha256_KEYBYTES);

  // step 1. create message key from current chain key
  //crypto_auth_hmacsha256(message_key, (const uint8_t *)(const uint8_t) 0x01, 1, chain_key);
  uint8_t seed = 0x01;
  uint8_t secret[crypto_auth_hmacsha256_BYTES];

  /*
   * extracting secret
   * hmacsha256
   *  - init (chain_key)
   *  - update (0x01)
   *  - final (secret)
   */
  ratchet_hkdf_sha256_extract(
      secret,
      chain_key, crypto_auth_hmacsha256_BYTES,
      &seed, 1);

  // expanding secret to 80-byte cipher key(message-key | hash-key | iv)
  uint8_t cipher_key_bytes[ratchet_cipher_key_bytes];
  if (ratchet_hkdf_sha256_expand(
      cipher_key_bytes, ratchet_cipher_key_bytes,
      (const uint8_t *) ratchet_chain_seed, sizeof(ratchet_chain_seed) - 1,
      secret) != 0) {
    return;
  }
  memcpy(cipher_keys->message_key, cipher_key_bytes, ratchet_cipher_message_key_bytes);
  memcpy(cipher_keys->hash_key, cipher_key_bytes + ratchet_cipher_message_key_bytes,
         ratchet_cipher_hash_key_bytes);
  memcpy(cipher_keys->iv,
         cipher_key_bytes + ratchet_cipher_message_key_bytes + ratchet_cipher_hash_key_bytes,
         ratchet_cipher_iv_bytes);

  // step 2. update chain key
  uint8_t buffer[crypto_auth_hmacsha256_BYTES];
  seed = 0x02;
  crypto_auth_hmacsha256(buffer, &seed, 1, secret);
  memcpy(chain_key, buffer, crypto_auth_hmacsha256_BYTES);
}

int
ratchet_hkdf_sha256_extract(
    uint8_t out[crypto_auth_hmacsha256_BYTES],
    const uint8_t *salt,
    size_t salt_length,
    const uint8_t *in,
    size_t in_length
) {
  crypto_auth_hmacsha256_state state;

  crypto_auth_hmacsha256_init(&state, salt, salt_length);
  crypto_auth_hmacsha256_update(&state, in, in_length);
  crypto_auth_hmacsha256_final(&state, out);
  sodium_memzero(&state, sizeof state);

  return 0;
}

int
ratchet_hkdf_sha256_expand(
    uint8_t *out,
    size_t out_length,
    const uint8_t *info,
    size_t info_length,
    const uint8_t in[crypto_auth_hmacsha256_BYTES]
) {
  crypto_auth_hmacsha256_state st;
  unsigned char tmp[crypto_auth_hmacsha256_BYTES];
  size_t i;
  size_t left;
  unsigned char counter = 1U;

  if (out_length > max_kdf_hkdf_sha256_bytes) {
    return -1;
  }

  for (i = (size_t) 0U; i + crypto_auth_hmacsha256_BYTES <= out_length;
       i += crypto_auth_hmacsha256_BYTES) {
    crypto_auth_hmacsha256_init(&st, in, crypto_auth_hmacsha256_BYTES);
    if (i != (size_t) 0U) {
      crypto_auth_hmacsha256_update(&st, &out[i - crypto_auth_hmacsha256_BYTES],
                                    crypto_auth_hmacsha256_BYTES);
    }
    if (info) {
      crypto_auth_hmacsha256_update(&st, info, info_length);
    }
    crypto_auth_hmacsha256_update(&st, &counter, (size_t) 1U);
    crypto_auth_hmacsha256_final(&st, &out[i]);
    counter++;
  }
  if ((left = out_length & (crypto_auth_hmacsha256_BYTES - 1U)) != (size_t) 0U) {
    crypto_auth_hmacsha256_init(&st, in, crypto_auth_hmacsha256_BYTES);
    if (i != (size_t) 0U) {
      crypto_auth_hmacsha256_update(&st, &out[i - crypto_auth_hmacsha256_BYTES],
                                    crypto_auth_hmacsha256_BYTES);
    }
    crypto_auth_hmacsha256_update(&st, info, info_length);
    crypto_auth_hmacsha256_update(&st, &counter, (size_t) 1U);
    crypto_auth_hmacsha256_final(&st, tmp);
    memcpy(&out[i], tmp, left);
    sodium_memzero(tmp, sizeof tmp);
  }
  sodium_memzero(&st, sizeof st);

  return 0;
}

void
ratchet_encrypt(
    ratchet *ratchet,
    uint8_t **encrypted,
    unsigned long long *encrypted_length,
    const uint8_t *plain,
    size_t plain_length
) {
  // is hardware-acceleration available. 1 supported 0 not supported
  if (crypto_aead_aes256gcm_is_available() == 0) {
    // not available on this cpu
    abort();
  }

  uint8_t *buffer = NULL;

  char hex[512];
  sodium_bin2hex(hex, sizeof hex, plain, plain_length);
  LOGD("encryption plain text: %s, size: %zu", hex, plain_length);

  sodium_bin2hex(hex, sizeof hex, ratchet->chain_key_pair.sender, crypto_kx_SESSIONKEYBYTES);
  LOGD("  -> before chain_key_pair.sender: %s", hex);

  // state.CKs, mk = KDF_CK(state.CKs)
  // derive cipher keys
  // message keys(80 bytes, AES256 32 bytes, HMAC-SHA256 32 bytes, IV 16 bytes)
  ratchet_cipher_keys cipher_keys;
  ratchet_hkdf_chain_keys(ratchet->chain_key_pair.sender, &cipher_keys);

  sodium_bin2hex(hex, sizeof hex, ratchet->chain_key_pair.sender, crypto_kx_SESSIONKEYBYTES);
  LOGD("  -> after chain_key_pair.sender: %s", hex);
  sodium_bin2hex(hex, sizeof hex, cipher_keys.message_key, ratchet_cipher_message_key_bytes);
  LOGD("  -> after message_key: %s", hex);
  sodium_bin2hex(hex, sizeof hex, cipher_keys.hash_key, ratchet_cipher_message_key_bytes);
  LOGD("  -> after hash_key: %s", hex);
  sodium_bin2hex(hex, sizeof hex, cipher_keys.iv, ratchet_cipher_iv_bytes);
  LOGD("  -> after iv: %s", hex);

  // header
  ratchet_session_header header;
  ratchet_create_header(&header, ratchet);

  ratchet->Ns++;

  // associated_data -> hmacsha256(header)
  uint8_t associated_data[crypto_auth_hmacsha256_BYTES];
  ratchet_hash(
      associated_data,
      cipher_keys.hash_key, ratchet_cipher_hash_key_bytes,
      header.bytes, ratchet_session_header_bytes);

  sodium_bin2hex(hex, sizeof hex, header.bytes, ratchet_session_header_bytes);
  LOGD("  -> message header: %s", hex);
  sodium_bin2hex(hex, sizeof hex, associated_data, crypto_auth_hmacsha256_BYTES);
  LOGD("  -> hash of message header: %s", hex);

  //unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
  unsigned char *encrypted_text = sodium_malloc(plain_length + crypto_aead_aes256gcm_ABYTES);
  unsigned long long encrypted_text_size = 0;

  // AEAD encrypt
  // encrypted_text_size: actual cipher text size
  // nonce
  //  The public nonce [npub] should never ever be reused with the same key.
  //  Randomly generated nonce cannot be used by recipient. so use iv as nonce.
  //   ex) randombytes_buf(nonce, sizeof nonce) -> X
  crypto_aead_aes256gcm_encrypt(
      encrypted_text,
      &encrypted_text_size,
      plain,
      plain_length,
      associated_data,
      crypto_auth_hmacsha256_BYTES,
      NULL,
      cipher_keys.iv,
      cipher_keys.message_key);

  sodium_bin2hex(hex, sizeof hex, encrypted_text, encrypted_text_size);
  LOGD("  -> encrypted text: %s, size: %llu", hex, encrypted_text_size);

  /*
   * encrypted byte stream ┌ ┐ ┘└ ┬ ┴ ┼ │ ─ ├ ┤
   * ┌────────────────────────────────────────────────────┐
   * │ header                                             │
   * ├──────────────────────┬──────────────┬──────────────┤
   * │public key (32 bytes) │ PN (8 bytes) │ Ns (8 bytes) │
   * ├──────────────────────┴──────────────┴──────────────┤
   * │ message                                            │
   * └────────────────────────────────────────────────────┘
   */
  buffer = sodium_malloc(ratchet_session_header_bytes + encrypted_text_size);
  memcpy(buffer, header.bytes, ratchet_session_header_bytes);
  memcpy(buffer + ratchet_session_header_bytes, encrypted_text, encrypted_text_size);
  sodium_free(encrypted_text);

  *encrypted = buffer;
  *encrypted_length = ratchet_session_header_bytes + encrypted_text_size;
}

void
ratchet_create_header(
    ratchet_session_header *header,
    ratchet *ratchet
) {
  memcpy(header->contents.self_public_key, ratchet->key_pair.public_key, crypto_kx_PUBLICKEYBYTES);
  header->contents.PN = ratchet->PN;
  header->contents.Ns = ratchet->Ns;
}

void
ratchet_hash(
    uint8_t out[crypto_auth_hmacsha256_BYTES],
    const uint8_t *hash_key,
    size_t hash_key_length,
    const uint8_t *content,
    size_t content_length
) {
  crypto_auth_hmacsha256_state state;
  crypto_auth_hmacsha256_init(&state, hash_key, hash_key_length);
  crypto_auth_hmacsha256_update(&state, content, content_length);
  crypto_auth_hmacsha256_final(&state, out);
  sodium_memzero(&state, sizeof state);
}

int
ratchet_decrypt(
    ratchet *ratchet,
    uint8_t **decrypted,
    unsigned long long *decrypted_length,
    const uint8_t *encrypted,
    unsigned long long encrypted_length
) {
  if (encrypted_length < crypto_aead_aes256gcm_ABYTES) {
    // invalid message body
    return -1;
  }

  uint8_t *buffer = NULL;

  unsigned long long encrypted_text_size = encrypted_length - ratchet_session_header_bytes;
  unsigned char *encrypted_text = sodium_malloc(encrypted_text_size);

  ratchet_session_header header;
  memcpy(header.bytes, encrypted, ratchet_session_header_bytes);
  memcpy(encrypted_text, encrypted + ratchet_session_header_bytes, encrypted_text_size);

  char hex[512];
  sodium_bin2hex(hex, sizeof hex, header.bytes, ratchet_session_header_bytes);
  LOGD("decryption message header: %s", hex);
  sodium_bin2hex(hex, sizeof hex, encrypted_text, encrypted_text_size);
  LOGD("  -> encrypted text: %s, size: %llu", hex, encrypted_text_size);

  // step 1. has skipped message
  //trySkippedMessageKey()

  // step 2. compare dh public key
  if (sodium_memcmp(
      ratchet->other_public_key,
      header.contents.self_public_key,
      crypto_auth_hmacsha256_BYTES) != 0) {
    // skipMessageKeys(state, header.pn)

    // double ratchet
    ratchet_perform_double_ratchet(ratchet, &header);
  }

  // skipMessageKeys(state, header.n)

  sodium_bin2hex(hex, sizeof hex, ratchet->chain_key_pair.receiver, crypto_kx_SESSIONKEYBYTES);
  LOGD("  -> before chain_key_pair.receiver: %s", hex);

  // state.CKr, mk = KDF_CK(state.CKr)
  // derive cipher keys
  // message keys(80 bytes, AES256 32 bytes, HMAC-SHA256 32 bytes, IV 16 bytes)
  ratchet_cipher_keys cipher_keys;
  ratchet_hkdf_chain_keys(ratchet->chain_key_pair.receiver, &cipher_keys);
  ratchet->Nr++;

  sodium_bin2hex(hex, sizeof hex, ratchet->chain_key_pair.receiver, crypto_kx_SESSIONKEYBYTES);
  LOGD("  -> after chain_key_pair.receiver: %s", hex);
  sodium_bin2hex(hex, sizeof hex, cipher_keys.message_key, ratchet_cipher_message_key_bytes);
  LOGD("  -> after message_key: %s", hex);
  sodium_bin2hex(hex, sizeof hex, cipher_keys.hash_key, ratchet_cipher_message_key_bytes);
  LOGD("  -> after hash_key: %s", hex);
  sodium_bin2hex(hex, sizeof hex, cipher_keys.iv, ratchet_cipher_iv_bytes);
  LOGD("  -> after iv: %s", hex);

  // associated_data -> hmacsha256(header)
  uint8_t associated_data[crypto_auth_hmacsha256_BYTES];
  ratchet_hash(
      associated_data,
      cipher_keys.hash_key, ratchet_cipher_hash_key_bytes,
      header.bytes, ratchet_session_header_bytes);

  sodium_bin2hex(hex, sizeof hex, associated_data, crypto_auth_hmacsha256_BYTES);
  LOGD("  -> hash of message header: %s", hex);

  buffer = sodium_malloc(encrypted_text_size + 1);

  // AEAD decrypt
  if (crypto_aead_aes256gcm_decrypt(
      buffer,
      decrypted_length,
      NULL,
      encrypted_text,
      encrypted_text_size,
      associated_data,
      crypto_auth_hmacsha256_BYTES,
      cipher_keys.iv,
      cipher_keys.message_key) != 0) {
    // message forged
    return -1;
  }

  // only for displaying
  *(buffer + encrypted_text_size) = '\0';
  sodium_bin2hex(hex, sizeof hex, buffer, encrypted_text_size);
  LOGD("  -> decrypted message: %s, size: %llu", buffer, *decrypted_length);

  *decrypted = buffer;

  return 0;
}

void
ratchet_perform_double_ratchet(ratchet *ratchet, ratchet_session_header *header) {
  ratchet->PN = header->contents.Ns;
  ratchet->Ns = 0;
  ratchet->Nr = 0;
  memcpy(ratchet->other_public_key, header->contents.self_public_key, crypto_kx_PUBLICKEYBYTES);

  // dh for receiver
  uint8_t dh[crypto_kx_SESSIONKEYBYTES];

  // state.RK, state.CKr = KDF_RK(state.RK, DH(state.DHs, state.DHr))
  ratchet_receiver_dh(
      dh,
      ratchet->key_pair.secret_key,
      ratchet->key_pair.public_key,
      ratchet->other_public_key);

  ratchet_hkdf_root_keys(ratchet->root_key, ratchet->chain_key_pair.receiver, ratchet->root_key, dh);

  // state.DHs = GENERATE_DH()
  ratchet_create_key_pair(&ratchet->key_pair);

  // state.RK, state.CKs = KDF_RK(state.RK, DH(state.DHs, state.DHr))
  ratchet_receiver_dh(
      dh,
      ratchet->key_pair.secret_key,
      ratchet->key_pair.public_key,
      ratchet->other_public_key);

  ratchet_hkdf_root_keys(ratchet->root_key, ratchet->chain_key_pair.sender, ratchet->root_key, dh);
}