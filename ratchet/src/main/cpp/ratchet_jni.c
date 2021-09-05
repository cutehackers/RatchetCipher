#include <jni.h>
#include <string.h>
#include <assert.h>
#include <android/log.h>

#include "ratchet.h"

#define LOG_TAG "RATCHET>"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/**
 * Java VM type signature
 * Type Signature Java Type
 * Z boolean
 * B byte
 * C char
 * S short
 * I int
 * J long
 * F float
 * D double
 * L fully-qualified-class ; fully-qualified-class
 * [ type type[]
 * ( arg-types ) ret-type method type
 *
 * For example, the Java method:
 * long f (int n, String s, int[] arr);
 * has the following type signature:
 * (ILjava/lang/String;[I)J
 */

jclass Jni_get_class(JNIEnv *env, const char *class_name);
jfieldID
Jni_get_object_field_id(
    JNIEnv *env,
    jclass clazz,
    const char* field_name,
    const char* field_type_signature
);
jobject
Jni_get_object_field(
    JNIEnv *env,
    jobject object,
    jfieldID fieldId
);
jmethodID
get_object_method_id(
    JNIEnv *env,
    jclass clazz,
    const char* method_name,
    const char* signatures
);
jlong pointer_to_java_address(void* ptr);

jobject
Jni_allocate_direct_byte_buffer(
    JNIEnv *env,
    int size
);

void
Jni_free_direct_byte_buffer(
    JNIEnv *env,
    jbyteArray buffer
);

JNIEXPORT void JNICALL
Java_app_junhyounglee_ratchet_core_RatchetCipher_externalInit(
    JNIEnv *env,
    jclass clazz
) {
  // will return 1 if it's already initialized.
  // 0 if initialized
  // -1 cannot be initialized. it is not safe to use.
  if (sodium_init() < 0) {
    // panic! the library couldn't be initialized, it is not safe to use
  }
}

JNIEXPORT jobject JNICALL
Java_app_junhyounglee_ratchet_core_RatchetCipher_externalNewKeyPair(
    JNIEnv *env,
    __unused jclass clazz
) {
//  ratchet_key_pair key_pair;
//  ratchet_create_key_pair(&key_pair);

  // byte buffer for (public_key or secret_key)
  jobject public_key = Jni_allocate_direct_byte_buffer(env, crypto_kx_PUBLICKEYBYTES);
  jobject secret_key = Jni_allocate_direct_byte_buffer(env, crypto_kx_SECRETKEYBYTES);

  // KeyPair object
  jclass key_pair_class = (*env)->FindClass(env, "app/junhyounglee/ratchet/core/KeyPair");
  if (key_pair_class == NULL) {
    return NULL;
  }
  jmethodID constructor = (*env)->GetMethodID(env, key_pair_class, "<init>", "(Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;)V");
  if ((*env)->ExceptionCheck(env)) {
    return NULL;
  }

  /*
   * Copying native bytes to Java ByteArray output.
   * #1 can be simply replaced with #2
   *
   * jbyteArray public_key = (*env)->NewByteArray(env, crypto_kx_PUBLICKEYBYTES);
   *
   * #1
   * uint8_t* public_key_bytes = (uint8_t*)(*env)->GetByteArrayElements(env, public_key, 0);
   * memcpy(public_key_bytes, key_pair.public_key, crypto_kx_PUBLICKEYBYTES);
   * (*env)->ReleaseByteArrayElements(env, public_key, (jbyte*)public_key_bytes, 0);
   *
   * #2
   * (*env)->SetByteArrayRegion(env, public_key, 0, crypto_kx_PUBLICKEYBYTES, (const jbyte *)key_pair.public_key);
   */
  // #
//  (*env)->SetByteArrayRegion(
//      env,
//      // target
//      public_key,
//      0,
//      crypto_kx_PUBLICKEYBYTES,
//      // source
//      (const jbyte *) key_pair.public_key
//  );
//  (*env)->SetByteArrayRegion(
//      env,
//      // target
//      secret_key,
//      0,
//      crypto_kx_SECRETKEYBYTES,
//      // source
//      (const jbyte *) key_pair.secret_key
//  );
  uint8_t* public_key_bytes = (*env)->GetDirectBufferAddress(env, public_key);
  uint8_t* secret_key_bytes = (*env)->GetDirectBufferAddress(env, secret_key);

  ratchet_create_key_pair_buffer(
      public_key_bytes,
      secret_key_bytes
  );

  char hex[65];
  sodium_bin2hex(hex, sizeof hex, public_key_bytes, crypto_kx_PUBLICKEYBYTES);
  LOGD("create_key_pair, public_key: %s", hex);
  sodium_bin2hex(hex, sizeof hex, secret_key_bytes, crypto_kx_SECRETKEYBYTES);
  LOGD("create_key_pair, secret_key: %s", hex);

  return (*env)->NewObject(env, key_pair_class, constructor, public_key, secret_key);
}

JNIEXPORT jobject JNICALL
Java_app_junhyounglee_ratchet_core_RatchetCipher_externalKeyPair(
    JNIEnv *env,
    __unused jclass clazz,
    jbyteArray public_key,
    jbyteArray secret_key
) {
  // byte buffer for (public_key or secret_key)
  jobject public_key_buffer = Jni_allocate_direct_byte_buffer(env, crypto_kx_PUBLICKEYBYTES);
  jobject secret_key_buffer = Jni_allocate_direct_byte_buffer(env, crypto_kx_SECRETKEYBYTES);

  // KeyPair object
  jclass key_pair_class = (*env)->FindClass(env, "app/junhyounglee/ratchet/core/KeyPair");
  if (key_pair_class == NULL) {
    return NULL;
  }
  jmethodID constructor = (*env)->GetMethodID(env, key_pair_class, "<init>", "(Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;)V");
  if ((*env)->ExceptionCheck(env)) {
    return NULL;
  }

  jsize pk_length = (*env)->GetArrayLength(env, public_key);
  jsize sk_length = (*env)->GetArrayLength(env, secret_key);
  if (pk_length != crypto_kx_PUBLICKEYBYTES || sk_length != crypto_kx_SECRETKEYBYTES) {
    (*env)->ThrowNew(env, (*env)->FindClass(env, "app/junhyounglee/ratchet/exception/InvalidKeyException"), "Invalid key size.");
  }

  uint8_t* public_key_bytes = (*env)->GetDirectBufferAddress(env, public_key_buffer);
  uint8_t* secret_key_bytes = (*env)->GetDirectBufferAddress(env, secret_key_buffer);

  const uint8_t* public_key_source = (const uint8_t*)(*env)->GetByteArrayElements(env, public_key, 0);
  const uint8_t* secret_key_source = (const uint8_t*)(*env)->GetByteArrayElements(env, secret_key, 0);
  memcpy(public_key_bytes, public_key_source, crypto_kx_PUBLICKEYBYTES);
  memcpy(secret_key_bytes, secret_key_source, crypto_kx_PUBLICKEYBYTES);

  char hex[65];
  sodium_bin2hex(hex, sizeof hex, public_key_bytes, crypto_kx_PUBLICKEYBYTES);
  LOGD("create_key_pair, public_key: %s", hex);
  sodium_bin2hex(hex, sizeof hex, secret_key_bytes, crypto_kx_SECRETKEYBYTES);
  LOGD("create_key_pair, secret_key: %s", hex);

  (*env)->ReleaseByteArrayElements(env, public_key, (jbyte*)public_key_source, 0);
  (*env)->ReleaseByteArrayElements(env, secret_key, (jbyte*)secret_key_source, 0);

  return (*env)->NewObject(env, key_pair_class, constructor, public_key_buffer, secret_key_buffer);
}

JNIEXPORT jobject JNICALL
Java_app_junhyounglee_ratchet_core_RatchetCipher_externalNewSharedSecretKeyForServer(
    JNIEnv *env,
    __unused jclass clazz,
    jobject server_key_pair,
    jobject client_public_key
) {
  // KeyPair object
  jclass key_pair_class = Jni_get_class(env, "app/junhyounglee/ratchet/core/KeyPair");
  jfieldID field_public_key = Jni_get_object_field_id(env, key_pair_class, "publicKey", "Ljava/nio/ByteBuffer;");
  jfieldID field_secret_key = Jni_get_object_field_id(env, key_pair_class, "secretKey", "Ljava/nio/ByteBuffer;");

  jobject server_public_key = Jni_get_object_field(env, server_key_pair, field_public_key);
  jobject server_secret_key = Jni_get_object_field(env, server_key_pair, field_secret_key);
  uint8_t* server_public_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, server_public_key);
  uint8_t* server_secret_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, server_secret_key);
  uint8_t* client_public_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, client_public_key);

  // byte buffer for (server's shared secret key)
  jobject shared_secret_key = Jni_allocate_direct_byte_buffer(env, crypto_kx_SESSIONKEYBYTES);
  uint8_t* shared_secret_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, shared_secret_key);

  if (ratchet_create_shared_secret_for_server(
      shared_secret_key_bytes,
      server_public_key_bytes,
      server_secret_key_bytes,
      client_public_key_bytes
  ) < 0) {
    // error while generating shared secret for client
  }

  return shared_secret_key;
}

JNIEXPORT jobject JNICALL
Java_app_junhyounglee_ratchet_core_RatchetCipher_externalNewSharedSecretKeyForClient(
    JNIEnv *env,
    __unused jclass clazz,
    jobject client_key_pair,
    jobject server_public_key
) {
  // KeyPair object
  jclass key_pair_class = Jni_get_class(env, "app/junhyounglee/ratchet/core/KeyPair");
  jfieldID field_public_key = Jni_get_object_field_id(env, key_pair_class, "publicKey", "Ljava/nio/ByteBuffer;");
  jfieldID field_secret_key = Jni_get_object_field_id(env, key_pair_class, "secretKey", "Ljava/nio/ByteBuffer;");

  jobject client_public_key = Jni_get_object_field(env, client_key_pair, field_public_key);
  jobject client_secret_key = Jni_get_object_field(env, client_key_pair, field_secret_key);
  uint8_t* client_public_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, client_public_key);
  uint8_t* client_secret_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, client_secret_key);
  uint8_t* server_public_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, server_public_key);

  // byte buffer for (client's shared secret key)
  jobject shared_secret_key = Jni_allocate_direct_byte_buffer(env, crypto_kx_SESSIONKEYBYTES);
  uint8_t* shared_secret_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, shared_secret_key);

  if (ratchet_create_shared_secret_for_client(
      shared_secret_key_bytes,
      client_public_key_bytes,
      client_secret_key_bytes,
      server_public_key_bytes
  ) < 0) {
    // error while generating shared secret for client
  }

  return shared_secret_key;
}

/**
 * Generates a ratchet session state java object for a server.
 *
 * NOTE
 * sodium_init() method must be called before run this methods.
 *
 * @param env
 * @param clazz
 * @param shared_secret_key shared secret key
 * @param server_key_pair server's key pair object
 * @param client_public_key
 * @return RatchetSessionState java instance that has native ratchet state.
 */
JNIEXPORT jobject JNICALL
Java_app_junhyounglee_ratchet_core_RatchetCipher_externalSessionSetUpForServer(
    JNIEnv *env,
    __unused jclass clazz,
    jobject shared_secret_key,
    jobject server_key_pair,
    jobject client_public_key
) {
  // 1. self_key_pair -> key_pair
  jclass key_pair_class = Jni_get_class(env, "app/junhyounglee/ratchet/core/KeyPair");
  jfieldID field_public_key = Jni_get_object_field_id(env, key_pair_class, "publicKey", "Ljava/nio/ByteBuffer;");
  jfieldID field_secret_key = Jni_get_object_field_id(env, key_pair_class, "secretKey", "Ljava/nio/ByteBuffer;");

  jobject server_public_key = Jni_get_object_field(env, server_key_pair, field_public_key);
  jobject server_secret_key = Jni_get_object_field(env, server_key_pair, field_secret_key);
  uint8_t* server_public_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, server_public_key);
  uint8_t* server_secret_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, server_secret_key);
  uint8_t* client_public_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, client_public_key);

  // 2. shared secret
  uint8_t* shared_secret_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, shared_secret_key);

  // 3. generate ratchet session state
  ratchet* ratchet = sodium_malloc(sizeof(struct ratchet));
  memcpy(ratchet->key_pair.public_key, server_public_key_bytes, crypto_kx_PUBLICKEYBYTES);
  memcpy(ratchet->key_pair.secret_key, server_secret_key_bytes, crypto_kx_SECRETKEYBYTES);
  ratchet_session_setup_for_server(ratchet, shared_secret_key_bytes, client_public_key_bytes);

  // 4. create RatchetSessionState object with native state object as construct parameter.
  jclass session_state_class = Jni_get_class(
      env,
      "app/junhyounglee/ratchet/core/RatchetSessionState"
  );
  jmethodID constructor = get_object_method_id(env, session_state_class, "<init>", "(J)V");

  jlong ref = pointer_to_java_address(ratchet);
  return (*env)->NewObject(env, session_state_class, constructor, ref);
}

/**
 * Generates a ratchet session state java object for a client.
 *
 * NOTE
 * sodium_init() method must be called before run this methods
 *
 * @param env
 * @param clazz
 * @param shared_secret_key shared secret key
 * @param client_key_pair a self key pair for client
 * @return
 */
JNIEXPORT jobject JNICALL
Java_app_junhyounglee_ratchet_core_RatchetCipher_externalSessionSetUpForClient(
    JNIEnv *env,
    __unused jclass clazz,
    jobject shared_secret_key,
    jobject client_key_pair
) {
  // 1. self_key_pair -> key_pair
  jclass key_pair_class = Jni_get_class(env, "app/junhyounglee/ratchet/core/KeyPair");
  jfieldID field_public_key = Jni_get_object_field_id(env, key_pair_class, "publicKey", "Ljava/nio/ByteBuffer;");
  jfieldID field_secret_key = Jni_get_object_field_id(env, key_pair_class, "secretKey", "Ljava/nio/ByteBuffer;");

  jobject client_public_key = Jni_get_object_field(env, client_key_pair, field_public_key);
  jobject client_secret_key = Jni_get_object_field(env, client_key_pair, field_secret_key);
  uint8_t* client_public_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, client_public_key);
  uint8_t* client_secret_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, client_secret_key);

  // 2. shared secret
  uint8_t* shared_secret_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, shared_secret_key);

  // 3. generate ratchet session state
  ratchet* ratchet = sodium_malloc(sizeof(struct ratchet));
  memcpy(ratchet->key_pair.public_key, client_public_key_bytes, crypto_kx_PUBLICKEYBYTES);
  memcpy(ratchet->key_pair.secret_key, client_secret_key_bytes, crypto_kx_SECRETKEYBYTES);
  ratchet_session_setup_for_client(ratchet, shared_secret_key_bytes);

  // 4. create RatchetSessionState object with native state object as construct parameter.
  jclass session_state_class = Jni_get_class(
      env,
      "app/junhyounglee/ratchet/core/RatchetSessionState"
  );
  jmethodID constructor = get_object_method_id(env, session_state_class, "<init>", "(J)V");

  jlong ref = pointer_to_java_address(ratchet);
  return (*env)->NewObject(env, session_state_class, constructor, ref);
}

JNIEXPORT void JNICALL
Java_app_junhyounglee_ratchet_core_RatchetCipher_externalFreeSessionState(
    __unused JNIEnv *env,
    __unused jclass clazz,
    jlong external_ref
) {
  ratchet* ptr = (void*)external_ref;
  if (ptr) {
    sodium_free(ptr);
  }
}

JNIEXPORT jbyteArray JNICALL
Java_app_junhyounglee_ratchet_core_RatchetCipher_externalEncrypt(
    JNIEnv *env,
    jclass clazz,
    jlong external_server_ref,
    jbyteArray plain
) {
  if (!external_server_ref) {
    (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/IllegalArgumentException"), "Invalid native ratchet object.");
  }
  ratchet* server = (ratchet*) external_server_ref;

  jsize length = (*env)->GetArrayLength(env, plain);
  if (length < 1) {
    //(*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/IllegalArgumentException"), "Byte stream length should greater than 0");
    jbyteArray empty = (*env)->NewByteArray(env, 0);
    return empty;
  }

  // encrypt
  const uint8_t* buffer = (const uint8_t*)(*env)->GetByteArrayElements(env, plain, 0);
  uint8_t *encrypted = NULL;
  unsigned long long encrypted_length = 0;
  ratchet_encrypt(server, &encrypted, &encrypted_length, buffer, length);

  jbyteArray java_encrypted = (*env)->NewByteArray(env, encrypted_length);
  (*env)->SetByteArrayRegion(
      env,
      java_encrypted,
      0,
      encrypted_length,
      (const jbyte *) encrypted
  );
  (*env)->ReleaseByteArrayElements(env, plain, (jbyte*)buffer, 0);

  return java_encrypted;
}

JNIEXPORT jbyteArray JNICALL
Java_app_junhyounglee_ratchet_core_RatchetCipher_externalDecrypt(
    JNIEnv *env,
    __unused jclass clazz,
    jlong external_client_ref,
    jbyteArray java_encrypted
) {
  if (!external_client_ref) {
    (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/IllegalArgumentException"), "Invalid native ratchet object.");
  }
  ratchet* client = (ratchet*) external_client_ref;

  jsize encrypted_length = (*env)->GetArrayLength(env, java_encrypted);
  if (encrypted_length < 1) {
    jbyteArray empty = (*env)->NewByteArray(env, 0);
    return empty;
  }

  // decrypt
  const uint8_t* encrypted = (const uint8_t*)(*env)->GetByteArrayElements(env, java_encrypted, 0);
  char *decrypted = NULL;
  unsigned long long decrypted_length = 0;
  ratchet_decrypt(client, (uint8_t**)&decrypted, &decrypted_length, encrypted, encrypted_length);

  jbyteArray java_plain = (*env)->NewByteArray(env, decrypted_length);
  (*env)->SetByteArrayRegion(
      env,
      java_plain,
      0,
      decrypted_length,
      (const jbyte *) decrypted
  );

  (*env)->ReleaseByteArrayElements(env, java_encrypted, (jbyte*)encrypted, 0);

  return java_plain;
}

//--------------------------------------------------------------------------------------------------
// jni_common

JNIEXPORT jobject JNICALL
Java_app_junhyounglee_ratchet_core_JniCommon_externalNewByteBuffer(
    JNIEnv *env,
    __unused jclass clazz,
    jint size
) {
  return Jni_allocate_direct_byte_buffer(env, size);
}

jobject
Jni_allocate_direct_byte_buffer(
    JNIEnv *env,
    int size
) {
  void *buffer = sodium_malloc(size);
  return (*env)->NewDirectByteBuffer(env, buffer, size);
}

JNIEXPORT void JNICALL
Java_app_junhyounglee_ratchet_core_JniCommon_externalFreeByteBuffer(
    JNIEnv *env,
    __unused jclass clazz,
    jbyteArray buffer
) {
  Jni_free_direct_byte_buffer(env, buffer);
}

void
Jni_free_direct_byte_buffer(
    JNIEnv *env,
    jbyteArray buffer
) {
  void* bytes = (*env)->GetDirectBufferAddress(env, buffer);
  sodium_free(bytes);
}

//--------------------------------------------------------------------------------------------------
// java_types

jclass
Jni_get_class(
    JNIEnv *env,
    const char *class_name
) {
  jclass klass = (*env)->FindClass(env, class_name);
  if (klass == NULL) {
    char message[strlen(class_name) + 32];
    sprintf(message, "Java class(%s) not found.", class_name);

    (*env)->ThrowNew(
        env,
        (*env)->FindClass(env, "java/lang/AssertionError"),
        message
    );
  }
  return klass;
}

jfieldID
Jni_get_object_field_id(
    JNIEnv *env,
    jclass clazz,
    const char* field_name,
    const char* field_type_signature
) {
  jfieldID field_id = (*env)->GetFieldID(env, clazz, field_name, field_type_signature);
  if ((*env)->ExceptionCheck(env)) {
    (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/AssertionError"), "Failed to get a field id.");
  }
  return field_id;
}

jobject
Jni_get_object_field(
    JNIEnv *env,
    jobject object,
    jfieldID fieldId
) {
  jobject field = (*env)->GetObjectField(env, object, fieldId);
  if ((*env)->ExceptionCheck(env)) {
    (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/AssertionError"), "Failed to get field object.");
  }
  return field;
}

jmethodID
get_object_method_id(
    JNIEnv *env,
    jclass clazz,
    const char* method_name,
    const char* signatures
) {
  jmethodID method_id = (*env)->GetMethodID(env, clazz, method_name, signatures);
  if ((*env)->ExceptionCheck(env)) {
    (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/AssertionError"), "Failed to get a method id.");
  }
  return method_id;
}

jlong
pointer_to_java_address(void* ptr) {
  jlong externalRef = (intptr_t) ptr;
  assert((void*)(externalRef) == ptr);
  return externalRef;
}
