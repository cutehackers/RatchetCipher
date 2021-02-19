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
Java_app_junhyounglee_ratchet_core_RatchetCipher_externalNewSharedSecretKeyForInitiator(
    JNIEnv *env,
    __unused jclass clazz,
    jobject self_key_pair,
    jobject recipient_public_key
) {
  // KeyPair object
  jclass key_pair_class = Jni_get_class(env, "app/junhyounglee/ratchet/core/KeyPair");
  jfieldID field_public_key = Jni_get_object_field_id(env, key_pair_class, "publicKey", "Ljava/nio/ByteBuffer;");
  jfieldID field_secret_key = Jni_get_object_field_id(env, key_pair_class, "secretKey", "Ljava/nio/ByteBuffer;");
  jobject self_public_key = Jni_get_object_field(env, self_key_pair, field_public_key);
  jobject self_secret_key = Jni_get_object_field(env, self_key_pair, field_secret_key);
  uint8_t* self_public_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, self_public_key);
  uint8_t* self_secret_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, self_secret_key);
  uint8_t* recipient_public_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, recipient_public_key);

  // byte buffer for (initiator's shared secret key)
  jobject shared_secret_key = Jni_allocate_direct_byte_buffer(env, crypto_kx_SESSIONKEYBYTES);
  uint8_t* shared_secret_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, shared_secret_key);

  // TODO 아래의 함수가 크래쉬가 나지 않는다는 것을 보장해야한다. 리턴값으로 예외처리를 할 것.
  ratchet_create_shared_secret_for_initiator(
      shared_secret_key_bytes,
      self_public_key_bytes,
      self_secret_key_bytes,
      recipient_public_key_bytes
  );

  return shared_secret_key;
}

JNIEXPORT jbyteArray JNICALL
Java_app_junhyounglee_ratchet_core_RatchetCipher_externalNewSharedSecretKeyForRecipient(
    JNIEnv *env,
    __unused jclass clazz,
    jobject self_key_pair,
    jobject initiator_public_key
) {
  // KeyPair object
  jclass key_pair_class = Jni_get_class(env, "app/junhyounglee/ratchet/core/KeyPair");
  jfieldID field_public_key = Jni_get_object_field_id(env, key_pair_class, "publicKey", "Ljava/nio/ByteBuffer;");
  jfieldID field_secret_key = Jni_get_object_field_id(env, key_pair_class, "secretKey", "Ljava/nio/ByteBuffer;");
  jobject self_public_key = Jni_get_object_field(env, self_key_pair, field_public_key);
  jobject self_secret_key = Jni_get_object_field(env, self_key_pair, field_secret_key);
  uint8_t* self_public_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, self_public_key);
  uint8_t* self_secret_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, self_secret_key);
  uint8_t* initiator_public_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, initiator_public_key);

  // byte buffer for (recipient's shared secret key)
  jobject shared_secret_key = Jni_allocate_direct_byte_buffer(env, crypto_kx_SESSIONKEYBYTES);
  uint8_t* shared_secret_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, shared_secret_key);

  // TODO 아래의 함수가 크래쉬가 나지 않는다는 것을 보장해야한다. 리턴값으로 예외처리를 할 것.
  ratchet_create_shared_secret_for_recipient(
      shared_secret_key_bytes,
      self_public_key_bytes,
      self_secret_key_bytes,
      initiator_public_key_bytes
  );

  return shared_secret_key;
}

/**
 * Generates a ratchet session state java object for initiator.
 *
 * NOTE
 * sodium_init() method must be called before run this methods.
 *
 * @param env
 * @param clazz
 * @param self_key_pair initiator's key pair object
 * @param recipient_public_key
 * @return RatchetSessionState java instance that has native ratchet state.
 */
JNIEXPORT jobject JNICALL
Java_app_junhyounglee_ratchet_core_RatchetCipher_externalSessionSetUpForInitiator(
    JNIEnv *env,
    __unused jclass clazz,
    jobject self_key_pair,
    jobject recipient_public_key
) {
  //sodium_init();

  // 1. self_key_pair -> key_pair
  jclass key_pair_class = Jni_get_class(env, "app/junhyounglee/ratchet/core/KeyPair");
  jfieldID field_public_key = Jni_get_object_field_id(env, key_pair_class, "publicKey", "Ljava/nio/ByteBuffer;");
  jfieldID field_secret_key = Jni_get_object_field_id(env, key_pair_class, "secretKey", "Ljava/nio/ByteBuffer;");
  jobject self_public_key = Jni_get_object_field(env, self_key_pair, field_public_key);
  jobject self_secret_key = Jni_get_object_field(env, self_key_pair, field_secret_key);
  uint8_t* self_public_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, self_public_key);
  uint8_t* self_secret_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, self_secret_key);
  uint8_t* recipient_public_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, recipient_public_key);

  // 2. shared secret
  uint8_t shared_secret_key[crypto_kx_SESSIONKEYBYTES];
  ratchet_create_shared_secret_for_initiator(
      shared_secret_key,
      self_public_key_bytes,
      self_secret_key_bytes,
      recipient_public_key_bytes
  );

  // 3. generate ratchet session state
  ratchet* ratchet = sodium_malloc(sizeof(struct ratchet));
  ratchet_session_setup_for_initiator(ratchet, shared_secret_key, recipient_public_key_bytes);

  // 4. create RatchetSessionState object with native state object as construct parameter.
  jclass session_state_class = Jni_get_class(
      env,
      "app/junhyounglee/ratchet/core/RatchetSessionState"
  );
  jmethodID constructor = get_object_method_id(env, session_state_class, "<init>", "(J)V");

  jlong ref = pointer_to_java_address(ratchet);
  return (*env)->NewObject(env, session_state_class, constructor, ref);
}

JNIEXPORT jobject JNICALL
Java_app_junhyounglee_ratchet_core_RatchetCipher_externalSessionSetUpForRecipient(
    JNIEnv *env,
    __unused jclass clazz,
    jobject self_key_pair,
    jobject initiator_public_key
) {
  //sodium_init();

  // 1. self_key_pair -> key_pair
  jclass key_pair_class = Jni_get_class(env, "app/junhyounglee/ratchet/core/KeyPair");
  jfieldID field_public_key = Jni_get_object_field_id(env, key_pair_class, "publicKey", "Ljava/nio/ByteBuffer;");
  jfieldID field_secret_key = Jni_get_object_field_id(env, key_pair_class, "secretKey", "Ljava/nio/ByteBuffer;");
  jobject self_public_key = Jni_get_object_field(env, self_key_pair, field_public_key);
  jobject self_secret_key = Jni_get_object_field(env, self_key_pair, field_secret_key);
  uint8_t* self_public_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, self_public_key);
  uint8_t* self_secret_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, self_secret_key);
  uint8_t* initiator_public_key_bytes = (uint8_t*)(*env)->GetDirectBufferAddress(env, initiator_public_key);

  // 2. shared secret
  uint8_t shared_secret_key[crypto_kx_SESSIONKEYBYTES];
  ratchet_create_shared_secret_for_recipient(
      shared_secret_key,
      self_public_key_bytes,
      self_secret_key_bytes,
      initiator_public_key_bytes);

  // 3. generate ratchet session state
  ratchet* ratchet = sodium_malloc(sizeof(struct ratchet));
  ratchet_session_setup_for_initiator(ratchet, shared_secret_key, initiator_public_key_bytes);

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
