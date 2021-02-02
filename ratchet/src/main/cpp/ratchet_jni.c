#include <jni.h>
#include <string.h>
#include <android/log.h>

#include "ratchet.h"

#define LOG_TAG "RATCHET>"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

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
  ratchet_key_pair key_pair;
  ratchet_create_key_pair(&key_pair);

  // byte buffer for (public_key or secret_key)
  jbyteArray public_key = (*env)->NewByteArray(env, crypto_kx_PUBLICKEYBYTES);
  jbyteArray secret_key = (*env)->NewByteArray(env, crypto_kx_SECRETKEYBYTES);

  // KeyPair object
  jclass key_pair_class = (*env)->FindClass(env, "app/junhyounglee/ratchet/core/KeyPair");
  if (key_pair_class == NULL) {
    return NULL;
  }
  jmethodID constructor = (*env)->GetMethodID(env, key_pair_class, "<init>", "([B[B)V");
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
  (*env)->SetByteArrayRegion(
      env,
      // target
      public_key,
      0,
      crypto_kx_PUBLICKEYBYTES,
      // source
      (const jbyte *) key_pair.public_key
  );
  (*env)->SetByteArrayRegion(
      env,
      // target
      secret_key,
      0,
      crypto_kx_SECRETKEYBYTES,
      // source
      (const jbyte *) key_pair.secret_key
  );

  char hex[65];
  sodium_bin2hex(hex, sizeof hex, key_pair.public_key, crypto_kx_PUBLICKEYBYTES);
  LOGD("create_key_pair, public_key: %s", hex);
  sodium_bin2hex(hex, sizeof hex, key_pair.secret_key, crypto_kx_SECRETKEYBYTES);
  LOGD("create_key_pair, secret_key: %s", hex);

  return (*env)->NewObject(env, key_pair_class, constructor, public_key, secret_key);
}

JNIEXPORT jbyteArray JNICALL
Java_app_junhyounglee_ratchet_core_RatchetCipher_externalNewSharedSecretKeyForInitiator(
    JNIEnv *env,
    __unused jclass clazz,
    jobject self_key_pair,
    jbyteArray recipient_public_key
) {
  // KeyPair object
  jclass key_pair_class = (*env)->FindClass(env, "app/junhyounglee/ratchet/core/KeyPair");
  if (key_pair_class == NULL) {
    (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/AssertionError"), "KeyPair class not found.");
  }
  jfieldID field_public_key = (*env)->GetFieldID(env, key_pair_class, "publicKey", "[B");
  jfieldID field_secret_key = (*env)->GetFieldID(env, key_pair_class, "secretKey", "[B");
  if ((*env)->ExceptionCheck(env)) {
    (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/AssertionError"), "Failed to get public key from KeyPair.");
  }
  jbyteArray self_public_key = (jbyteArray)(*env)->GetObjectField(env, self_key_pair, field_public_key);
  jbyteArray self_secret_key = (jbyteArray)(*env)->GetObjectField(env, self_key_pair, field_secret_key);

  uint8_t* self_public_key_bytes = (uint8_t*)(*env)->GetByteArrayElements(env, self_public_key, 0);
  uint8_t* self_secret_key_bytes = (uint8_t*)(*env)->GetByteArrayElements(env, self_secret_key, 0);
  uint8_t* recipient_public_key_bytes = (uint8_t*)(*env)->GetByteArrayElements(env, recipient_public_key, 0);

  // byte buffer for (initiator's shared secret key)
  jbyteArray shared_secret_key = (*env)->NewByteArray(env, crypto_kx_SESSIONKEYBYTES);
  uint8_t* shared_secret_key_bytes = (uint8_t*)(*env)->GetByteArrayElements(env, shared_secret_key, 0);

  // TODO 아래의 함수가 크래쉬가 나지 않는다는 것을 보장해야한다. 리턴값으로 예외처리를 할 것.
  ratchet_create_shared_secret_for_initiator(
      shared_secret_key_bytes,
      self_public_key_bytes,
      self_secret_key_bytes,
      recipient_public_key_bytes);

  (*env)->ReleaseByteArrayElements(env, self_public_key, (jbyte*)self_public_key_bytes, 0);
  (*env)->ReleaseByteArrayElements(env, self_secret_key, (jbyte*)self_secret_key_bytes, 0);
  (*env)->ReleaseByteArrayElements(env, recipient_public_key, (jbyte*)recipient_public_key_bytes, 0);
  (*env)->ReleaseByteArrayElements(env, shared_secret_key, (jbyte*)shared_secret_key_bytes, 0);

  return shared_secret_key;
}

JNIEXPORT jbyteArray JNICALL
Java_app_junhyounglee_ratchet_core_RatchetCipher_externalNewSharedSecretKeyForRecipient(
    JNIEnv *env,
    __unused jclass clazz,
    jobject self_key_pair,
    jbyteArray initiator_public_key
) {
  // KeyPair object
  jclass key_pair_class = (*env)->FindClass(env, "app/junhyounglee/ratchet/core/KeyPair");
  if (key_pair_class == NULL) {
    (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/AssertionError"), "KeyPair class not found.");
  }
  jfieldID field_public_key = (*env)->GetFieldID(env, key_pair_class, "publicKey", "[B");
  jfieldID field_secret_key = (*env)->GetFieldID(env, key_pair_class, "secretKey", "[B");
  if ((*env)->ExceptionCheck(env)) {
    (*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/AssertionError"), "Failed to get public key from KeyPair.");
  }
  jbyteArray self_public_key = (jbyteArray)(*env)->GetObjectField(env, self_key_pair, field_public_key);
  jbyteArray self_secret_key = (jbyteArray)(*env)->GetObjectField(env, self_key_pair, field_secret_key);

  uint8_t* self_public_key_bytes = (uint8_t*)(*env)->GetByteArrayElements(env, self_public_key, 0);
  uint8_t* self_secret_key_bytes = (uint8_t*)(*env)->GetByteArrayElements(env, self_secret_key, 0);
  uint8_t* initiator_public_key_bytes = (uint8_t*)(*env)->GetByteArrayElements(env, initiator_public_key, 0);

  // byte buffer for (recipient's shared secret key)
  jbyteArray shared_secret_key = (*env)->NewByteArray(env, crypto_kx_SESSIONKEYBYTES);
  uint8_t* shared_secret_key_bytes = (uint8_t*)(*env)->GetByteArrayElements(env, shared_secret_key, 0);

  // TODO 아래의 함수가 크래쉬가 나지 않는다는 것을 보장해야한다. 리턴값으로 예외처리를 할 것.
  ratchet_create_shared_secret_for_recipient(
      shared_secret_key_bytes,
      self_public_key_bytes,
      self_secret_key_bytes,
      initiator_public_key_bytes);

  (*env)->ReleaseByteArrayElements(env, self_public_key, (jbyte*)self_public_key_bytes, 0);
  (*env)->ReleaseByteArrayElements(env, self_secret_key, (jbyte*)self_secret_key_bytes, 0);
  (*env)->ReleaseByteArrayElements(env, initiator_public_key, (jbyte*)initiator_public_key_bytes, 0);
  (*env)->ReleaseByteArrayElements(env, shared_secret_key, (jbyte*)shared_secret_key_bytes, 0);

  return shared_secret_key;
}