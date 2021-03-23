package app.junhyounglee.ratchet.core

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.nio.charset.Charset

@RunWith(AndroidJUnit4::class)
class RatchetCipherTest {

  @Before
  fun setUp() {
    RatchetCipher.externalInit()
  }

  @Test
  fun testNewKeyPair() {
    val keyPair: KeyPair = RatchetCipher.externalNewKeyPair()
    assertEquals(RatchetCipher.PUBLIC_KEY_SIZE, keyPair.publicKey.capacity())
    assertEquals(RatchetCipher.SECRET_KEY_SIZE, keyPair.secretKey.capacity())
  }

  @Test
  fun testNewSharedSecretKey() {
    val initiator: KeyPair = RatchetCipher.externalNewKeyPair()
    val recipient: KeyPair = RatchetCipher.externalNewKeyPair()

    val initiatorSharedSecretKey = RatchetCipher.externalNewSharedSecretKeyForInitiator(
      initiator,
      recipient.publicKey
    )
    val recipientSharedSecretKey = RatchetCipher.externalNewSharedSecretKeyForRecipient(
      recipient,
      initiator.publicKey
    )

    assertTrue(initiatorSharedSecretKey.capacity() == RatchetCipher.SESSION_KEY_SIZE)
    assertTrue(recipientSharedSecretKey.capacity() == RatchetCipher.SESSION_KEY_SIZE)
    (0 until RatchetCipher.SESSION_KEY_SIZE).forEach {
      assertTrue(initiatorSharedSecretKey[it] == recipientSharedSecretKey[it])
    }

    initiator.destroy()
    recipient.destroy()
    JniCommon.externalFreeByteBuffer(initiatorSharedSecretKey)
    JniCommon.externalFreeByteBuffer(recipientSharedSecretKey)
  }

  @Test
  fun testSessionSetUpForInitiator() {
    val initiator: KeyPair = RatchetCipher.externalNewKeyPair()
    val recipient: KeyPair = RatchetCipher.externalNewKeyPair()

    val initiatorSessionState: RatchetSessionState = RatchetCipher.externalSessionSetUpForInitiator(
      initiator,
      recipient.publicKey
    )

    assertTrue(initiatorSessionState.isValidRef)

    initiator.destroy()
    recipient.destroy()
    initiatorSessionState.destroy() // <- free native memory
  }

  @Test
  fun testSessionSetUpForRecipient() {
    val initiator: KeyPair = RatchetCipher.externalNewKeyPair()
    val recipient: KeyPair = RatchetCipher.externalNewKeyPair()

    val recipientSessionState: RatchetSessionState = RatchetCipher.externalSessionSetUpForRecipient(
      recipient,
      initiator.publicKey
    )

    assertTrue(recipientSessionState.isValidRef)

    initiator.destroy()
    recipient.destroy()
    recipientSessionState.destroy() // <- free native memory
  }

  @Test
  fun testRatchetCipher() {
    val initiator: KeyPair = RatchetCipher.externalNewKeyPair()
    val recipient: KeyPair = RatchetCipher.externalNewKeyPair()

    val initiatorSessionState: RatchetSessionState = RatchetCipher.externalSessionSetUpForInitiator(
      initiator,
      recipient.publicKey
    )
    val recipientSessionState: RatchetSessionState = RatchetCipher.externalSessionSetUpForRecipient(
      recipient,
      initiator.publicKey
    )

    assertTrue(initiatorSessionState.isValidRef)

    // TODO 지정된 public, secret key를 사용해서 KeyPair 만들어 테스트하기

    val sample = "Hello World!"
    val encrypted: ByteArray = RatchetCipher.externalEncrypt(initiatorSessionState.externalRef, plain = sample.toByteArray())
    assertTrue(encrypted.isNotEmpty())
    //val encryptedString = encrypted.toHex()

    val plain: ByteArray = RatchetCipher.externalDecrypt(recipientSessionState.externalRef, encrypted)
    val result = String(plain, Charset.forName("UTF8"))
    assertEquals("Hello World!", result)

    initiator.destroy()
    recipient.destroy()
    initiatorSessionState.destroy() // <- free native memory
    recipientSessionState.destroy() // <- free native memory
  }
}