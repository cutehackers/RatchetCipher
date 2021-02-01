package app.junhyounglee.ratchet.core

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RatchetCipherTest {

  @Before
  fun setUp() {
    RatchetCipher.externalInit()
  }

  @Test
  fun testNewKeyPair() {
    val keyPair: KeyPair = RatchetCipher.externalNewKeyPair()
    assertEquals(RatchetCipher.PUBLIC_KEY_SIZE, keyPair.publicKey.size)
    assertEquals(RatchetCipher.SECRET_KEY_SIZE, keyPair.secretKey.size)
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

    assertTrue(initiatorSharedSecretKey.size == RatchetCipher.SESSION_KEY_SIZE)
    assertTrue(recipientSharedSecretKey.size == RatchetCipher.SESSION_KEY_SIZE)
    (0 until RatchetCipher.SESSION_KEY_SIZE).forEach {
      assertTrue(initiatorSharedSecretKey[it] == recipientSharedSecretKey[it])
    }
  }
}