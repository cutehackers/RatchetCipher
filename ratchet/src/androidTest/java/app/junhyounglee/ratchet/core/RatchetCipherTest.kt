package app.junhyounglee.ratchet.core

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
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
    val serverKeyPair: KeyPair = RatchetCipher.externalNewKeyPair()
    val clientKeyPair: KeyPair = RatchetCipher.externalNewKeyPair()

    val serverSharedSecretKey = RatchetCipher.externalNewSharedSecretKeyForServer(
      serverKeyPair,
      clientKeyPair.publicKey
    )
    val clientSharedSecretKey = RatchetCipher.externalNewSharedSecretKeyForClient(
      clientKeyPair,
      serverKeyPair.publicKey
    )

    assertTrue(serverSharedSecretKey.capacity() == RatchetCipher.SESSION_KEY_SIZE)
    assertTrue(clientSharedSecretKey.capacity() == RatchetCipher.SESSION_KEY_SIZE)
    (0 until RatchetCipher.SESSION_KEY_SIZE).forEach {
      assertTrue(serverSharedSecretKey[it] == clientSharedSecretKey[it])
    }

    serverKeyPair.destroy()
    clientKeyPair.destroy()
    JniCommon.externalFreeByteBuffer(serverSharedSecretKey)
    JniCommon.externalFreeByteBuffer(clientSharedSecretKey)
  }

  @Test
  fun testSessionSetUpForServer() {
    val serverKeyPair: KeyPair = RatchetCipher.externalNewKeyPair()
    val clientKeyPair: KeyPair = RatchetCipher.externalNewKeyPair()

    val sharedSecretKey = RatchetCipher.externalNewSharedSecretKeyForServer(
      serverKeyPair = serverKeyPair,
      clientPublicKey = clientKeyPair.publicKey
    )

    val serverSessionState: RatchetSessionState = RatchetCipher.externalSessionSetUpForServer(
      sharedSecretKey,
      serverKeyPair,
      clientKeyPair.publicKey
    )

    assertTrue(serverSessionState.isValidRef)

    serverKeyPair.destroy()
    clientKeyPair.destroy()
    serverSessionState.destroy() // <- free native memory
  }

  @Test
  fun testSessionSetUpForClient() {
    val serverKeyPair: KeyPair = RatchetCipher.externalNewKeyPair()
    val clientKeyPair: KeyPair = RatchetCipher.externalNewKeyPair()

    val sharedSecretKey = RatchetCipher.externalNewSharedSecretKeyForClient(
      clientKeyPair = clientKeyPair,
      serverPublicKey = serverKeyPair.publicKey
    )

    val clientSessionState: RatchetSessionState = RatchetCipher.externalSessionSetUpForClient(
      sharedSecretKey,
      clientKeyPair
    )

    assertTrue(clientSessionState.isValidRef)

    serverKeyPair.destroy()
    clientKeyPair.destroy()
    clientSessionState.destroy() // <- free native memory
  }

  @Test
  fun testRatchetCipher() {
    val serverKeyPair: KeyPair = RatchetCipher.externalNewKeyPair()
    val clientKeyPair: KeyPair = RatchetCipher.externalNewKeyPair()

    val serverSharedSecretKey = RatchetCipher.externalNewSharedSecretKeyForServer(
      serverKeyPair,
      clientKeyPair.publicKey
    )
    val clientSharedSecretKey = RatchetCipher.externalNewSharedSecretKeyForClient(
      clientKeyPair,
      serverKeyPair.publicKey
    )

    val serverSessionState: RatchetSessionState = RatchetCipher.externalSessionSetUpForServer(
      serverSharedSecretKey,
      serverKeyPair,
      clientKeyPair.publicKey
    )
    val clientSessionState: RatchetSessionState = RatchetCipher.externalSessionSetUpForClient(
      clientSharedSecretKey,
      clientKeyPair
    )

    assertTrue(serverSessionState.isValidRef)
    assertTrue(clientSessionState.isValidRef)

    // TODO 지정된 public, secret key를 사용해서 KeyPair 만들어 테스트하기

    val sample = "Hello World!"
    val encrypted: ByteArray = RatchetCipher.externalEncrypt(serverSessionState.externalRef, plain = sample.toByteArray())
    assertTrue(encrypted.isNotEmpty())
    //val encryptedString = encrypted.toHex()

    val plain: ByteArray = RatchetCipher.externalDecrypt(clientSessionState.externalRef, encrypted)
    val result = String(plain, Charset.forName("UTF8"))
    assertEquals("Hello World!", result)

    serverKeyPair.destroy()
    clientKeyPair.destroy()
    serverSessionState.destroy() // <- free native memory
    clientSessionState.destroy() // <- free native memory
  }
}