package app.junhyounglee.ratchet

import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import app.junhyounglee.ratchet.core.RatchetCipher
import app.junhyounglee.ratchet.core.toHex

class MainActivity : AppCompatActivity() {

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)

    setContentView(R.layout.activity_main)
  }

  override fun onResume() {
    super.onResume()
    RatchetCipher.externalInit()

    val keyPair = RatchetCipher.externalNewKeyPair()
    Log.d("RATCHET>", "public-key: ${keyPair.publicKey.toHex()}")
    Log.d("RATCHET>", "secret-key: ${keyPair.secretKey.toHex()}")
  }
}