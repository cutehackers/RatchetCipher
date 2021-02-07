package app.junhyounglee.ratchet.core

data class RatchetSessionState(private val externalRef: Long): Destroyable {

  val isValidRef: Boolean = externalRef != 0L

  override fun destroy() {
    RatchetCipher.externalFreeSessionState(externalRef)
  }
}