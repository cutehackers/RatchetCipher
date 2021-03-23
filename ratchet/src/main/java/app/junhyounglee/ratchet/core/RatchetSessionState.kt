package app.junhyounglee.ratchet.core

data class RatchetSessionState(internal val externalRef: Long): Destroyable {

  val isValidRef: Boolean = externalRef != 0L

  override fun destroy() {
    RatchetCipher.externalFreeSessionState(externalRef)
  }
}