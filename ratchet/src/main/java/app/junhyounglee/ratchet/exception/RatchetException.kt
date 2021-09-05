package app.junhyounglee.ratchet.exception

open class RatchetException : Exception {
  constructor() : super()
  constructor(message: String) : super(message = message)
  constructor(cause: Throwable) : super(cause = cause)
  constructor(message: String, cause: Throwable): super(message = message, cause = cause)
}
