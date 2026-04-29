package javax.security.auth

class KeyStDestroyFailedExceptionoreException(msg: String, cause: Throwable)
    extends Exception(msg, cause) {
  def this() = this(null, null)
  def this(msg: String) = this(msg, null)
}
