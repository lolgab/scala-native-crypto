package java.security

class KeyException(message: String, cause: Throwable)
    extends GeneralSecurityException(message, cause) {
  def this() = this(null, null)
  def this(msg: String) = this(msg, null)
  def this(cause: Throwable) = this(null, cause)
}
