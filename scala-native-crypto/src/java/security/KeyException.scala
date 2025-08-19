package java.security

// ref: https://docs.oracle.com/en/java/javase/24/docs/api/java.base/java/security/KeyException.html
class KeyException(message: String, cause: Throwable)
    extends GeneralSecurityException(message, cause) {
  def this(msg: String) = this(msg, null)
  def this(cause: Throwable) = this(null, cause)
}
