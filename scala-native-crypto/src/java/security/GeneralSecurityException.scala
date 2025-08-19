package java.security

// ref: https://docs.oracle.com/en/java/javase/24/docs/api/java.base/java/security/GeneralSecurityException.html
class GeneralSecurityException(message: String, cause: Throwable)
    extends Exception(message, cause) {
  def this(msg: String) = this(msg, null)
  def this(cause: Throwable) = this(null, cause)
}

object GeneralSecurityException {
  private final val serialVersionUID = 894798122053539237L
}
