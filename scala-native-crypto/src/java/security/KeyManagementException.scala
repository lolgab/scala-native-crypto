package java.security

// ref: https://docs.oracle.com/en/java/javase/24/docs/api/java.base/java/security/KeyManagementException.html
class KeyManagementException(message: String, cause: Throwable)
    extends KeyException(message, cause) {
  def this() = this(null, null)
  def this(msg: String) = this(msg, null)
  def this(cause: Throwable) = this(null, cause)
}

object KeyManagementException {
  private final val serialVersionUID = 947674216157062695L;
}
