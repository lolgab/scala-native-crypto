package java.security

class KeyManagementException(message: String, cause: Throwable)
    extends KeyException(message, cause) {
  def this() = this(null, null)
  def this(msg: String) = this(msg, null)
  def this(cause: Throwable) = this(null, cause)
}
