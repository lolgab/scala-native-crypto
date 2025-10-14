package java.security

class InvalidKeyException(msg: String, cause: Throwable)
    extends KeyException(msg, cause) {
  def this() = this(null, null)
  def this(msg: String) = this(msg, null)
  def this(cause: Throwable) = this(null, cause)
}
