package java.security

class InvalidParameterException(msg: String, cause: Throwable)
    extends IllegalArgumentException(msg, cause) {
  def this() = this(null, null)
  def this(msg: String) = this(msg, null)
  def this(cause: Throwable) = this(null, cause)
}
