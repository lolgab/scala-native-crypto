package javax.net.ssl

import java.io.IOException

// @since 1.4
// public api: https://docs.oracle.com/en/java/javase/24/docs/api/java.base/javax/net/ssl/SSLException.html
class SSLException(message: String, cause: Throwable)
    extends IOException(message, cause) {
  def this(reason: String) = this(reason, null)
  def this(cause: Throwable) = this(null, cause)
}

object SSLException {
  private final val serialVersionUID = 4511006460650708967L;
}
