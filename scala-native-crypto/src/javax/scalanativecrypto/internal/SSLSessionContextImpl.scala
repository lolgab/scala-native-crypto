package javax.scalanativecrypto.internal

import java.util.Enumeration
import java.util.Objects.requireNonNull

import javax.net.ssl.SSLSessionContext

// TODO: Undone
class SSLSessionContextImpl(
    private var cacheSize: Int,
    private var timeout: Int
    // private val sessionId: Array[Byte],
) extends SSLSessionContext {

  def getSession(sessionId: Array[Byte]): SSLSession = {
    requireNonNull(sessionId, "sessionId must not be null")
    ???
  }

  def getIds(): Enumeration[Array[Byte]] = {
    ???
  }

  def setSessionTimeout(seconds: Int): Unit = {
    require(seconds >= 0, "Session timeout should be non-negative")
    timeout = seconds
  }

  def getSessionTimeout(): Int = timeout

  def setSessionCacheSize(size: Int): Unit = {
    require(size >= 0, "Cache size should be non-negative")
    cacheSize = size
  }

  def getSessionCacheSize(): Int = cacheSize

}

object SSLSessionContextImpl {
  def apply(
      cacheSize: Int,
      timeout: Int
      //   sessionId: Array[Byte],
  ): SSLSessionContextImpl = {
    require(
      cacheSize >= 0 && timeout >= 0,
      "Cache size and timeout should be non-negative"
    )
    new SSLSessionContextImpl(cacheSize, timeout)
  }

}
