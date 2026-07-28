package javax.security.auth.callback

class UnsupportedCallbackException(
    callback: Callback,
    message: String = null
) extends Exception(message) {
  def getCallback(): Callback = callback
}
