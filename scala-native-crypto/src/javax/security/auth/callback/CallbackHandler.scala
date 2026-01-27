package javax.security.auth.callback

trait CallbackHandler {
  def handle(callbacks: Array[Callback]): Unit
}
