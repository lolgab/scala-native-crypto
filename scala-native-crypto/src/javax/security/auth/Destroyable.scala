package javax.security.auth

trait Destroyable {
  def destroy(): Unit

  def isDestroyed(): Boolean
}
