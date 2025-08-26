package javax.security.auth

// ref: https://docs.oracle.com/en/java/javase/24/docs/api/java.base/javax/security/auth/Destroyable.html
trait Destroyable {
  def destroy(): Unit
  def isDestroyed(): Boolean
}
