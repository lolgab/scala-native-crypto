package javax.security.auth

/**
 * Refs:
 *
 *   - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/javax/security/auth/Destroyable.html
 */
trait Destroyable {
  def destroy(): Unit
  def isDestroyed(): Boolean
}
