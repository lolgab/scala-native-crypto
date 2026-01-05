package java.security

import javax.security.auth.Destroyable

/**
 * Refs:
 *
 *   - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/PrivateKey.html
 */
trait PrivateKey extends AsymmetricKey with Destroyable {}
