package java.security

import javax.security.auth.Destroyable

// https://docs.oracle.com/en/java/javase/24/docs/api/java.base/java/security/PrivateKey.html
trait PrivateKey extends AsymmetricKey with Destroyable {}
