package javax.crypto

import java.security.Key
import javax.security.auth.Destroyable

trait SecretKey extends Key with Destroyable {}
