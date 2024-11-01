package javax.crypto.spec

import javax.crypto.SecretKey
import java.security.spec.KeySpec

class SecretKeySpec(key: Array[Byte], algorithm: String)
    extends KeySpec
    with SecretKey {
  if (key == null || algorithm == null) {
    throw new IllegalArgumentException("Missing argument")
  }
  if (key.isEmpty) {
    throw new IllegalArgumentException("Empty key")
  }

  def getAlgorithm(): String = algorithm
  def getEncoded(): Array[Byte] = key
  def getFormat(): String = ???
}
