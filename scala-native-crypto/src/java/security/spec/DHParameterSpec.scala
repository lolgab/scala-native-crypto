package javax.crypto.spec

import java.math.BigInteger
import java.security.spec.AlgorithmParameterSpec
import java.util.concurrent.ThreadLocalRandom

// Refs:
// - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/javax/crypto/spec/DHParameterSpec
class DHParameterSpec(p: BigInteger, g: BigInteger, l: Int)
    extends AlgorithmParameterSpec {

  def this(p: BigInteger, g: BigInteger) =
    this(p, g, ThreadLocalRandom.current().nextInt())

  def getP(): BigInteger = p

  def getG(): BigInteger = g

  def getL(): Int = l

}
