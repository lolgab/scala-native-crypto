package scalanativecrypto

import utest.TestSuite
import utest.Tests
import utest.test

import java.security.CryptoPrimitive

object CryptoPrimitiveSuite extends TestSuite {

  val tests = Tests {
    test("CryptoPrimitive.values()") {
      val values = CryptoPrimitive.values()
      assert(values.length == 10)
      val allValues = Array(
        CryptoPrimitive.BLOCK_CIPHER,
        CryptoPrimitive.KEY_AGREEMENT,
        CryptoPrimitive.KEY_ENCAPSULATION,
        CryptoPrimitive.KEY_WRAP,
        CryptoPrimitive.MAC,
        CryptoPrimitive.MESSAGE_DIGEST,
        CryptoPrimitive.PUBLIC_KEY_ENCRYPTION,
        CryptoPrimitive.SECURE_RANDOM,
        CryptoPrimitive.SIGNATURE,
        CryptoPrimitive.STREAM_CIPHER
      )
      assert(values.toSet.diff(allValues.toSet).isEmpty)
    }

    test("CryptoPrimitive.valueOf()") {
      CryptoPrimitive
        .values()
        .foreach(v => {
          val name = v.name()
          val ins = CryptoPrimitive.valueOf(name)
          assert(ins == v)
        })
    }
  }
}
