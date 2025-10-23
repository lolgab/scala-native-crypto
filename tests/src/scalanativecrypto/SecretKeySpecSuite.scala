package scalanativecrypto

import utest._

import javax.crypto.spec._

/** Tests for [[MessageDigest]] class fields and methods
  */
object SecretKeySpecSuite extends TestSuite {
  val tests = Tests {
    test("SecretKeySpec") {
      test("null key") {
        val ex = intercept[IllegalArgumentException] {
          new SecretKeySpec(null, "")
        }
        ex.getMessage() ==> "Missing argument"
      }
      test("null algorithm") {
        val ex = intercept[IllegalArgumentException] {
          new SecretKeySpec(Array.emptyByteArray, null)
        }
        ex.getMessage() ==> "Missing argument"
      }
      test("empty key") {
        val ex = intercept[IllegalArgumentException] {
          new SecretKeySpec(Array.emptyByteArray, "")
        }
        ex.getMessage() ==> "Empty key"
      }
    }
  }
}
