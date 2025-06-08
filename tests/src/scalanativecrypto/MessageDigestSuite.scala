package scalanativecrypto

import utest._

import java.security._
import javax.crypto.spec._

/** Tests for [[MessageDigest]] class fields and methods
  */
object MessageDigestSuite extends TestSuite {
  private def checkStringResult(
      algorithm: String,
      input: String,
      expected: Array[Byte]
  ): Unit = {
    val instance = MessageDigest.getInstance(algorithm)
    val result = instance.digest(input.getBytes("UTF-8"))

    assert(result.sameElements(expected))
  }

  val tests = Tests {
    test("memoryLeak") {
      // tests that we can construct many instances without
      // double free crashes due to bad finalizer
      for (_ <- 0 to 100) { MessageDigest.getInstance("MD5") }
      ()
    }
    test("basicMd5DigestTest") {
      checkStringResult(
        "MD5",
        "Hello world!",
        Array[Byte](-122, -5, 38, -99, 25, 13, 44, -123, -10, -32, 70, -116,
          -20, -92, 42, 32)
      )
    }

    test("emptyMd5DigestTest") {
      checkStringResult(
        "MD5",
        "",
        Array[Byte](-44, 29, -116, -39, -113, 0, -78, 4, -23, -128, 9, -104,
          -20, -8, 66, 126)
      )
    }

    test("basicSHA1DigestTest") {
      checkStringResult(
        "SHA-1",
        "Hello world!",
        Array[Byte](-45, 72, 106, -23, 19, 110, 120, 86, -68, 66, 33, 35, -123,
          -22, 121, 112, -108, 71, 88, 2)
      )
    }

    test("variousUpdatesSHA1DigestTest") {
      val instance = MessageDigest.getInstance("SHA-1")
      instance.update("He".getBytes("UTF-8"))
      instance.update("****llo****".getBytes("UTF-8"), 4, 3)
      instance.update(' '.toByte)
      instance.update('w'.toByte)
      instance.update('o'.toByte)
      val result = instance.digest("rld!".getBytes("UTF-8"))
      val expected = Array[Byte](-45, 72, 106, -23, 19, 110, 120, 86, -68, 66,
        33, 35, -123, -22, 121, 112, -108, 71, 88, 2)

      assert(result.sameElements(expected))
    }

    test("digestWithResultBuffer") {
      val instance = MessageDigest.getInstance("SHA")
      instance.update("***Hello world!***".getBytes("UTF-8"), 3, 12)
      val buf = new Array[Byte](30)
      val digestLength = instance.digest(buf, 5, 25)
      digestLength ==> 20
      val result = buf.slice(5, 25)

      val expected = Array[Byte](-45, 72, 106, -23, 19, 110, 120, 86, -68, 66,
        33, 35, -123, -22, 121, 112, -108, 71, 88, 2)
      assert(result.sameElements(expected))
    }

    test("basicSHA224Digest") {
      checkStringResult(
        "SHA-224",
        "Hello world!",
        Array[Byte](
          126, -127, -21, -23, -26, 4, -96, -55, 127, -17, 14, 76, -2, 113, -7,
          -70, 14, -53, -95, 51, 50, -67, -23, 83, -83, 28, 102, -28
        )
      )
    }

    test("basicSHA256Digest") {
      checkStringResult(
        "SHA-256",
        "Hello world!",
        Array[Byte](
          -64, 83, 94, 75, -30, -73, -97, -3, -109, 41, 19, 5, 67, 107, -8,
          -119, 49, 78, 74, 63, -82, -64, 94, -49, -4, -69, 125, -13, 26, -39,
          -27, 26
        )
      )
    }

    test("basicSHA384Digest") {
      checkStringResult(
        "SHA-384",
        "Hello world!",
        Array[Byte](
          -122, 37, 95, -94, -61, 110, 75, 48, -106, -98, -82, 23, -36, 52, -57,
          114, -53, -21, -33, -59, -117, 88, 64, 57, 0, -66, -121, 97, 78, -79,
          -93, 75, -121, -128, 38, 63, 37, 94, -75, -26, 92, -87, -69, -72, 100,
          28, -52, -2
        )
      )
    }

    test("basicSHA512Digest") {
      checkStringResult(
        "SHA-512",
        "Hello world!",
        Array[Byte](
          -10, -51, -30, -96, -8, 25, 49, 76, -35, -27, 95, -62, 39, -40, -41,
          -38, -29, -46, -116, -59, 86, 34, 42, 10, -118, -42, 109, -111, -52,
          -83, 74, -83, 96, -108, -11, 23, -94, 24, 35, 96, -55, -86, -49, 106,
          61, -61, 35, 22, 44, -74, -3, -116, -33, -2, -37, 15, -32, 56, -11,
          94, -123, -1, -75, -74
        )
      )
    }

    test("basicSHA3-224Digest") {
      checkStringResult(
        "SHA3-224",
        "Hello world!",
        Array[Byte](
          -45, -18, -101, 27, -95, -103, 15, -20, -3, 121, 77, 47, 48, -32, 32,
          122, -86, 123, -27, -45, 125, 70, 48, 115, 9, 109, -122, -8
        )
      )
    }

    test("basicSHA3-256Digest") {
      checkStringResult(
        "SHA3-256",
        "Hello world!",
        Array[Byte](
          -42, -22, -113, -102, 31, 34, -31, 41, -114, 90, -107, 6, -67, 6, 111,
          35, -52, 86, 0, 31, 93, 54, 88, 35, 68, -90, 40, 100, -99, -11, 58,
          -24
        )
      )
    }

    test("basicSHA3-384Digest") {
      checkStringResult(
        "SHA3-384",
        "Hello world!",
        Array[Byte](
          -7, 33, 5, 17, -48, -78, -122, 43, -36, -74, 114, -38, -93, -10, -92,
          40, 69, 118, -52, -78, 77, 91, 41, 59, 54, 107, 57, -62, 76, 65, -90,
          -111, -124, 100, 3, 94, -60, 70, 107, 18, -30, 32, 86, -65, 85, -100,
          122, 73
        )
      )
    }

    test("basicSHA3-512Digest") {
      checkStringResult(
        "SHA3-512",
        "Hello world!",
        Array[Byte](
          -107, -34, -52, 114, -16, -91, 10, -28, -39, -43, 55, -114, 27, 34,
          82, 88, 124, -4, 113, -105, 126, 67, 41, 44, -113, 27, -124, 100,
          -126, 72, 80, -97, 27, -63, -117, -58, -16, -80, -48, -72, 96, 106,
          100, 62, -1, 97, -42, 17, -82, -124, -26, -5, -44, -94, 104, 49, 101,
          112, 107, -42, -3, 72, -77, 52
        )
      )
    }

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
