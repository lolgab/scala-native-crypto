package scalanativecrypto

import utest._

import java.security._
import java.util.UUID

/**
 * Tests for [[SecureRandom]
 */
object SecureRandomSuite extends TestSuite {

  val tests = Tests {
    test("basicSecureRandomTest") {
      val bytes = new Array[Byte](100)
      val random = new SecureRandom()
      random.nextBytes(bytes)
      assert(bytes.exists(_ != 0))
    }

    test("basicRandomUUIDTest") {
      val uuid1 = UUID.randomUUID()
      assert(uuid1.variant() == 2)
      assert(uuid1.version() == 4)

      val uuid2 = UUID.randomUUID()
      assert(uuid2.variant() == 2)
      assert(uuid2.version() == 4)

      assert(uuid1 != uuid2)
    }

    test("basicNextIntTest") {
      val random = new SecureRandom()
      var or = 0
      for (_ <- 0 until 100) {
        or |= random.nextInt()
      }
      assert(or != 0)
    }
  }
}
