package scalanativecrypto

import utest._

import java.util.Base64
import javax.crypto._
import javax.crypto.spec._

object MacSuite extends TestSuite {
  val javaVersion = java.lang.Double.parseDouble(
    System.getProperty("java.specification.version")
  )
  val isScalaNative = System.getProperty("java.vm.name") == "Scala Native"

  val mainTests = Tests {
    test("HmacSHA256") {
      val data = "Hello, World!"
      val secretKey = "my_secret_key"

      val mac = Mac.getInstance("HmacSHA256")
      val keySpec =
        new SecretKeySpec(secretKey.getBytes("UTF-8"), "HmacSHA256")
      mac.init(keySpec)
      val hmacData = mac.doFinal(data.getBytes("UTF-8"))
      val hmac =
        Base64.getEncoder.encodeToString(hmacData)

      assert(hmac == "88r11H48jN6js66Mh7ZNJH1NrPeDuNFxCDZ51TKRWcw=")
    }
    test("HmacSHA256 - update not initialized") {
      val e = assertThrows[IllegalStateException](
        Mac.getInstance("HmacSHA256").update(Array[Byte]())
      )
      assert(e.getMessage == "MAC not initialized")
    }
    test("HmacSHA256 - doFinal not initialized") {
      val e = assertThrows[IllegalStateException](
        Mac.getInstance("HmacSHA256").doFinal(Array[Byte]())
      )
      assert(e.getMessage == "MAC not initialized")
    }
  }

  val java16Tests = Tests {
    test("HmacSHA3-256") {
      val data = "Hello, World!"
      val secretKey = "my_secret_key"

      val mac = Mac.getInstance("HmacSHA3-256")
      val keySpec =
        new SecretKeySpec(secretKey.getBytes("UTF-8"), "HmacSHA3-256")
      mac.init(keySpec)
      val hmacData = mac.doFinal(data.getBytes("UTF-8"))
      val hmac =
        Base64.getEncoder.encodeToString(hmacData)

      assert(hmac == "C08oqdn7+WWRctwSsXzfPfRFtawt9hJ6YJYyW9Aib0s=")
    }
    test("HmacSHA3-256 - update not initialized") {
      val e = assertThrows[IllegalStateException](
        Mac.getInstance("HmacSHA3-256").update(Array[Byte]())
      )
      assert(e.getMessage == "MAC not initialized")
    }
    test("HmacSHA3-256 - doFinal not initialized") {
      val e = assertThrows[IllegalStateException](
        Mac.getInstance("HmacSHA3-256").doFinal(Array[Byte]())
      )
      assert(e.getMessage == "MAC not initialized")
    }
  }
  val tests =
    if (javaVersion >= 16 || isScalaNative) mainTests ++ java16Tests
    else mainTests
}
