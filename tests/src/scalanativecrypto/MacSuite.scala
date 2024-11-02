package scalanativecrypto

import utest._

import java.util.Base64
import javax.crypto._
import javax.crypto.spec._

object MacSuite extends TestSuite {
  val tests = Tests {
    test("HMAC") {
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
    test("update not initialized") {
      val e = intercept[IllegalStateException](
        Mac.getInstance("HmacSHA256").update(Array[Byte]())
      )
      assert(e.getMessage == "MAC not initialized")
    }
    test("doFinal not initialized") {
      val e = intercept[IllegalStateException](
        Mac.getInstance("HmacSHA256").doFinal(Array[Byte]())
      )
      assert(e.getMessage == "MAC not initialized")
    }
  }
}
