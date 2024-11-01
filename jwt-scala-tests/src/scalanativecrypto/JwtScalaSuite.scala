package scalanativecrypto

import utest._
import pdi.jwt.{JwtUpickle, JwtAlgorithm, JwtClaim}
import java.time.Instant
import scala.util.{Failure, Success}

object JwtExampleSuite extends TestSuite {

  val tests = Tests {
    test("JWT should be correctly generated, signed, and verified") {
      // Define a secret key for signing the JWT
      val secretKey = "your-secret-key"

      val claimContent = """{"user":"exampleUser","role":"admin"}"""
      val expiration =
        Some(7284447535L) // We will be all dead when this expires
      // Create a claim (payload) for the JWT
      val claim = JwtClaim(
        content = claimContent,
        expiration = expiration
      )

      // Encode (sign) the JWT using HMAC SHA-256
      val token = JwtUpickle.encode(claim, secretKey, JwtAlgorithm.HS256)
      assert(
        token == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjcyODQ0NDc1MzUsInVzZXIiOiJleGFtcGxlVXNlciIsInJvbGUiOiJhZG1pbiJ9.nGh3SFGmePsMPl4J9Jg5qFQ6FkVss6M5lh7QXwTB-44"
      )

      // Decode and verify the token
      JwtUpickle.decode(token, secretKey, Seq(JwtAlgorithm.HS256)) match {
        case Success(decodedClaim) =>
          assert(decodedClaim.content == claimContent) // Check payload
          assert(decodedClaim.expiration == expiration) // Check expiration
        case Failure(exception) =>
          sys.error(
            s"JWT verification failed with error: ${exception.getMessage}"
          )
      }
    }
  }
}
