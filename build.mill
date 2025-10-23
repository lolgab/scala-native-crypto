//| mill-version: 1.0.6
//| mvnDeps:
//|   - com.goyeau::mill-scalafix::0.6.0
//|   - com.lihaoyi::mill-contrib-buildinfo:$MILL_VERSION

package build

import mill._, mill.scalalib._, mill.scalanativelib._, mill.scalanativelib.api._
import mill.javalib.api.JvmWorkerUtil.isScala3
import mill.scalalib.publish._
import mill.util.Jvm
import com.goyeau.mill.scalafix.ScalafixModule
import mill.util.VcsVersion
import mill.contrib.buildinfo.BuildInfo

val scala212 = "2.12.20"
val scala213 = "2.13.17"
val scala3 = "3.3.6"
val scalaVersions = Seq(scala212, scala213, scala3)

trait Shared
    extends CrossScalaModule
    with ScalafixModule
    with ScalaNativeModule {
  def organization = "com.github.lolgab"
  def scalaNativeVersion = "0.5.8"

  def scalacOptions =
    super.scalacOptions() ++ (if (isScala3(crossScalaVersion)) Seq()
                              else Seq("-Ywarn-unused"))
}

trait Test extends TestModule.Utest {
  override def mvnDeps = super.mvnDeps() ++ Seq(
    mvn"com.lihaoyi::utest::0.8.3"
  )
}

trait Publish extends PublishModule {
  def pomSettings =
    PomSettings(
      description =
        "Scala Native java.security implementation based on OpenSSL",
      organization = "com.github.lolgab",
      url = "https://github.com/lolgab/scala-native-crypto",
      licenses = Seq(License.`Apache-2.0`),
      versionControl =
        VersionControl.github(owner = "lolgab", repo = "scala-native-crypto"),
      developers = Seq(
        Developer("lolgab", "Lorenzo Gabriele", "https://github.com/lolgab")
      )
    )
  def publishVersion = VcsVersion.vcsState().format()
}
object `scala-native-crypto`
    extends Cross[ScalaNativeCryptoModule](scalaVersions)
trait ScalaNativeCryptoModule extends Shared with Publish {
  def compileModuleDeps = Seq(`scala-native-crypto-javalib-shims`())
  def scalacOptions = super.scalacOptions() ++ Seq(
    "-P:scalanative:genStaticForwardersForNonTopLevelObjects"
  )
  // Remove class and tasty files
  override def jar = Task {
    val jar = Task.dest / "out.jar"
    Jvm.createJar(
      jar,
      localClasspath().map(_.path).filter(os.exists),
      manifest(),
      (_, file) =>
        file.ext match {
          case "class" | "tasty" => false
          case _                 => true
        }
    )
    PathRef(jar)
  }
}

object `scala-native-crypto-javalib-shims`
    extends Cross[ScalaNativeCryptoJavalibShimsModule](scalaVersions)
trait ScalaNativeCryptoJavalibShimsModule extends Shared

def jwtScalaSources = Task {
  val dest = Task.dest
  os.proc(
    "git",
    "clone",
    "--branch",
    "v10.0.2",
    "--depth",
    "1",
    "https://github.com/jwt-scala/jwt-scala.git",
    dest
  ).call()
  PathRef(dest)
}

object tests extends Module {
  object jvm extends Cross[TestsJvmModule](scalaVersions)
  trait TestsJvmModule extends CrossScalaModule with Test {
    override def moduleDir = super.moduleDir / os.up
  }

  object native extends Cross[TestsNativeModule](scalaVersions)
  trait TestsNativeModule
      extends CrossScalaModule
      with Shared
      with Test
      with TestScalaNativeModule {
    override def moduleDeps =
      super.moduleDeps ++ Seq(`scala-native-crypto`(crossScalaVersion))
    override def moduleDir = super.moduleDir / os.up
  }
}

object `jwt-scala-tests` extends Module {
  trait SharedJwtScalaTestsModule extends ScalaModule {
    override def generatedSources = super.generatedSources() ++ Seq(
      PathRef(
        jwtScalaSources().path / "core" / "shared" / "src" / "main" / "scala"
      ),
      PathRef(
        jwtScalaSources().path / "json" / "upickle" / "shared" / "src" / "main" / "scala"
      ),
      PathRef(
        jwtScalaSources().path / "json" / "common" / "src" / "main" / "scala"
      )
    )
    override def mvnDeps = super.mvnDeps() ++ Seq(
      mvn"com.lihaoyi::upickle::3.3.1"
    )
  }

  object jvm extends Cross[JwtScalaTestsJvmModule](scala3)
  trait JwtScalaTestsJvmModule
      extends CrossScalaModule
      with SharedJwtScalaTestsModule
      with Test {
    override def moduleDir = super.moduleDir / os.up
  }

  object native extends Cross[JwtScalaTestsNativeModule](scala3)
  trait JwtScalaTestsNativeModule
      extends CrossScalaModule
      with SharedJwtScalaTestsModule
      with Shared
      with Test
      with TestScalaNativeModule {
    override def moduleDeps =
      super.moduleDeps ++ Seq(`scala-native-crypto`(crossScalaVersion))
    override def moduleDir = super.moduleDir / os.up

    override def mvnDeps = super.mvnDeps() ++ Seq(
      mvn"io.github.cquiroz::scala-java-time::2.6.0"
    )
  }
}
