package java.security

import java.io.{InputStream, ObjectInputStream}
import java.io.IOException
import java.util.Properties
import java.util.{Map => JMap, Set => JSet, List => JList}
import java.util.{Collections, HashMap, ArrayList, LinkedHashSet, Enumeration}
import java.util.Objects.requireNonNull
import java.util.concurrent.ConcurrentHashMap
import java.util.regex.Pattern
import java.util.function.{BiConsumer, BiFunction, Function}
import java.security.cert.CertStoreParameters
import scala.scalanative.libc.stdatomic.AtomicBool
import java.util.Collection

// Refs:
// 1. https://docs.oracle.com/en/java/javase/24/docs/api/java.base/java/security/Provider.html
// 2. https://docs.oracle.com/en/java/javase/24/security/howtoimplaprovider.html
abstract class Provider(
    private val name: String,
    private val versionStr: String,
    private val info: String
) extends Properties {

  requireNonNull(name)
  requireNonNull(versionStr)
  requireNonNull(info)
  require(name.nonEmpty && versionStr.nonEmpty && info.nonEmpty)

  private val version: Double = Provider.parseVersionStr(versionStr)
  // @volatile protected val defaults = _

  // @deprecated since JDK 9
  // def this(name: String, version: Double, info: String)

  // @since JDK 9
  def configure(configArg: String): Provider =
    throw new UnsupportedOperationException("configure is not supported")

  def isConfigured(): Boolean = true

  def getName(): String = name

  // @deprecated since JDK 9
  // def getVersion(): Double = version

  // @since JDK 9
  def getVersionStr(): String = versionStr

  def getInfo(): String = info

  override def toString(): String = s"${name} version ${versionStr}"

  def getService(svcType: String, algorithm: String): Provider.Service

  def getServices(): JSet[Provider.Service]

  protected def putService(s: Provider.Service): Unit

  protected def removeService(s: Provider.Service): Unit

  //
  // Private methods
  //

}

object Provider {
  private val versionStrPattern = Pattern.compile("^[0-9]+(\\.[0-9]+)*")
  private def parseVersionStr(vs: String): Double = {
    if (vs == null) return 0.0
    val s = vs.trim()
    if (versionStrPattern.matcher(s).lookingAt() == false) return 0.0

    val arr = s.split('.')
    arr.length match {
      case 0 => s.toDouble
      case 1 => arr(0).toDouble
      case _ => s"${arr(0)}.${arr(1)}".toDouble
    }
  }

  class Service(
      provider: Provider,
      svcType: String,
      algorithm: String,
      className: String,
      aliases: JList[String],
      attributes: JMap[String, String]
  ) {

    requireNonNull(provider)
    requireNonNull(svcType)
    requireNonNull(algorithm)
    requireNonNull(className)
    require(svcType.nonEmpty && algorithm.nonEmpty && className.nonEmpty)

    private val svcAliases: JList[String] =
      if (aliases == null) JList.of()
      else Collections.unmodifiableList(aliases)
    private val serviceAttributes: JMap[String, String] =
      if (attributes == null) JMap.of()
      else Collections.unmodifiableMap(attributes)

    final def getType(): String = svcType

    final def getAlgorithm(): String = algorithm

    final def getProvider(): Provider = provider

    final def getClassName(): String = className

    final def getAttribute(name: String): String = {
      requireNonNull(name)
      require(name.nonEmpty)
      serviceAttributes.get(name)
    }

    def newInstance(constructorParameter: Object): Object = ???

    def supportsParameter(parameter: Object): Boolean = ???

    override def toString(): String = {
      val aliasStr =
        if (svcAliases.isEmpty) ""
        else s"\r\n  aliases: ${svcAliases}"
      val attrStr =
        if (serviceAttributes.isEmpty) ""
        else s"\r\n  attributes: ${serviceAttributes}"

      s"${provider.getName()}: ${svcType}.${algorithm} -> ${className}${aliasStr}${attrStr}\r\n"
    }
  }
}
