package java.security

import java.util.{Collections, HashSet}
import java.util.{Map => JMap, Set => JSet}
import java.util.Objects.requireNonNull

import scala.util.Properties
import scala.collection.mutable.ListBuffer
import scala.collection.mutable.HashMap

/// Refs:
///
/// - https://docs.oracle.com/en/java/javase/24/docs/api/java.base/java/security/Security.html
object Security {

  // @deprecated
  // def getAlgorithmProperty(algName: String, propName: String): String

  def insertProviderAt(provider: Provider, position: Int): Int = {
    requireNonNull(provider, "provider must not be null")

    if (
      _providers
        .find(p => p.equals(provider) || p.getName() == provider.getName())
        .isDefined
    )
      return -1

    // The position is 1-based.
    // If the position is less than 1 or greater than n,
    // where n is the number of installed providers,
    // the provider is inserted at the end of the list.
    if (position < 1 || position > _providers.length) {
      _providers.append(provider)
      _providers.length
    } else {
      _providers.insert(position - 1, provider)
      position
    }
  }

  def addProvider(provider: Provider): Int = {
    requireNonNull(provider, "provider must not be null")
    if (
      _providers
        .find(p => p.equals(provider))
        .isDefined
    )
      return -1
    _providers.append(provider)
    _providers.length
  }

  def removeProvider(name: String): Unit = {
    requireNonNull(name, "name must not be null")
    require(name.nonEmpty, "name must not be empty")
    val idx = _providers.indexWhere(p => p.getName() == name)
    if (idx >= 0) _providers.remove(idx)
  }

  def getProviders(): Array[Provider] = _providers.toArray

  def getProvider(name: String): Provider =
    _providers.find(_.getName() == name).orNull

  /// According to JDK doc:
  ///
  /// The selection criterion must be specified in one of the following two formats:
  ///
  /// - `<crypto_service>.<algorithm_or_type>`
  ///   The cryptographic service name must not contain any dots.
  ///   For example, "CertificateFactory.X.509" would be satisfied by any provider
  ///   that supplied a CertificateFactory implementation for X.509 certificates.
  /// - `<crypto_service>.<algorithm_or_type> <attribute_name>:<attribute_value>`
  ///   The cryptographic service name must not contain any dots.
  ///   There must be one or more space characters between the <algorithm_or_type> and the <attribute_name>.
  ///   For example, "Signature.SHA1withDSA KeySize:1024" would be satisfied by
  ///   any provider that implemented the SHA1withDSA signature algorithm with a keysize of 1024 (or larger).
  def getProviders(filter: String): Array[Provider] = {
    requireNonNull(filter)
    require(filter.nonEmpty)

    val parts =
      filter.trim().split(' ').filter(_.nonEmpty) // aovid multiple spaces
    if (parts.length == 1) {
      // match `<crypto_service>.<algorithm_or_type>`
      val key = parts(0).trim()
      val value = ""
      getProviders(JMap.of[String, String](key, value))
    } else if (parts.length == 2) {
      // match `<crypto_service>.<algorithm_or_type> <attribute_name>:<attribute_value>`
      val key = parts(0).trim()
      val value = parts(1).trim()
      getProviders(JMap.of[String, String](key, value))
    } else
      throw new InvalidParameterException(s"Invalid filter format: '${filter}'")
  }

  def getProviders(filter: JMap[String, String]): Array[Provider] = {
    val allProviders = getProviders()
    val entries = filter.entrySet()

    if (allProviders == null || allProviders.length == 0) return null
    if (entries == null) return allProviders
    if (entries.isEmpty) return null

    ???
  }

  def getProperty(key: String): String = {
    requireNonNull(key)
    require(key.nonEmpty && !ReservedKeys.contains(key))

    _props.get(key.trim()).map(_.trim()).orNull
  }

  def setProperty(key: String, datum: String): Unit = {
    requireNonNull(key)
    requireNonNull(datum)
    require(key.nonEmpty && !ReservedKeys.contains(key) && datum.nonEmpty)

    _props.put(key.trim(), datum.trim())
  }

  def getAlgorithms(serviceName: String): JSet[String] = {
    if (serviceName == null || serviceName.isEmpty || serviceName.endsWith("."))
      return JSet.of()

    val result = new HashSet[String]()
    val providers = getProviders()
    val sn = serviceName.trim()

    for (p <- providers) {
      val services = p.getServices()
      val it = services.iterator()
      while (it.hasNext()) {
        val s = it.next()
        if (s.getClassName().equalsIgnoreCase(sn)) result.add(s.getAlgorithm())
      }
    }

    Collections.unmodifiableSet(result)
  }

  //
  // Private implementation details
  //

  private val ReservedKeys = JSet.of[String]("include")

  private val _providers: ListBuffer[Provider] = ListBuffer()

  private val _props: HashMap[String, String] = HashMap()

  // private case class ProviderEntry(name: String, provider: Provider)

  // private case class Criteria(key: String, value: String) { ??? }

}
