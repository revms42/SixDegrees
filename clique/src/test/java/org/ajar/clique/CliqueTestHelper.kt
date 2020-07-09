package org.ajar.clique

import org.ajar.clique.encryption.*
import java.security.Key
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.util.*
import javax.crypto.SecretKey

object CliqueTestHelper {

    fun createTestRSAParameters(desc: AsymmetricEncryption) : (name: String, purpose: Int) -> AlgorithmParameterSpec? =
            fun(_: String, _: Int) : RSAKeyGenParameterSpec {
                return RSAKeyGenParameterSpec(desc.keySize, RSAKeyGenParameterSpec.F4)
            }

    fun createTestAESParameters() : (name: String, purpose: Int) -> AlgorithmParameterSpec? =
            fun(_: String, _: Int) : AlgorithmParameterSpec? {
                return null
            }

    fun getOnlySupportedECDHAlgo() : SymmetricEncryption =
            EncryptionBuilder.symmetric().algorithm(AlgorithmDesc.toAlgorithm("TlsPremasterSecret")).build() as SymmetricEncryption

    fun switchCliqueConfigForJDK() {
        CliqueConfig.setStringEncoder { array:ByteArray, _:Int  ->
            Base64.getEncoder().encodeToString(array)
        }
        CliqueConfig.setByteArrayDecoder { string, _ ->
            Base64.getDecoder().decode(string)
        }
    }
}

class SymmetricEncryptionWrapper(private val wrapped: SymmetricEncryption,
                                 private val setKey: ((Key) -> Unit)? = null
) : SymmetricEncryption {
    override val secureRandom: String = wrapped.secureRandom
    override val secureRandomProvider: String = wrapped.secureRandomProvider
    override val algorithm: String = wrapped.algorithm
    override val cipherGenerator: String = wrapped.cipherGenerator
    override val blockMode: String = wrapped.blockMode
    override val keySize: Int = wrapped.keySize
    override val keyGenerator: String = wrapped.keyGenerator
    override val padding: String = wrapped.padding
    override var createKeyGenSpec: (name: String, purpose: Int) -> AlgorithmParameterSpec? = wrapped.createKeyGenSpec

    override fun generateSecretKey(name: String): SecretKey {
        return wrapped.generateSecretKey(name).also { setKey?.invoke(it) }
    }

    override fun secretKeyFromBytes(byteArray: ByteArray): SecretKey {
        return wrapped.secretKeyFromBytes(byteArray).also { setKey?.invoke(it) }
    }
}

class AsymetricEncryptionWrapper(private val wrapped: AsymmetricEncryption,
                                 private val setKeyPair: ((KeyPair) -> Unit)? = null,
                                 private val setPrivate: ((PrivateKey) -> Unit)? = null,
                                 private val setPublic: ((PublicKey) -> Unit)? = null
) : AsymmetricEncryption {
    override val signaturePadding: String = wrapped.signaturePadding
    override val factory: String = wrapped.factory
    override val algorithm: String = wrapped.algorithm
    override val cipherGenerator: String = wrapped.cipherGenerator
    override val blockMode: String = wrapped.blockMode
    override val keySize: Int = wrapped.keySize
    override val keyGenerator: String = wrapped.keyGenerator
    override val padding: String = wrapped.padding
    override var createKeyGenSpec: (name: String, purpose: Int) -> AlgorithmParameterSpec? = wrapped.createKeyGenSpec

    override fun generateKeyPair(name: String, keyStore: String?): KeyPair {
        return wrapped.generateKeyPair(name, keyStore).also { setKeyPair?.invoke(it) }
    }

    override fun privateKeyFromBytes(keyBytes: ByteArray): PrivateKey {
        return wrapped.privateKeyFromBytes(keyBytes).also { setPrivate?.invoke(it) }
    }

    override fun publicKeyFromBytes(keyBytes: ByteArray): PublicKey {
        return wrapped.publicKeyFromBytes(keyBytes).also { setPublic?.invoke(it) }
    }

    override fun toString(): String {
        return wrapped.toString()
    }
}

class SharedSecretExchangeWrapper(val wrappedExchange: SharedSecretExchange,
                                  val captureKeyPair: ((KeyPair) -> Unit)? = null,
                                  val captureSecretKey: ((SecretKey) -> Unit)? = null,
                                  val captureKeyFromBytes: ((Key) -> Unit)? = null
) : SharedSecretExchange {
    override val algorithm: String = wrappedExchange.algorithm
    override val keyGenerator: String = wrappedExchange.keyGenerator
    override val keyAgreement: String = wrappedExchange.keyAgreement
    override val agreementProvider: String = wrappedExchange.agreementProvider
    override val generatorParameter: String = wrappedExchange.generatorParameter
    override val secretAlgo: SymmetricEncryption = wrappedExchange.secretAlgo
    override val secureRandom: String = wrappedExchange.secureRandom
    override val randomProvider: String = wrappedExchange.randomProvider
    override var createKeyGenSpec: (name: String) -> AlgorithmParameterSpec?
        get() = wrappedExchange.createKeyGenSpec
        set(value) {
            wrappedExchange.createKeyGenSpec = value
        }

    override fun generateKeyPair(): KeyPair {
        return wrappedExchange.generateKeyPair().also { captureKeyPair?.invoke(it) }
    }

    override fun generateSecret(key: PrivateKey): SecretKey {
        return wrappedExchange.generateSecret(key).also { captureSecretKey?.invoke(it) }
    }

    override fun generateSecret(key: PublicKey): SecretKey {
        return wrappedExchange.generateSecret(key).also { captureSecretKey?.invoke(it) }
    }

    override fun privateKeyFromBytes(keyBytes: ByteArray): PrivateKey {
        return wrappedExchange.privateKeyFromBytes(keyBytes).also { captureKeyFromBytes?.invoke(it) }
    }

    override fun publicKeyFromBytes(keyBytes: ByteArray): PublicKey {
        return wrappedExchange.publicKeyFromBytes(keyBytes).also { captureKeyFromBytes?.invoke(it) }
    }

    override fun toString(): String {
        return wrappedExchange.toString()
    }

}