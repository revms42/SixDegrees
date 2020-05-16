package org.ajar.clique

import org.ajar.clique.encryption.AsymmetricEncryption
import org.ajar.clique.encryption.SymmetricEncryption
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

    fun switchCliqueConfigForJDK() {
        CliqueConfig.setStringEncoder { array:ByteArray, _:Int  ->
            Base64.getEncoder().encodeToString(array)
        }
        CliqueConfig.setByteArrayDecoder { string, _ ->
            Base64.getDecoder().decode(string)
        }
    }
}

class SymetricEncryptionWrapper(private val wrapped: SymmetricEncryption,
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