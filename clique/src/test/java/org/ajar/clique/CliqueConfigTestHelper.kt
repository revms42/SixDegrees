package org.ajar.clique

import android.security.keystore.KeyGenParameterSpec
import org.ajar.clique.encryption.AsymmetricEncryptionDescription
import org.ajar.clique.encryption.SymmetricEncryptionDescription
import org.junit.Assert
import org.mockito.Mockito
import java.security.*
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.KeySpec
import java.util.*
import javax.crypto.*

object CliqueConfigTestHelper {
    const val KEYSTORE_NAME = "MockKeyStore"

    const val ASYM_KEY_PAIR = "dummyAsym"
    const val ENCRYPTION_BACKWARDS = "backwards"
    const val ENCRYPTION_CAPITAL = "capitalize"

    const val BLOCKMODE_NONE = "none"
    const val PADDING_NONE = "none"

    fun createAsymmetricEncryptionDescription(encryption: String) : AsymmetricEncryptionDescription {
        return AsymmetricEncryptionDescription(encryption, BLOCKMODE_NONE, PADDING_NONE, false)
    }

    fun createSymmetricEncryptionDescription(encryption: String) : SymmetricEncryptionDescription {
        return SymmetricEncryptionDescription(encryption, BLOCKMODE_NONE, PADDING_NONE, 0)
    }

    fun createSpecBuilder(keySpec: KeyGenParameterSpec) : (String, Int) -> KeyGenParameterSpec.Builder =
        fun(_: String, _: Int): KeyGenParameterSpec.Builder {
            var mockBuilder: KeyGenParameterSpec.Builder? = null
            mockBuilder = Mockito.mock(KeyGenParameterSpec.Builder::class.java) {
                if(it.method.name == "build") {
                    keySpec
                } else {
                    mockBuilder
                }
            }

            return mockBuilder
        }

    fun createKeyPairGenerator(mockPair: KeyPair, keyPairGenerator: KeyPairGenerator) : (String, String?) -> KeyPairGenerator =
            fun(_: String, _: String?): KeyPairGenerator {
                Mockito.`when`(keyPairGenerator.genKeyPair()).thenReturn(mockPair)

                return keyPairGenerator
            }

    fun createKeyPairSetup(keySpec: KeyGenParameterSpec, mockPair: KeyPair) : KeyPairGenerator {
        CliqueConfig.setKeySpecBuilder(createSpecBuilder(keySpec))

        val keyPairGenerator = Mockito.mock(KeyPairGenerator::class.java)

        CliqueConfig.setKeyPairGeneratorCreator(createKeyPairGenerator(mockPair, keyPairGenerator))

        return keyPairGenerator
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

class TestCipherProviderSpi : Provider(PROVIDER_NAME, 1.0, "Provides test algos for Clique Testing") {

    class MockCipherProviderService(p: Provider) : Provider.Service(p, "Cipher", ENCRYPTION_BACKWARDS, Cipher::class.java.canonicalName, null, null) {
        override fun newInstance(constructorParameter: Any?): Any {
            return backwardsCipherSpi
        }
    }

    class MockCipherProviderCaseChangeService(p: Provider) : Provider.Service(p, "Cipher", ENCRYPTION_CAPITAL, Cipher::class.java.canonicalName, null, null) {
        override fun newInstance(constructorParameter: Any?): Any {
            return capitalCipherSpi
        }
    }

    class MockSecretKeyProvider(p: Provider) : Provider.Service(p, "KeyGenerator", ENCRYPTION_CAPITAL, SecretKey::class.java.canonicalName, null, null) {
        override fun newInstance(constructorParameter: Any?): Any {
            return secretKeyGenerator
        }
    }

    init {
        putService(MockCipherProviderService(this))
        putService(MockCipherProviderCaseChangeService(this))
        putService(MockSecretKeyProvider(this))
    }

    companion object {
        val provider = TestCipherProviderSpi()
        const val PROVIDER_NAME = "CliqueTestProvider"
        const val ENCRYPTION_BACKWARDS = CliqueConfigTestHelper.ENCRYPTION_BACKWARDS
        const val ENCRYPTION_CAPITAL = CliqueConfigTestHelper.ENCRYPTION_CAPITAL

        private val backwardsCipherSpi = object : CipherSpi() {
            override fun engineSetMode(mode: String?) {}

            override fun engineInit(opmode: Int, key: Key?, random: SecureRandom?) {}

            override fun engineInit(opmode: Int, key: Key?, params: AlgorithmParameterSpec?, random: SecureRandom?) {}

            override fun engineInit(opmode: Int, key: Key?, params: AlgorithmParameters?, random: SecureRandom?) {}

            override fun engineGetIV(): ByteArray { return ByteArray(0) }

            override fun engineDoFinal(input: ByteArray, inputOffset: Int, inputLen: Int): ByteArray {
                return input.reversedArray()
            }

            override fun engineDoFinal(input: ByteArray?, inputOffset: Int, inputLen: Int, output: ByteArray?, outputOffset: Int): Int { return -1 }

            override fun engineSetPadding(padding: String?) {}

            override fun engineGetParameters(): AlgorithmParameters { return AlgorithmParameters.getInstance(ENCRYPTION_BACKWARDS) }

            override fun engineUpdate(input: ByteArray?, inputOffset: Int, inputLen: Int): ByteArray { return ByteArray(0) }

            override fun engineUpdate(input: ByteArray?, inputOffset: Int, inputLen: Int, output: ByteArray?, outputOffset: Int): Int { return -1 }

            override fun engineGetBlockSize(): Int { return -1 }

            override fun engineGetOutputSize(inputLen: Int): Int { return -1 }
        }

        private val capitalCipherSpi = object : CipherSpi() {

            private var mode: String? = "encode"

            override fun engineSetMode(mode: String?) {
                this.mode = mode
            }

            override fun engineInit(opmode: Int, key: Key?, random: SecureRandom?) {}

            override fun engineInit(opmode: Int, key: Key?, params: AlgorithmParameterSpec?, random: SecureRandom?) {}

            override fun engineInit(opmode: Int, key: Key?, params: AlgorithmParameters?, random: SecureRandom?) {}

            override fun engineGetIV(): ByteArray { return ByteArray(0) }

            override fun engineDoFinal(input: ByteArray, inputOffset: Int, inputLen: Int): ByteArray {
                val string = String(input, Charsets.UTF_8)

                return (if(mode?.equals("encode") == true) string.toUpperCase() else string.toLowerCase()).toByteArray(Charsets.UTF_8)
            }

            override fun engineDoFinal(input: ByteArray?, inputOffset: Int, inputLen: Int, output: ByteArray?, outputOffset: Int): Int { return -1 }

            override fun engineSetPadding(padding: String?) {}

            override fun engineGetParameters(): AlgorithmParameters { return AlgorithmParameters.getInstance(ENCRYPTION_BACKWARDS) }

            override fun engineUpdate(input: ByteArray?, inputOffset: Int, inputLen: Int): ByteArray { return ByteArray(0) }

            override fun engineUpdate(input: ByteArray?, inputOffset: Int, inputLen: Int, output: ByteArray?, outputOffset: Int): Int { return -1 }

            override fun engineGetBlockSize(): Int { return -1 }

            override fun engineGetOutputSize(inputLen: Int): Int { return -1 }
        }

        private val secretKeyGenerator = object : KeyGeneratorSpi() {
            override fun engineInit(random: SecureRandom?) {}

            override fun engineInit(params: AlgorithmParameterSpec?, random: SecureRandom?) {}

            override fun engineInit(keysize: Int, random: SecureRandom?) {}

            override fun engineGenerateKey(): SecretKey {
                val secretKey = Mockito.mock(SecretKey::class.java)
                Mockito.`when`(secretKey.encoded).thenReturn("SecretKeyEncodedByteArray".toByteArray(Charsets.UTF_8))
                return secretKey
            }

        }
    }
}