package org.ajar.clique

import android.security.keystore.KeyGenParameterSpec
import org.ajar.clique.encryption.AsymmetricEncryptionDescription
import org.ajar.clique.encryption.SymmetricEncryptionDescription
import org.junit.Assert
import org.mockito.Mockito
import java.security.*
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.CipherSpi

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

    fun createSpecBuilder(keyName: String, selectedModes: Int, keySpec: KeyGenParameterSpec) : (String, Int) -> KeyGenParameterSpec.Builder =
        fun(name: String, modes: Int): KeyGenParameterSpec.Builder {
            Assert.assertEquals("Bad key name: $name != $keyName", keyName, name)
            Assert.assertEquals("Bad modes: $modes != $selectedModes", selectedModes, modes)

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

    fun createKeyPairGenerator(mockPair: KeyPair, keyPairGenerator: KeyPairGenerator, algorithm: String, selectedKeyStore: String?) : (String, String?) -> KeyPairGenerator =
            fun(algo: String, keyStore: String?): KeyPairGenerator {
                Assert.assertEquals("Bad algo: $algo != $algorithm", algorithm, algo)
                Assert.assertEquals("Bad keystore: $keyStore != $selectedKeyStore", selectedKeyStore, keyStore)

                Mockito.`when`(keyPairGenerator.genKeyPair()).thenReturn(mockPair)

                return keyPairGenerator
            }

    fun createKeyPairSetup(keyName: String, algorithm: String, keySpec: KeyGenParameterSpec, mockPair: KeyPair) : KeyPairGenerator {
        val selectedModes = Cipher.DECRYPT_MODE or Cipher.ENCRYPT_MODE

        CliqueConfig.setKeySpecBuilder(createSpecBuilder(keyName, selectedModes, keySpec))

        val keyPairGenerator = Mockito.mock(KeyPairGenerator::class.java)

        CliqueConfig.setKeyPairGeneratorCreator(createKeyPairGenerator(mockPair, keyPairGenerator, algorithm, null))

        return keyPairGenerator
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

    init {
        putService(MockCipherProviderService(this))
        putService(MockCipherProviderCaseChangeService(this))
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
    }
}