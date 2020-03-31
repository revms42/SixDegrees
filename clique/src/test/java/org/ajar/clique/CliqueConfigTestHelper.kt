package org.ajar.clique

import android.security.keystore.KeyGenParameterSpec
import org.ajar.clique.encryption.AsymmetricEncryptionDescription
import org.junit.Assert
import org.mockito.Mock
import org.mockito.Mockito
import java.security.*
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.CipherSpi

object CliqueConfigTestHelper {

    fun createSpecBuilder(keyName: String, selectedModes: Int, encDesc: AsymmetricEncryptionDescription, keySpec: KeyGenParameterSpec) : (String, Int) -> KeyGenParameterSpec.Builder =
        fun(name: String, modes: Int): KeyGenParameterSpec.Builder {
            Assert.assertEquals("Bad key name: $name != $keyName", keyName, name)
            Assert.assertEquals("Bad modes: $modes != $selectedModes", selectedModes, modes)

            val mockBuilder = Mockito.mock(KeyGenParameterSpec.Builder::class.java)

            Mockito.`when`(mockBuilder.setBlockModes(encDesc.blockMode)).thenReturn(mockBuilder)
            Mockito.`when`(mockBuilder.setEncryptionPaddings(encDesc.padding)).thenReturn(mockBuilder)
            Mockito.`when`(mockBuilder.setRandomizedEncryptionRequired(encDesc.requireRandom)).thenReturn(mockBuilder)
            Mockito.`when`(mockBuilder.build()).thenReturn(keySpec)

            return mockBuilder
        }

    fun createKeyPairGenerator(mockPair: KeyPair, keyPairGenerator: KeyPairGenerator, algorithm: String, selectedKeyStore: String?) : (String, String?) -> KeyPairGenerator =
            fun(algo: String, keyStore: String?): KeyPairGenerator {
                Assert.assertEquals("Bad algo: $algo != $algorithm", algorithm, algo)
                Assert.assertEquals("Bad keystore: $keyStore != $selectedKeyStore", selectedKeyStore, keyStore)

                Mockito.`when`(keyPairGenerator.genKeyPair()).thenReturn(mockPair)

                return keyPairGenerator
            }

    fun createKeyPairSetup(keyName: String, algorithm: String, encDesc: AsymmetricEncryptionDescription, keySpec: KeyGenParameterSpec, mockPair: KeyPair) : KeyPairGenerator {
        val selectedModes = Cipher.DECRYPT_MODE or Cipher.ENCRYPT_MODE

        CliqueConfig.setKeySpecBuilder(createSpecBuilder(keyName, selectedModes, encDesc, keySpec))

        val keyPairGenerator = Mockito.mock(KeyPairGenerator::class.java)

        CliqueConfig.setKeyPairGeneratorCreator(createKeyPairGenerator(mockPair, keyPairGenerator, algorithm, null))

        return keyPairGenerator
    }
}

class TestCipherProviderSpi : Provider(PROVIDER_NAME, 1.0, "Provides test algos for Clique Testing") {

    class MockCipherProviderService(p: Provider) : Provider.Service(p, "Cipher", ENCRYPTION_BACKWARDS, Cipher::class.java.canonicalName, null, null) {
        override fun newInstance(constructorParameter: Any?): Any {
            return cipherMockSpi
        }
    }

    init {
        putService(MockCipherProviderService(this))
    }

    companion object {
        val provider = TestCipherProviderSpi()
        const val PROVIDER_NAME = "CliqueTestProvider"
        const val ENCRYPTION_BACKWARDS = CliqueConfigTest.ENCRYPTION_BACKWARDS

        private val cipherMockSpi = object : CipherSpi() {
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
    }
}