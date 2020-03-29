package org.ajar.clique

import android.security.keystore.KeyGenParameterSpec
import org.ajar.clique.encryption.AsymmetricEncryptionDescription
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito
import java.security.*
import java.security.cert.Certificate
import javax.crypto.Cipher

class CliqueConfigTest {

    private lateinit var provider: Provider
    private lateinit var keyStoreSpi: KeyStoreSpi
    private lateinit var keyStore: KeyStore
    private lateinit var privateKey: PrivateKey
    private lateinit var publicKey: PublicKey

    class MockKeyStore(keyStoreSpi: KeyStoreSpi, provider: Provider) : KeyStore(keyStoreSpi, provider, KEYSTORE_NAME)

    @Before
    fun createProvider() {
        provider = Mockito.mock(Provider::class.java)
        CliqueConfig.provider = provider

        keyStoreSpi = Mockito.mock(KeyStoreSpi::class.java)
        keyStore = MockKeyStore(keyStoreSpi, provider)
        keyStore.load(null)

        privateKey = Mockito.mock(PrivateKey::class.java)
        publicKey = Mockito.mock(PublicKey::class.java)

        CliqueConfig.setKeyStore(keyStore)
    }

    @Test
    fun testGetPrivateKeyFromKeyStore() {
        Mockito.`when`(keyStoreSpi.engineGetKey(ASYM_KEY_PAIR, null)).thenReturn(privateKey)

        val testKey = CliqueConfig.getPrivateKeyFromKeyStore(ASYM_KEY_PAIR)
        assertEquals("Private Keys do not match: $testKey != $privateKey", testKey, privateKey)
    }

    @Test
    fun testGetPublicKeyFromKeyStore() {
        val certificate = Mockito.mock(Certificate::class.java)
        Mockito.`when`(certificate.publicKey).thenReturn(publicKey)

        Mockito.`when`(keyStoreSpi.engineGetCertificate(ASYM_KEY_PAIR)).thenReturn(certificate)

        val testKey = CliqueConfig.getPublicKeyFromKeyStore(ASYM_KEY_PAIR)
        assertEquals("Public Keys do not match: $testKey != $publicKey", publicKey, testKey)
    }

    @Test
    fun testCreateKeyPair() {
        val keySpec = Mockito.mock(KeyGenParameterSpec::class.java)
        val mockPair = KeyPair(publicKey, privateKey)

        val keyName = ASYM_KEY_PAIR
        val selectedModes = Cipher.DECRYPT_MODE or Cipher.ENCRYPT_MODE

        val createBuilderSpec = fun(name: String, modes: Int): KeyGenParameterSpec.Builder {
            assertEquals("Bad key name: $name != $keyName", keyName, name)
            assertEquals("Bad modes: $modes != $selectedModes", selectedModes, modes)

            val mockBuilder = Mockito.mock(KeyGenParameterSpec.Builder::class.java)

            Mockito.`when`(mockBuilder.setBlockModes(BLOCKMODE_NONE)).thenReturn(mockBuilder)
            Mockito.`when`(mockBuilder.setEncryptionPaddings(PADDING_NONE)).thenReturn(mockBuilder)
            Mockito.`when`(mockBuilder.setRandomizedEncryptionRequired(REQUIRE_RANDOM)).thenReturn(mockBuilder)
            Mockito.`when`(mockBuilder.build()).thenReturn(keySpec)

            return mockBuilder
        }
        CliqueConfig.setKeySpecBuilder(createBuilderSpec)

        val keyPairGenerator = Mockito.mock(KeyPairGenerator::class.java)

        val createKeyPairGenerator = fun(algo: String, keyStore: String?): KeyPairGenerator {
            assertEquals("Bad algo: $algo != $ENCRYPTION_BACKWARDS", ENCRYPTION_BACKWARDS, algo)
            assertEquals("Bad keystore: $keyStore != 'null'", null, keyStore)

            Mockito.`when`(keyPairGenerator.genKeyPair()).thenReturn(mockPair)

            return keyPairGenerator
        }
        CliqueConfig.setKeyPairGeneratorCreator(createKeyPairGenerator)

        val encryptionDescription = AsymmetricEncryptionDescription(ENCRYPTION_BACKWARDS, BLOCKMODE_NONE, PADDING_NONE, false)

        val keyPair = CliqueConfig.createKeyPair(ASYM_KEY_PAIR, encryptionDescription)

        Mockito.verify(keyPairGenerator).initialize(keySpec)

        assertEquals("KeyPairs do not match: $mockPair != $keyPair", keyPair, mockPair)
        assertEquals("Private key does not match: ${mockPair.private} != ${keyPair.private}", keyPair.private, mockPair.private)
        assertEquals("Public key does not match: ${mockPair.public} != ${keyPair.public}", keyPair.public, mockPair.public)

        // TODO: Find a way to actually verify that the keystore stores the keys? Maybe not possible?
        Mockito.`when`(keyStoreSpi.engineGetKey(ASYM_KEY_PAIR, null)).thenReturn(privateKey)

        var testKey = CliqueConfig.getPrivateKeyFromKeyStore(ASYM_KEY_PAIR)
        assertEquals("Private Keys do not match: $testKey != $privateKey", privateKey, testKey)

        val certificate = Mockito.mock(Certificate::class.java)
        Mockito.`when`(certificate.publicKey).thenReturn(publicKey)

        Mockito.`when`(keyStoreSpi.engineGetCertificate(ASYM_KEY_PAIR)).thenReturn(certificate)

        testKey = CliqueConfig.getPublicKeyFromKeyStore(ASYM_KEY_PAIR)
        assertEquals("Public Keys do not match: $testKey != $publicKey", publicKey, testKey)
    }

    companion object {
        const val KEYSTORE_NAME = "MockKeyStore"

        const val ASYM_KEY_PAIR = "dummyAsym"

        const val ENCRYPTION_BACKWARDS = "backwards"
        const val BLOCKMODE_NONE = "none"
        const val PADDING_NONE = "none"
        const val REQUIRE_RANDOM = false
    }
}