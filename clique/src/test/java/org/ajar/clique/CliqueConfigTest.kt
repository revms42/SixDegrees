package org.ajar.clique

import android.security.keystore.KeyGenParameterSpec
import android.util.Log
import org.ajar.clique.encryption.AsymmetricEncryptionDescription
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito
import java.security.*
import java.security.cert.Certificate
import java.util.*
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

        Mockito.verify(keyStoreSpi).engineLoad(null)

        privateKey = Mockito.mock(PrivateKey::class.java)
        publicKey = Mockito.mock(PublicKey::class.java)

        CliqueConfig.setKeyStore(keyStore)
    }

    fun switchCliqueConfigForJDK() {
        CliqueConfig.setStringEncoder { array:ByteArray, _:Int  ->
            Base64.getEncoder().encodeToString(array)
        }
        CliqueConfig.setByteArrayDecoder { string, _ ->
            Base64.getDecoder().decode(string)
        }
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
        val encryptionDescription = AsymmetricEncryptionDescription(ENCRYPTION_BACKWARDS, BLOCKMODE_NONE, PADDING_NONE, false)
        val keySpec = Mockito.mock(KeyGenParameterSpec::class.java)
        val mockPair = KeyPair(publicKey, privateKey)
        val keyPairGenerator = CliqueConfigTestHelper.createKeyPairSetup(ASYM_KEY_PAIR, ENCRYPTION_BACKWARDS, encryptionDescription, keySpec, mockPair)

        val keyPair = CliqueConfig.createKeyPair(ASYM_KEY_PAIR, encryptionDescription)

        Mockito.verify(keyPairGenerator).initialize(keySpec)
        Mockito.verifyNoMoreInteractions(keyStoreSpi)

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

    @Test
    fun testRoundTripEncodedStringToByteArray() {
        switchCliqueConfigForJDK()

        val mockKey = Mockito.mock(Key::class.java)
        val cipherMock = Cipher.getInstance(ENCRYPTION_BACKWARDS, TestCipherProviderSpi.provider)
        cipherMock.init(Cipher.ENCRYPT_MODE, mockKey)

        val byteArray = "The String to be encoded".toByteArray(Charsets.UTF_8)

        val reversed = CliqueConfig.byteArrayToEncodedString(byteArray, cipherMock)
        val restored = CliqueConfig.encodedStringToByteArray(reversed, cipherMock)

        assertArrayEquals("Input array does not equal output array!", byteArray, restored)
    }

    @Test
    fun testRoundTripStringToEncodedString() {
        switchCliqueConfigForJDK()

        val mockKey = Mockito.mock(Key::class.java)
        val cipherMock = Cipher.getInstance(ENCRYPTION_BACKWARDS, TestCipherProviderSpi.provider)
        cipherMock.init(Cipher.ENCRYPT_MODE, mockKey)

        val targetString = "The String to be encoded"

        val reversed = CliqueConfig.stringToEncodedString(targetString, cipherMock)
        val restored = CliqueConfig.encodedStringToString(reversed, cipherMock)

        assertEquals("Input string does not equal output string!", targetString, restored)
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