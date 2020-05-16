package org.ajar.clique

import org.ajar.clique.encryption.AsymmetricEncryptionDesc
import org.ajar.clique.encryption.CipherProvider
import org.ajar.clique.encryption.SymmetricEncryptionDesc
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito
import java.security.*
import java.security.cert.Certificate
import javax.crypto.Cipher
import javax.crypto.SecretKey

class CliqueConfigTest {

    private var asym = AsymmetricEncryptionDesc.DEFAULT
    private var sym = SymmetricEncryptionDesc.DEFAULT
    private lateinit var provider: Provider
    private lateinit var keyStoreSpi: KeyStoreSpi
    private lateinit var keyStore: KeyStore
    private lateinit var privateKey: PrivateKey
    private lateinit var publicKey: PublicKey
    private lateinit var secretKey: SecretKey

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
        secretKey = Mockito.mock(SecretKey::class.java)

        CliqueConfig.setKeyStore(keyStore)

        asym.createKeyGenSpec = CliqueTestHelper.createTestRSAParameters(asym)
        sym.createKeyGenSpec = CliqueTestHelper.createTestAESParameters()
    }

    @Test
    fun testGetPrivateKeyFromKeyStore() {
        Mockito.`when`(keyStoreSpi.engineGetKey(ASYM_KEY_PAIR, "".toCharArray())).thenReturn(privateKey)

        val testKey = CliqueConfig.getPrivateKeyFromKeyStore(ASYM_KEY_PAIR,"")
        assertEquals("Private Keys do not match: $testKey != $privateKey", testKey, privateKey)
    }

    @Test
    fun testGetSecretKeyFromKeyStore() {
        Mockito.`when`(keyStoreSpi.engineGetKey(SYM_KEY, "".toCharArray())).thenReturn(secretKey)

        val testKey = CliqueConfig.getSecretKeyFromKeyStore(SYM_KEY,"")
        assertEquals("Private Keys do not match: $testKey != $secretKey", testKey, secretKey)
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
    fun testRoundTripEncodedStringToByteArray() {
        CliqueTestHelper.switchCliqueConfigForJDK()

        val key = sym.generateSecretKey()
        val provider = CipherProvider.Symmetric(sym)

        val byteArray = "The String to be encoded".toByteArray(Charsets.UTF_8)

        var cipher = provider.cipher(Cipher.ENCRYPT_MODE, key)
        val reversed = CliqueConfig.byteArrayToEncodedString(byteArray, cipher)

        cipher = provider.cipher(Cipher.DECRYPT_MODE, key)
        val restored = CliqueConfig.encodedStringToByteArray(reversed, cipher)

        assertArrayEquals("Input array does not equal output array!", byteArray, restored)
    }

    @Test
    fun testRoundTripStringToEncodedString() {
        CliqueTestHelper.switchCliqueConfigForJDK()

        val key = sym.generateSecretKey()
        val provider = CipherProvider.Symmetric(sym)

        val targetString = "The String to be encoded"

        var cipher = provider.cipher(Cipher.ENCRYPT_MODE, key)
        val reversed = CliqueConfig.stringToEncodedString(targetString, cipher)

        cipher = provider.cipher(Cipher.DECRYPT_MODE, key)
        val restored = CliqueConfig.encodedStringToString(reversed, cipher)

        assertEquals("Input string does not equal output string!", targetString, restored)
    }

    @Test
    fun testTranscodeString() {
        CliqueTestHelper.switchCliqueConfigForJDK()

        val symKey = sym.generateSecretKey()
        val symProvider = CipherProvider.Symmetric(sym)

        val asymKey = asym.generateKeyPair()
        val asymProvider = CipherProvider.Private(asym)

        val targetString = "The String to be encoded"

        val asymPublicCipher = asymProvider.cipher(Cipher.ENCRYPT_MODE, asymKey.public)
        val asymmed = CliqueConfig.stringToEncodedString(targetString, asymPublicCipher)

        val asymPrivateCipher = asymProvider.cipher(Cipher.DECRYPT_MODE, asymKey.private)
        val symWriteCipher = symProvider.cipher(Cipher.ENCRYPT_MODE, symKey)
        val transcoded = CliqueConfig.transcodeString(asymmed, asymPrivateCipher, symWriteCipher)

        val symReadCipher = symProvider.cipher(Cipher.DECRYPT_MODE, symKey)
        val restored = CliqueConfig.encodedStringToString(transcoded, symReadCipher)

        assertEquals("Input string does not equal anticipated string: $restored != $targetString", targetString, restored)
    }

    companion object {
        private const val KEYSTORE_NAME = "testKeyStore"
        private const val ASYM_KEY_PAIR = "asymKeyPair"
        private const val SYM_KEY = "symKey"
    }
}