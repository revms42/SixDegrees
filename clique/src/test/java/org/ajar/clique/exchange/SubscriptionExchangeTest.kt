package org.ajar.clique.exchange

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import org.ajar.clique.*
import org.ajar.clique.database.SecureDAOTestHelper
import org.ajar.clique.encryption.AsymmetricEncryptionDescription
import org.ajar.clique.facade.User
import org.ajar.clique.transaction.SubscriptionExchange
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito
import java.security.*
import javax.crypto.Cipher

class SubscriptionExchangeTest {
    private lateinit var keyStoreSpi: KeyStoreSpi
    private lateinit var keyStore: KeyStore

    private val privateKey = Mockito.mock(PrivateKey::class.java)
    private val publicKey = Mockito.mock(PublicKey::class.java)

    private val mockContext = Mockito.mock(Context::class.java)
    private val mockUserSym = CliqueConfigTestHelper.createSymmetricEncryptionDescription(CliqueConfigTestHelper.ENCRYPTION_CAPITAL)
    private val mockUserAsym = CliqueConfigTestHelper.createAsymmetricEncryptionDescription(CliqueConfigTestHelper.ENCRYPTION_BACKWARDS)
    private var user: User? = null

    private lateinit var exchange: SubscriptionExchange
    private lateinit var exchangeCipher: (mode: Int) -> Cipher

    @Before
    fun setup() {
        val provider = TestCipherProviderSpi.provider
        CliqueConfig.provider = provider

        keyStoreSpi = Mockito.mock(KeyStoreSpi::class.java)
        keyStore = CliqueConfigTest.MockKeyStore(keyStoreSpi, provider)
        keyStore.load(null)

        Mockito.verify(keyStoreSpi).engineLoad(null)

        Mockito.`when`(keyStoreSpi.engineGetKey(UserFacadeTest.USER_NAME, null)).thenReturn(Mockito.mock(PrivateKey::class.java))

        CliqueConfig.setKeyStore(keyStore)

        SecureDAOTestHelper.setupMockDatabase()
        CliqueConfigTestHelper.switchCliqueConfigForJDK()
        CliqueConfig.assymetricEncryption = mockUserAsym // Use the same as the user.

        Mockito.`when`(publicKey.encoded).thenReturn("PublicKeyEncodedByteArray".toByteArray(Charsets.UTF_8))
        Mockito.`when`(privateKey.encoded).thenReturn("PrivateKeyEncodedByteArray".toByteArray(Charsets.UTF_8))

        val keySpec = Mockito.mock(KeyGenParameterSpec::class.java)
        val mockPair = KeyPair(publicKey, privateKey)
        CliqueConfigTestHelper.createKeyPairSetup(keySpec, mockPair)

        User.createUser(mockContext, UserFacadeTest.USER_NAME, UserFacadeTest.USER_DISPLAY_NAME, UserFacadeTest.USER_URL, mockUserSym, mockUserAsym)
        user = User.loadUser(mockContext, UserFacadeTest.USER_NAME)

        val exchangeEncryption = CliqueConfigTestHelper.createSymmetricEncryptionDescription(CliqueConfigTestHelper.ENCRYPTION_BACKWARDS)
        val key = CliqueConfig.createSecretKey(exchangeEncryption, TestCipherProviderSpi.provider)

        exchangeCipher = fun (mode: Int) : Cipher {
            val cipher = Cipher.getInstance(CliqueConfigTestHelper.ENCRYPTION_BACKWARDS, TestCipherProviderSpi.provider)
            cipher.init(mode, key)
            return cipher
        }

        exchange = SubscriptionExchange.createExchange(user!!, exchangeCipher)
    }

    @Test
    fun testExchangeSubscriptionRequest() {
        val asymDesc = AsymmetricEncryptionDescription(CliqueConfigTestHelper.ENCRYPTION_CAPITAL, CliqueConfigTestHelper.BLOCKMODE_NONE, CliqueConfigTestHelper.PADDING_NONE, false)
        val invitation = exchange.createInvitation("MockFriend", asymDesc)

        Assert.assertNotNull("Invitation should not be null!", invitation)
        Assert.assertEquals("Invitation URL does not match expected!", "http://obviouslywrong.net", invitation!!.url)
        Assert.assertEquals("Invitation read key does not match expected!", "not correct either", invitation.readKey)
        Assert.assertEquals("Invitation read key algo does not match expected!", "not correct either", invitation.readAlgo)
        Assert.assertEquals("Invitation rotate key does not match expected!", "may not even be able to get this on the fly", invitation.rotateKey)
        Assert.assertEquals("Invitation rotate key algo does not match expected!", "this might be easier to get", invitation.rotateAlgo)
    }

    @Test
    fun testExchangeSubscriptionRespond() {
        Assert.fail("Not yet implemented")
    }
}