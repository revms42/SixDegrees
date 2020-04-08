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
import java.util.*
import javax.crypto.Cipher

class SubscriptionExchangeTest {
    private lateinit var keyStoreSpi: KeyStoreSpi
    private lateinit var keyStore: KeyStore

    private val privateKey = Mockito.mock(PrivateKey::class.java)
    private val publicKey = Mockito.mock(PublicKey::class.java)

    private val mockContext = Mockito.mock(Context::class.java)
    private val mockUserSym = CliqueConfigTestHelper.createSymmetricEncryptionDescription(CliqueConfigTestHelper.ENCRYPTION_BACKWARDS)
    private val mockUserAsym = CliqueConfigTestHelper.createAsymmetricEncryptionDescription(CliqueConfigTestHelper.ENCRYPTION_CAPITAL)
    private var user: User? = null

    private lateinit var exchange: SubscriptionExchange
    private lateinit var exchangeCipher: (mode: Int) -> Cipher

    private lateinit var decoder: (String) -> String

    @Before
    fun setup() {
        val provider = TestCipherProviderSpi.provider
        CliqueConfig.provider = provider

        keyStoreSpi = Mockito.mock(KeyStoreSpi::class.java)
        keyStore = CliqueConfigTest.MockKeyStore(keyStoreSpi, provider)
        keyStore.load(null)

        Mockito.verify(keyStoreSpi).engineLoad(null)

        Mockito.`when`(keyStoreSpi.engineGetKey(USER_NAME, null)).thenReturn(Mockito.mock(PrivateKey::class.java))

        CliqueConfig.setKeyStore(keyStore)

        SecureDAOTestHelper.setupMockDatabase()
        CliqueConfigTestHelper.switchCliqueConfigForJDK()
        CliqueConfig.assymetricEncryption = mockUserAsym // Use the same as the user.

        Mockito.`when`(publicKey.encoded).thenReturn(USER_READ_KEY.toByteArray(Charsets.UTF_8))
        Mockito.`when`(privateKey.encoded).thenReturn(USER_WRITE_KEY.toByteArray(Charsets.UTF_8))

        val keySpec = Mockito.mock(KeyGenParameterSpec::class.java)
        val mockPair = KeyPair(publicKey, privateKey)
        CliqueConfigTestHelper.createKeyPairSetup(keySpec, mockPair)

        User.createUser(mockContext, USER_NAME, USER_DISPLAY_NAME, USER_URL, mockUserSym, mockUserAsym)
        user = User.loadUser(mockContext, USER_NAME)

        val exchangeEncryption = CliqueConfigTestHelper.createSymmetricEncryptionDescription(CliqueConfigTestHelper.ENCRYPTION_BACKWARDS)
        val key = CliqueConfig.createSecretKey(exchangeEncryption, TestCipherProviderSpi.provider)

        exchangeCipher = fun (mode: Int) : Cipher {
            val cipher = Cipher.getInstance(exchangeEncryption.algorithm, TestCipherProviderSpi.provider)
            cipher.init(mode, key)
            return cipher
        }

        exchange = SubscriptionExchange.createExchange(user!!, exchangeCipher)

        val base64Decoder = Base64.getDecoder()

        decoder = fun(string: String) : String {
            return String(base64Decoder.decode(string), Charsets.UTF_8)
        }
    }

    @Test
    fun testExchangeSubscriptionRequest() {
        val asymDesc = AsymmetricEncryptionDescription(CliqueConfigTestHelper.ENCRYPTION_CAPITAL, CliqueConfigTestHelper.BLOCKMODE_NONE, CliqueConfigTestHelper.PADDING_NONE, false)
        val invitation = exchange.createInvitation("MockFriend", asymDesc)

        Assert.assertNotNull("Invitation should not be null!", invitation)
        Assert.assertEquals("Invitation URL does not match expected!", USER_URL, decoder(invitation!!.url).reversed())
        Assert.assertEquals("Invitation read key does not match expected!", USER_READ_KEY, decoder(invitation.readKey).reversed())
        Assert.assertEquals("Invitation read key algo does not match expected!", mockUserAsym.toString(), decoder(invitation.readAlgo).reversed())
        // Note: What we actually expect here is a brand new private key created on the fly. But because of the way that Mockito works in this test we will be getting the User private write key
        // This is because we're requesting an asynchronous key pair and we've already set up Mockito to return the User's info when that is requested
        Assert.assertEquals("Invitation rotate key does not match expected!", USER_WRITE_KEY, decoder(invitation.rotateKey).reversed())
        Assert.assertEquals("Invitation rotate key algo does not match expected!", asymDesc.toString(), decoder(invitation.rotateAlgo).reversed())
    }

    @Test
    fun testExchangeSubscriptionRespond() {
        Assert.fail("Not Yet Implemented")
    }

    companion object {
        const val USER_NAME = UserFacadeTest.USER_NAME
        const val USER_DISPLAY_NAME = UserFacadeTest.USER_DISPLAY_NAME
        const val USER_URL = UserFacadeTest.USER_URL
        const val USER_READ_KEY = "UserPublicReadKey"
        const val USER_WRITE_KEY = "UserPrivateWriteKey"

        const val FRIEND_ONE_READ_KEY = UserFacadeTest.FRIEND_ONE_READ_KEY
        const val FRIEND_ONE_DISPLAY_NAME = UserFacadeTest.FRIEND_ONE_DISPLAY_NAME
        const val FRIEND_ONE_URL = UserFacadeTest.FRIEND_ONE_URL
    }
}