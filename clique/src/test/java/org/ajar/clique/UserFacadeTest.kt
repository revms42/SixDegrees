package org.ajar.clique

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import org.ajar.clique.database.CliqueAccount
import org.ajar.clique.database.CliqueSubscription
import org.ajar.clique.database.SecureDAOTestHelper
import org.ajar.clique.database.SecureDatabase
import org.ajar.clique.facade.Friend
import org.ajar.clique.facade.User
import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito
import java.security.*
import java.util.*
import javax.crypto.Cipher

class UserFacadeTest {

    private lateinit var keyStoreSpi: KeyStoreSpi
    private lateinit var keyStore: KeyStore

    private val privateKey = Mockito.mock(PrivateKey::class.java)
    private val publicKey = Mockito.mock(PublicKey::class.java)

    private val mockContext = Mockito.mock(Context::class.java)
    private val mockUserSym = CliqueConfigTestHelper.createSymmetricEncryptionDescription(CliqueConfigTestHelper.ENCRYPTION_BACKWARDS)
    private val mockUserAsym = CliqueConfigTestHelper.createAsymmetricEncryptionDescription(CliqueConfigTestHelper.ENCRYPTION_CAPITAL)
    private var user: User? = null

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

        Mockito.`when`(publicKey.encoded).thenReturn("PublicKeyEncodedByteArray".toByteArray(Charsets.UTF_8))
        Mockito.`when`(privateKey.encoded).thenReturn("PrivateKeyEncodedByteArray".toByteArray(Charsets.UTF_8))

        val base64Decoder = Base64.getDecoder()

        decoder = fun(string: String) : String {
            return String(base64Decoder.decode(string), Charsets.UTF_8)
        }
    }

    @After
    fun tearDown() {
        SecureDAOTestHelper.clear()
    }

    @Test
    fun testCreateUser() {
        val keySpec = Mockito.mock(KeyGenParameterSpec::class.java)
        val mockPair = KeyPair(publicKey, privateKey)
        CliqueConfigTestHelper.createKeyPairSetup(keySpec, mockPair)

        User.createUser(mockContext, USER_NAME, USER_DISPLAY_NAME, USER_URL, mockUserSym, mockUserAsym)
        user = User.loadUser(mockContext, USER_NAME)

        Assert.assertEquals("User name does not match expected!", USER_NAME, user!!.name)
        Assert.assertEquals("User display name does not match expected!", USER_NAME.reversed(), decoder(user!!.filter))
        Assert.assertEquals("User url does not match expected!", USER_URL, user!!.url)

        // Note: Since we use Transformations to map the result of the DB query to the user's friends list, we have to look
        // at the result of the DB itself, because there will be no observing of changes for the mediator live data
        // set up by the transformation.
        val friends = SecureDatabase.instance?.accountDao()?.findSubscriptionKeys(user!!.filter)

        Assert.assertEquals("User should have themselves (only) in their friends list!", 1, friends?.value?.size)
        Assert.assertEquals("User should be listed as the subscriber of the account!", USER_DISPLAY_NAME.reversed(), decoder(friends?.value?.get(0)?.subscriber!!))
        Assert.assertEquals("User's URL should be listed as the subscription in the first friend!", USER_URL.reversed(), decoder(friends.value?.get(0)?.subscription!!))
    }

    @Test
    fun testAddFriends() {
        val keySpec = Mockito.mock(KeyGenParameterSpec::class.java)
        val mockPair = KeyPair(publicKey, privateKey)
        CliqueConfigTestHelper.createKeyPairSetup(keySpec, mockPair)

        User.createUser(mockContext, USER_NAME, USER_DISPLAY_NAME, USER_URL, mockUserSym, mockUserAsym)
        user = User.loadUser(mockContext, USER_NAME)

        Assert.assertEquals("User name does not match expected!", USER_NAME, user!!.name)
        Assert.assertEquals("User display name does not match expected!", USER_NAME.reversed(), decoder(user!!.filter))
        Assert.assertEquals("User url does not match expected!", USER_URL, user!!.url)

        // Note: Since we use Transformations to map the result of the DB query to the user's friends list, we have to look
        // at the result of the DB itself, because there will be no observing of changes for the mediator live data
        // set up by the transformation.
        val friends = SecureDatabase.instance?.accountDao()?.findSubscriptionKeys(user!!.filter)

        Assert.assertEquals("User should have themselves (only) in their friends list!", 1, friends?.value?.size)
        Assert.assertEquals("User should be listed as the subscriber of the account!", USER_DISPLAY_NAME.reversed(), decoder(friends?.value?.get(0)?.subscriber!!))
        Assert.assertEquals("User's URL should be listed as the subscription in the first friend!", USER_URL.reversed(), decoder(friends.value?.get(0)?.subscription!!))

        val key = CliqueConfig.createSecretKey(mockUserSym, TestCipherProviderSpi.provider)

        // The friends should have their information encrypted with the user's sym encryption.
        val encrypt = fun (string: String) : String {
            val cipher = Cipher.getInstance(mockUserSym.algorithm, TestCipherProviderSpi.provider)
            cipher.init(Cipher.ENCRYPT_MODE, key)
            return CliqueConfig.stringToEncodedString(string, cipher)
        }

        val encryptedDisplayName = encrypt.invoke(FRIEND_ONE_DISPLAY_NAME)
        val encryptedUrl = encrypt.invoke(FRIEND_ONE_URL)
        val encryptedKey = encrypt.invoke(FRIEND_ONE_READ_KEY)

        val friendSubscription = CliqueSubscription(encryptedDisplayName, encryptedUrl, encryptedKey)

        // The friends should have their information encrypted with the user's sym encryption.
        Friend.fromSubscription(friendSubscription) {
            val cipher = Cipher.getInstance(mockUserSym.algorithm, TestCipherProviderSpi.provider)
            cipher.init(Cipher.DECRYPT_MODE, key)
            cipher
        }

        val friendAccount = CliqueAccount(
                "Invalid Name",
                encryptedDisplayName,
                user!!.filter,
                encryptedKey,
                "Invalid Key",
                "Invalid Key",
                "Probably Should Match",
                "The User Info",
                encryptedUrl
        )

        SecureDatabase.instance?.accountDao()?.addAccount(friendAccount)

        Assert.assertNotNull("User should now have a non-null friends list!", friends.value)
        Assert.assertEquals("User should have exactly two friends in their friends list!", 2, friends.value?.size?: -1)
        Assert.assertEquals("User should be listed as the first subscriber of the account!", USER_DISPLAY_NAME.reversed(), decoder(friends.value?.get(0)?.subscriber!!))
        Assert.assertEquals("User's URL should be listed as the subscription in the first friend!", USER_URL.reversed(), decoder(friends.value?.get(0)?.subscription!!))
        Assert.assertEquals("User's friend's display name does not match expected!", FRIEND_ONE_DISPLAY_NAME.reversed(), decoder(friends.value?.get(1)?.subscriber!!))
        Assert.assertEquals("User's friend's url does not match expected!", FRIEND_ONE_URL.reversed(), decoder(friends.value?.get(1)?.subscription!!))
        Assert.assertEquals("User's friend's read key does not match expected!", FRIEND_ONE_READ_KEY.reversed(), decoder(friends.value?.get(1)?.feedReadKey!!))
    }

    companion object {
        const val USER_NAME = "MockUser"
        const val USER_DISPLAY_NAME = "Mock User"
        const val USER_URL = "https://MockStorage.net"

        const val FRIEND_ONE_READ_KEY = "MockFriendOneReadKey"
        const val FRIEND_ONE_DISPLAY_NAME = "Mock Friend One"
        const val FRIEND_ONE_URL = "https://mockstorage.net/friend1"
    }
}