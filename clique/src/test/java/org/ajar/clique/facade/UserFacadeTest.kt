package org.ajar.clique.facade

import android.content.Context
import org.ajar.clique.CliqueConfig
import org.ajar.clique.CliqueConfigTest
import org.ajar.clique.CliqueTestHelper
import org.ajar.clique.SymmetricEncryptionWrapper
import org.ajar.clique.database.CliqueAccount
import org.ajar.clique.database.CliqueSubscription
import org.ajar.clique.database.SecureDAOTestHelper
import org.ajar.clique.database.SecureDatabase
import org.ajar.clique.encryption.*
import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito
import java.security.*
import javax.crypto.Cipher
import javax.crypto.SecretKey

class UserFacadeTest {

    private val mockContext = Mockito.mock(Context::class.java)
    private val userSym = SymmetricEncryptionDesc.DEFAULT
    private val userAsym = AsymmetricEncryptionDesc.DEFAULT
    private val userSymCipherProvider = CipherProvider.Symmetric(userSym)

    private val configCipherPublicProvider = CipherProvider.Symmetric(SymmetricEncryptionDesc.DEFAULT)

    private lateinit var provider: Provider
    private lateinit var keyStoreSpi: KeyStoreSpi
    private lateinit var keyStore: KeyStore
    private lateinit var symKey: SecretKey
    private var configKey: Key? = null

    private var user: User? = null

    private fun encryptedSym(string: String): String =
            CliqueConfig.stringToEncodedString(string, userSymCipherProvider.cipher(Cipher.ENCRYPT_MODE, symKey))

    private fun decryptedSym(string: String): String =
            CliqueConfig.encodedStringToString(string, userSymCipherProvider.cipher(Cipher.DECRYPT_MODE, symKey))

    private fun encryptedConfig(string: String): String =
            CliqueConfig.stringToEncodedString(string, configCipherPublicProvider.cipher(Cipher.ENCRYPT_MODE, configKey!!))

    private fun decryptedConfig(string: String): String =
            CliqueConfig.encodedStringToString(string, configCipherPublicProvider.cipher(Cipher.DECRYPT_MODE, configKey!!))

    private fun decryptedSymKey(string: String): ByteArray =
            CliqueConfig.encodedStringToByteArray(string, configCipherPublicProvider.cipher(Cipher.DECRYPT_MODE, configKey!!))

    private fun loadSymKey() {
        val encryptedUserName = encryptedConfig(USER_NAME)
        val account = SecureDatabase.instance!!.accountDao().findAccount(encryptedUserName)

        val symAlgo = decryptedConfig(account!!.algo)
        val desc = SymmetricEncryptionDesc.fromString(symAlgo)

        val encryptedKey = decryptedSymKey(account.sym)

        symKey = desc.secretKeyFromBytes(encryptedKey)
    }

    @Before
    fun setup() {
        CliqueTestHelper.switchCliqueConfigForJDK()

        provider = Mockito.mock(Provider::class.java)
        CliqueConfig.provider = provider

        keyStoreSpi = Mockito.mock(KeyStoreSpi::class.java)
        keyStore = CliqueConfigTest.MockKeyStore(keyStoreSpi, provider)
        keyStore.load(null)

        Mockito.verify(keyStoreSpi).engineLoad(null)

        CliqueConfig.setKeyStore(keyStore)
        SecureDAOTestHelper.setupMockDatabase()

        AsymmetricEncryptionDesc.setKeyPairGeneratorCreator { algo, _ ->
            KeyPairGenerator.getInstance(algo)
        }

        val captureKey = fun(key: Key) {
            if(configKey == null) configKey = key
        }

        val originalEncryption = CliqueConfig.tableNameEncryption
        val wrappedEncryption = SymmetricEncryptionWrapper(originalEncryption, captureKey)
        CliqueConfig.tableNameEncryption = wrappedEncryption

        userAsym.createKeyGenSpec = CliqueTestHelper.createTestRSAParameters(userAsym)
        userSym.createKeyGenSpec = CliqueTestHelper.createTestAESParameters()
    }

    @After
    fun tearDown() {
        SecureDAOTestHelper.clear()
        CliqueConfig.getKeyStore()?.deleteEntry(USER_NAME)
    }

    @Test
    fun createUser() {
        User.createUser(mockContext, USER_NAME, USER_PASSWORD, USER_DISPLAY_NAME, USER_URL, userSym, userAsym)

        Mockito.verify(keyStoreSpi).engineSetEntry(
                Mockito.eq(USER_NAME),
                Mockito.any(KeyStore.SecretKeyEntry::class.java),
                Mockito.any(KeyStore.PasswordProtection::class.java)
        )

        Mockito.`when`(keyStoreSpi.engineGetKey(USER_NAME, USER_PASSWORD.toCharArray())).thenReturn(configKey)

        user = User.loadUser(mockContext, USER_NAME, USER_PASSWORD)

        Mockito.verify(keyStoreSpi).engineGetKey(USER_NAME, USER_PASSWORD.toCharArray())

        loadSymKey()

        Assert.assertEquals("User name does not match expected!", USER_NAME, user!!.name)
        Assert.assertEquals("User display name does not match expected!", USER_NAME, decryptedSym(user!!.filter))
        Assert.assertEquals("User url does not match expected!", USER_URL, user!!.url)

        // Note: Since we use Transformations to map the result of the DB query to the user's friends list, we have to look
        // at the result of the DB itself, because there will be no observing of changes for the mediator live data
        // set up by the transformation.
        val friends = SecureDatabase.instance?.accountDao()?.observeSubscriptionKeys(user!!.filter)

        Assert.assertEquals("User should have themselves (only) in their friends list!", 1, friends?.value?.size)
        Assert.assertEquals("User should be listed as the subscriber of the account!", USER_DISPLAY_NAME, decryptedSym(friends?.value?.get(0)?.subscriber!!))
        Assert.assertEquals("User's URL should be listed as the subscription in the first friend!", USER_URL, decryptedSym(friends.value?.get(0)?.subscription!!))
    }

    @Test
    fun addFriends() {
        User.createUser(mockContext, USER_NAME, USER_PASSWORD, USER_DISPLAY_NAME, USER_URL, userSym, userAsym)

        Mockito.verify(keyStoreSpi).engineSetEntry(
                Mockito.eq(USER_NAME),
                Mockito.any(KeyStore.SecretKeyEntry::class.java),
                Mockito.any(KeyStore.PasswordProtection::class.java)
        )

        Mockito.`when`(keyStoreSpi.engineGetKey(USER_NAME, USER_PASSWORD.toCharArray())).thenReturn(configKey)

        user = User.loadUser(mockContext, USER_NAME, USER_PASSWORD)

        Mockito.verify(keyStoreSpi).engineGetKey(USER_NAME, USER_PASSWORD.toCharArray())

        loadSymKey()

        Assert.assertEquals("User name does not match expected!", USER_NAME, user!!.name)
        Assert.assertEquals("User display name does not match expected!", USER_NAME, decryptedSym(user!!.filter))
        Assert.assertEquals("User url does not match expected!", USER_URL, user!!.url)

        // Note: Since we use Transformations to map the result of the DB query to the user's friends list, we have to look
        // at the result of the DB itself, because there will be no observing of changes for the mediator live data
        // set up by the transformation.
        val friends = SecureDatabase.instance?.accountDao()?.observeSubscriptionKeys(user!!.filter)

        Assert.assertEquals("User should have themselves (only) in their friends list!", 1, friends?.value?.size)
        Assert.assertEquals("User should be listed as the subscriber of the account!", USER_DISPLAY_NAME, decryptedSym(friends?.value?.get(0)?.subscriber!!))
        Assert.assertEquals("User's URL should be listed as the subscription in the first friend!", USER_URL, decryptedSym(friends.value?.get(0)?.subscription!!))

        val key = userSym.generateSecretKey("MockUserKey")

        val encryptedDisplayName = encryptedSym(FRIEND_ONE_DISPLAY_NAME)
        val encryptedUrl = encryptedSym(FRIEND_ONE_URL)
        val encryptedKey = encryptedSym(FRIEND_ONE_READ_KEY)
        val encryptedRotate = encryptedSym(FRIEND_ONE_ROTATE_KEY)
        val encryptedVerify = encryptedSym(FRIEND_ONE_VERIFY_KEY)

        val friendSubscription = CliqueSubscription(encryptedDisplayName, encryptedUrl, encryptedKey, encryptedRotate, encryptedVerify)

        // The friends should have their information encrypted with the user's sym encryption.
        Friend.fromSubscription(friendSubscription) {
            userSymCipherProvider.cipher(it, symKey)
        }

        val friendAccount = CliqueAccount(
                "Invalid Name",
                encryptedDisplayName,
                user!!.filter,
                encryptedRotate,
                encryptedKey,
                encryptedVerify,
                "Invalid Key",
                "Probably Should Match",
                encryptedUrl
        )

        SecureDatabase.instance?.accountDao()?.addAccount(friendAccount)

        Assert.assertNotNull("User should now have a non-null friends list!", friends.value)
        Assert.assertEquals("User should have exactly two friends in their friends list!", 2, friends.value?.size?: -1)

        val userIndex = if(decryptedSym(friends.value?.get(0)?.subscriber!!) == USER_DISPLAY_NAME) 0 else 1
        val friendIndex = if(userIndex == 0) 1 else 0

        Assert.assertEquals("User should be listed as the first subscriber of the account!", USER_DISPLAY_NAME, decryptedSym(friends.value?.get(userIndex)?.subscriber!!))
        Assert.assertEquals("User's URL should be listed as the subscription in the first friend!", USER_URL, decryptedSym(friends.value?.get(userIndex)?.subscription!!))
        Assert.assertEquals("User's friend's display name does not match expected!", FRIEND_ONE_DISPLAY_NAME, decryptedSym(friends.value?.get(friendIndex)?.subscriber!!))
        Assert.assertEquals("User's friend's url does not match expected!", FRIEND_ONE_URL, decryptedSym(friends.value?.get(friendIndex)?.subscription!!))
        Assert.assertEquals("User's friend's read key does not match expected!", FRIEND_ONE_READ_KEY, decryptedSym(friends.value?.get(friendIndex)?.feedReadKey!!))
        Assert.assertEquals("User's friend's rotate key does not match expected!", FRIEND_ONE_ROTATE_KEY, decryptedSym(friends.value?.get(friendIndex)?.rotateKey!!))
        Assert.assertEquals("User's friend's verify key does not match expected!", FRIEND_ONE_VERIFY_KEY, decryptedSym(friends.value?.get(friendIndex)?.verifyKey!!))
    }

    companion object {
        const val USER_NAME = "MockUser"
        const val USER_PASSWORD ="MockUserPassword"
        const val USER_DISPLAY_NAME = "Mock User"
        const val USER_URL = "https://MockStorage.net"

        const val FRIEND_ONE_READ_KEY = "MockFriendOneReadKey"
        const val FRIEND_ONE_ROTATE_KEY = "MockFriendOneRotateKey"
        const val FRIEND_ONE_VERIFY_KEY = "MockFriendOneVerifyKey"
        const val FRIEND_ONE_DISPLAY_NAME = "Mock Friend One"
        const val FRIEND_ONE_URL = "https://mockstorage.net/friend1"
    }
}