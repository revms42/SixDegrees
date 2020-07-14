package org.ajar.clique.exchange

import android.content.Context
import android.security.keystore.KeyProperties
import org.ajar.clique.*
import org.ajar.clique.database.*
import org.ajar.clique.encryption.*
import org.ajar.clique.facade.Friend
import org.ajar.clique.facade.User
import org.ajar.clique.facade.UserFacadeTest
import org.ajar.clique.transaction.RotationExchange
import org.ajar.clique.transaction.SubscriptionExchange
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito
import java.security.*
import javax.crypto.Cipher
import javax.crypto.SecretKey

class RotationExchangeTest {

    private lateinit var provider: Provider
    private lateinit var keyStoreSpi: KeyStoreSpi
    private lateinit var keyStore: KeyStore

    private val userSym = SymmetricEncryptionDesc.DEFAULT
    private val userAsym = AsymmetricEncryptionDesc.DEFAULT

    private val configCipherPublicProvider = CipherProvider.Symmetric(SymmetricEncryptionDesc.DEFAULT)
    private var userConfigKey: Key? = null
    private var goodFriendConfigKey: Key? = null
    private var badFriendConfigKey: Key? = null

    private lateinit var userSymKeyCipherProvider: CipherProvider.Symmetric
    private lateinit var userSymKey: SecretKey

    private val mockContext = Mockito.mock(Context::class.java)
    private lateinit var user: User
    private lateinit var goodFriend: Friend
    private lateinit var badFriend: Friend

    private lateinit var oldPublishKey: String
    private lateinit var oldReadKey: String
    private lateinit var oldPublishUrl: String

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

        val captureKey = fun(key: Key) {
            // We rely on knowing the order of calls here in order to correctly set the values.
            when {
                userConfigKey == null -> userConfigKey = key
                goodFriendConfigKey == null -> goodFriendConfigKey = key
                badFriendConfigKey == null -> badFriendConfigKey = key
            }
        }

        val originalEncryption = CliqueConfig.tableNameEncryption
        val wrappedEncryption = SymmetricEncryptionWrapper(originalEncryption, captureKey)
        CliqueConfig.tableNameEncryption = wrappedEncryption

        setupUser()
        setupFriends()
    }

    private fun encryptedWithConfig(string: String, config: Key): String =
            CliqueConfig.stringToEncodedString(string, configCipherPublicProvider.cipher(Cipher.ENCRYPT_MODE, config))
    private fun decryptedWithConfig(string: String, config: Key): String =
            CliqueConfig.encodedStringToString(string, configCipherPublicProvider.cipher(Cipher.DECRYPT_MODE, config))

    private fun decryptedSymKey(string: String, config: Key): ByteArray =
            CliqueConfig.encodedStringToByteArray(string, configCipherPublicProvider.cipher(Cipher.DECRYPT_MODE, config))

    private fun encryptedWithUserConfig(string: String): String = encryptedWithConfig(string, userConfigKey!!)
    private fun decryptedWithUserConfig(string: String): String = decryptedWithConfig(string, userConfigKey!!)

    private fun decryptedUserSymKey(string: String): ByteArray = decryptedSymKey(string, userConfigKey!!)

    private val userSymCipher = fun(mode: Int): Cipher? = userSymKeyCipherProvider.cipher(mode, userSymKey)

    private fun userConfigCipher(mode: Int) : Cipher? {
        return userConfigKey?.let { configCipherPublicProvider.cipher(mode, it) }
    }

    private fun setupUser() {
        user = setupAccount(USER_NAME, USER_PASSWORD, USER_DISPLAY_NAME, USER_URL, userAsym, userSym)
        Mockito.verify(keyStoreSpi).engineGetKey(SubscriptionExchangeTest.USER_NAME, SubscriptionExchangeTest.USER_PASSWORD.toCharArray())

        loadUserSymKey()

        val account = getAccount(user.name, ::userConfigCipher)!!
        oldPublishKey = account.key1
        oldReadKey = account.key2
        oldPublishUrl = account.url
    }

    private fun loadUserSymKey() {
        val encryptedUserName = encryptedWithUserConfig(SubscriptionExchangeTest.USER_NAME)
        val account = SecureDatabase.instance!!.accountDao().findAccount(encryptedUserName)

        val symAlgo = decryptedWithUserConfig(account!!.algo)
        val desc = SymmetricEncryptionDesc.fromString(symAlgo)
        userSymKeyCipherProvider = CipherProvider.Symmetric(desc)

        val encryptedKey = decryptedUserSymKey(account.sym)

        userSymKey = desc.secretKeyFromBytes(encryptedKey)
    }

    private fun setupFriends() {
        goodFriend = setupFriend(GOOD_FRIEND_NAME, GOOD_FRIEND_DISPLAY_NAME, GOOD_FRIEND_URL)
        badFriend = setupFriend(BAD_FRIEND_NAME, BAD_FRIEND_DISPLAY_NAME, BAD_FRIEND_URL)
    }

    private fun setupFriend(friendName: String, friendDisplayName: String, friendUrl: String): Friend {
        val friend = setupAccount(friendName, USER_PASSWORD, friendDisplayName, friendUrl, userAsym, userSym)
        Mockito.verify(keyStoreSpi).engineGetKey(friendName, USER_PASSWORD.toCharArray())

        val exchangeEncryption = EncryptionBuilder.symmetric().build() as SymmetricEncryption
        exchangeEncryption.createKeyGenSpec = CliqueTestHelper.createTestAESParameters()

        val key = exchangeEncryption.generateSecretKey("exchangeKeyGood")

        val exchangeCipherProvider = CipherProvider.Symmetric(exchangeEncryption)

        val exchangeCipher = fun(mode: Int) : Cipher {
            return exchangeCipherProvider.cipher(mode, key)
        }

        val exchangeFriend = SubscriptionExchange.createExchange(friend, exchangeCipher)
        val invitationFriend = exchangeFriend.createInvitation("$friendDisplayName's Friend $USER_NAME")

        val exchangeUser = SubscriptionExchange.createExchange(user, exchangeCipher)
        exchangeUser.readInvitation(invitationFriend!!)

        val friendNameSubscription = "$USER_NAME's Friend $friendDisplayName"
        val invitationUser = exchangeUser.createInvitation(friendNameSubscription)
        exchangeFriend.readInvitation(invitationUser!!)

        val preFriendList = SecureDatabase.instance?.accountDao()?.observeSubscriptionKeys(user.filter)

        exchangeFriend.finalizeExchange()
        exchangeUser.finalizeExchange()

        return Friend.fromSubscription(preFriendList!!.value!!.first {
            val encrypted = CliqueConfig.stringToEncodedString(friendNameSubscription, user.symCipher(Cipher.ENCRYPT_MODE)!!)
            encrypted == it.subscriber
        }, user.symCipher)
    }

    private fun setupAccount(
            userName: String,
            userPassword: String,
            userDisplayName: String,
            userUrl: String,
            userAsym: AsymmetricEncryption,
            userSym: SymmetricEncryption
    ): User {
        userAsym.createKeyGenSpec = CliqueTestHelper.createTestRSAParameters(userAsym)
        userSym.createKeyGenSpec = CliqueTestHelper.createTestAESParameters()


        User.createUser(mockContext, userName, userPassword, userDisplayName, userUrl, userSym, userAsym)

        Mockito.verify(keyStoreSpi).engineSetEntry(
                Mockito.eq(userName),
                Mockito.any(KeyStore.SecretKeyEntry::class.java),
                Mockito.any(KeyStore.PasswordProtection::class.java)
        )

        Mockito.`when`(keyStoreSpi.engineGetKey(userName, userPassword.toCharArray())).then {
            when(userName) {
                USER_NAME -> userConfigKey
                GOOD_FRIEND_NAME -> goodFriendConfigKey
                BAD_FRIEND_NAME -> badFriendConfigKey
                else -> null
            }
        }

        return User.loadUser(mockContext, userName, userPassword)!!
    }

    @After
    fun tearDown() {
        SecureDAOTestHelper.clear()
        CliqueConfig.getKeyStore()?.deleteEntry(USER_NAME)
        CliqueConfig.getKeyStore()?.deleteEntry(GOOD_FRIEND_NAME)
        CliqueConfig.getKeyStore()?.deleteEntry(BAD_FRIEND_NAME)
    }

    private fun getAccount(name: String, configCipher: (Int) -> Cipher?): CliqueAccount? {
        val properName = CliqueConfig.stringToEncodedString(name, configCipher.invoke(Cipher.ENCRYPT_MODE)!!)
        return SecureDatabase.instance!!.accountDao().findAccount(properName)
    }

    private fun getKey(name: String): CliqueKey? {
        return SecureDatabase.instance!!.keyDao().findKey(name)
    }

    @Test
    fun testSendRotationExchangeURLandFriend() {
        val preFriendList = SecureDatabase.instance?.accountDao()?.observeSubscriptionKeys(user.filter)
        assertEquals("Friends list is the wrong size", 3, preFriendList?.value?.size)

        val exchange = RotationExchange.startRotation(user)

        exchange.removeFriend(badFriend)

        val newEncryption = EncryptionBuilder.asymetric().blockMode(
                BlockModeDesc.findBlockMode(KeyProperties.BLOCK_MODE_CBC)!!
        ).build() as AsymmetricEncryption

        newEncryption.createKeyGenSpec = CliqueTestHelper.createTestRSAParameters(newEncryption)

        lateinit var capturedKeyPair: KeyPair
        val captureKeyPair = fun(pair: KeyPair) {
            capturedKeyPair = pair
        }

        val newEncryptionWrapper = AsymetricEncryptionWrapper(newEncryption, captureKeyPair)

        exchange.changeEncryption(newEncryptionWrapper)
        exchange.changeUrl(NEW_URL)

        val rotationPublishData = exchange.finalizeExchange()

        // Check to make sure that the rotation publish data matches expected
        assertNotNull("Rotation publish data not created", rotationPublishData)

        assertEquals("Original publish key does not match.", oldPublishKey, rotationPublishData?.oldPublishKey)
        assertEquals("Original publish url does not match.", oldPublishUrl, rotationPublishData?.oldUrl)

        // Check the user to make sure that the right friend was removed.
        assertEquals("Friends list is the wrong size", 2, preFriendList?.value?.size)
        val remainingFriend = preFriendList?.value?.firstOrNull { friend ->
            // Because you have your own filter on your account you are your own friend, so find the friend that isn't you
            CliqueConfig.encodedStringToString(friend.subscriber, userSymCipher(Cipher.DECRYPT_MODE)!!) != USER_DISPLAY_NAME
        }
        assertEquals("Expected friend is not in the friends list",
                goodFriend.displayName,
                Friend.fromSubscription(remainingFriend!!, userSymCipher).displayName
        )

        // Check that the rotation message has the correct values
        val rotationMessageGoodFriend = goodFriend.createRotationMessage(user)

        assertTrue("At this point the rotation should be encrypted", rotationMessageGoodFriend.encrypted)
        assertEquals("New cipher is incorrect in friend rotation message.",
                newEncryption.toString(),
                goodFriend.decryptStringRotation(rotationMessageGoodFriend.cipher!!)
        )
        assertArrayEquals("New key does not have the correct bytes",
                capturedKeyPair.private.encoded,
                goodFriend.decryptByteArrayRotation(rotationMessageGoodFriend.encodedKey!!)
        )
        assertEquals("New URL does not match expected value",
                NEW_URL,
                goodFriend.decryptStringRotation(rotationMessageGoodFriend.url!!)
        )

        // Make sure the excluded friend can't read the message
        try {
            assertNotEquals("Wrong friend can read the encrypted cipher description.",
                    newEncryption.toString(),
                    badFriend.decryptStringRotation(rotationMessageGoodFriend.cipher!!)
            )
        } catch (e: Exception) {
            // Not a problem
        }

//        You can't do this, but I'd like to.
//        assertArrayNotEquals("New key does not have the correct bytes",
//                capturedKeyPair.private.encoded,
//                badFriend.decryptByteArrayRotation(rotationMessageGoodFriend.key!!)
//        )
        try {
            assertNotEquals("Wrong friend can read the encrypted url",
                    NEW_URL,
                    badFriend.decryptStringRotation(rotationMessageGoodFriend.url!!)
            )
        } catch (e : Exception) {
            // Not a problem
        }

        // Make sure that cleanup happens
        rotationPublishData!!.cleanUp()

        assertNull("Cleanup did not clean up the publish key", getKey(oldPublishKey))
        assertNull("Cleanup did not clean up the ready key", getKey(oldReadKey))
    }

    companion object {
        const val USER_NAME = UserFacadeTest.USER_NAME
        const val USER_URL = UserFacadeTest.USER_URL
        const val USER_PASSWORD = UserFacadeTest.USER_PASSWORD
        const val USER_DISPLAY_NAME = UserFacadeTest.USER_DISPLAY_NAME

        const val GOOD_FRIEND_NAME = "GoodFriendName"
        const val GOOD_FRIEND_DISPLAY_NAME = "Good Friend Display Name"
        const val GOOD_FRIEND_URL = "https://goodfriend.com"

        const val BAD_FRIEND_NAME = "BadFriendName"
        const val BAD_FRIEND_DISPLAY_NAME = "Bad Friend Display Name"
        const val BAD_FRIEND_URL = "https://badfriend.com"

        const val NEW_URL = "https://mynewsite.com"
    }
}