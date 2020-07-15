package org.ajar.clique.facade

import org.ajar.clique.CliqueConfig
import org.ajar.clique.CliqueTestHelper
import org.ajar.clique.database.CliqueKey
import org.ajar.clique.database.CliqueSubscription
import org.ajar.clique.database.SecureDAOTestHelper
import org.ajar.clique.database.SecureDatabase
import org.ajar.clique.encryption.AsymmetricEncryptionDesc
import org.ajar.clique.encryption.CipherProvider
import org.ajar.clique.encryption.SymmetricEncryptionDesc
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import javax.crypto.Cipher

class FriendFacadeTest {

    @Before
    fun setup() {
        CliqueTestHelper.switchCliqueConfigForJDK()
        SecureDAOTestHelper.setupMockDatabase()
    }

    @After
    fun tearDown() {
        SecureDAOTestHelper.clear()
    }

    // This method is used when we pull out all the subscriptions that a given user has.
    // We map the subscription information into friends.
    @Test
    fun testFriendFromSubscription() {
        val symCipher = SymmetricEncryptionDesc.DEFAULT
        symCipher.createKeyGenSpec = CliqueTestHelper.createTestAESParameters()
        val symCipherProvider = CipherProvider.Symmetric(symCipher)
        val symKey = symCipher.generateSecretKey("MockKey")

        // Active user's symmetric encryption.
        val cipher = fun(mode: Int) : Cipher? {
            return symCipherProvider.cipher(mode, symKey)
        }

        // Publish Key
        val friendFeedCipher = AsymmetricEncryptionDesc.DEFAULT
        friendFeedCipher.createKeyGenSpec = CliqueTestHelper.createTestRSAParameters(friendFeedCipher)
        val friendFeedWriterProvider = CipherProvider.Public(friendFeedCipher)

        val keyPair = friendFeedCipher.generateKeyPair("MockFeedKeyPair")

        // This is the key that would have been previously saved during a subscription exchange.
        val feedKey = CliqueKey(
                CliqueConfig.stringToEncodedString("$FRIEND_DISPLAY_NAME:key2", cipher.invoke(Cipher.ENCRYPT_MODE)!!),
                CliqueConfig.byteArrayToEncodedString(keyPair.private.encoded, cipher.invoke(Cipher.ENCRYPT_MODE)!!),
                CliqueConfig.stringToEncodedString(friendFeedCipher.toString(), cipher.invoke(Cipher.ENCRYPT_MODE)!!)
        )

        SecureDatabase.instance!!.keyDao().addKey(feedKey)

        // Rotate Key
        val friendRotateCipher = SymmetricEncryptionDesc.DEFAULT
        friendRotateCipher.createKeyGenSpec = CliqueTestHelper.createTestAESParameters()
        val friendRotateProvider = CipherProvider.Symmetric(friendRotateCipher)

        val rotateSecretKey = friendRotateCipher.generateSecretKey()

        val rotateKey = CliqueKey(
                CliqueConfig.stringToEncodedString("$FRIEND_DISPLAY_NAME:key1", cipher.invoke(Cipher.ENCRYPT_MODE)!!),
                CliqueConfig.byteArrayToEncodedString(rotateSecretKey.encoded, cipher.invoke(Cipher.ENCRYPT_MODE)!!),
                CliqueConfig.stringToEncodedString(friendRotateCipher.toString(), cipher.invoke(Cipher.ENCRYPT_MODE)!!)
        )

        SecureDatabase.instance!!.keyDao().addKey(rotateKey)

        val subscription = CliqueSubscription(FRIEND_DISPLAY_NAME, FRIEND_URL, "", "", "")
        subscription.subscriber = CliqueConfig.stringToEncodedString(FRIEND_DISPLAY_NAME, cipher(Cipher.ENCRYPT_MODE)!!)
        subscription.feedReadKey = CliqueConfig.stringToEncodedString("$FRIEND_DISPLAY_NAME:key2", cipher.invoke(Cipher.ENCRYPT_MODE)!!)
        subscription.rotateKey = CliqueConfig.stringToEncodedString("$FRIEND_DISPLAY_NAME:key1", cipher.invoke(Cipher.ENCRYPT_MODE)!!)
        subscription.subscription = CliqueConfig.stringToEncodedString(FRIEND_URL, cipher(Cipher.ENCRYPT_MODE)!!)

        val friend = Friend.fromSubscription(subscription, cipher)

        assertEquals(friend.displayName, FRIEND_DISPLAY_NAME)
        assertEquals(friend.url, FRIEND_URL)

        val encryptedFeed = CliqueConfig.stringToEncodedString(
                FRIEND_FEED,
                friendFeedWriterProvider.cipher(Cipher.ENCRYPT_MODE, keyPair.public)
        )

        assertEquals(FRIEND_FEED, friend.decryptFeed(encryptedFeed))

        val encryptedRotate = CliqueConfig.stringToEncodedString(
                FRIEND_ROTATE,
                friendRotateProvider.cipher(Cipher.ENCRYPT_MODE, rotateSecretKey)
        )

        assertEquals(FRIEND_ROTATE, friend.decryptStringRotation(encryptedRotate))
    }

    companion object {
        const val FRIEND_DISPLAY_NAME = "Mock Friend"
        const val FRIEND_URL = "Mock Friend Url"
        const val FRIEND_FEED = "Mock Friend Feed Data"
        const val FRIEND_ROTATE = "Mock Friend Rotate Data"
    }
}