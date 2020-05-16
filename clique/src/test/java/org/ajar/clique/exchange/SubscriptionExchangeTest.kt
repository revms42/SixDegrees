package org.ajar.clique.exchange

import android.content.Context
import org.ajar.clique.*
import org.ajar.clique.database.SecureDAOTestHelper
import org.ajar.clique.database.SecureDatabase
import org.ajar.clique.encryption.*
import org.ajar.clique.facade.User
import org.ajar.clique.transaction.Invitation
import org.ajar.clique.transaction.SubscriptionExchange
import org.junit.*
import org.mockito.Mockito
import java.lang.NullPointerException
import java.security.*
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.SecretKey

class SubscriptionExchangeTest {
    private val mockContext = Mockito.mock(Context::class.java)

    private val userSym = SymmetricEncryptionDesc.DEFAULT
    private val userAsym = AsymmetricEncryptionDesc.DEFAULT

    private var userConfigKey: Key? = null
    private var friendConfigKey: Key? = null
    private val configCipherPublicProvider = CipherProvider.Symmetric(SymmetricEncryptionDesc.DEFAULT)

    private lateinit var userSymKey: SecretKey
    private lateinit var userSymKeyCipherProvider: CipherProvider.Symmetric
    private lateinit var userReadKey: String

    private lateinit var friendSymKey: SecretKey
    private lateinit var friendSymKeyCipherProvider: CipherProvider.Symmetric
    private lateinit var friendReadKey: String

    private lateinit var provider: Provider
    private lateinit var keyStoreSpi: KeyStoreSpi
    private lateinit var keyStore: KeyStore


    private var user: User? = null
    private var friend: User? = null

    private lateinit var exchange: SubscriptionExchange
    private lateinit var exchangeCipher: (mode: Int) -> Cipher
    
    private lateinit var encoder: (String) -> String
    private lateinit var decoder: (String) -> String

    private fun encryptedWithConfig(string: String, config: Key): String =
            CliqueConfig.stringToEncodedString(string, configCipherPublicProvider.cipher(Cipher.ENCRYPT_MODE, config))

    private fun decryptedWithConfig(string: String, config: Key): String =
            CliqueConfig.encodedStringToString(string, configCipherPublicProvider.cipher(Cipher.DECRYPT_MODE, config))

    private fun decryptedSymKey(string: String, config: Key): ByteArray =
            CliqueConfig.encodedStringToByteArray(string, configCipherPublicProvider.cipher(Cipher.DECRYPT_MODE, config))
    
    private fun encryptedWithUserConfig(string: String): String = encryptedWithConfig(string, userConfigKey!!)

    private fun decryptedWithUserConfig(string: String): String = decryptedWithConfig(string, userConfigKey!!)

    private fun decryptedUserSymKey(string: String): ByteArray = decryptedSymKey(string, userConfigKey!!)

    private fun encryptedWithFriendConfig(string: String): String = encryptedWithConfig(string, friendConfigKey!!)

    private fun decryptedWithFriendConfig(string: String): String = decryptedWithConfig(string, friendConfigKey!!)

    private fun decryptedFriendSymKey(string: String): ByteArray = decryptedSymKey(string, friendConfigKey!!)

    private fun loadUserSymKey() {
        val encryptedUserName = encryptedWithUserConfig(USER_NAME)
        val account = SecureDatabase.instance!!.accountDao().findAccount(encryptedUserName)

        val symAlgo = decryptedWithUserConfig(account!!.algo)
        val desc = SymmetricEncryptionDesc.fromString(symAlgo)
        userSymKeyCipherProvider = CipherProvider.Symmetric(desc)

        val encryptedKey = decryptedUserSymKey(account.sym)

        userSymKey = desc.secretKeyFromBytes(encryptedKey)
    }

    private fun loadFriendSymKey() {
        val encryptedUserName = encryptedWithFriendConfig(FRIEND_ONE_NAME)
        val account = SecureDatabase.instance!!.accountDao().findAccount(encryptedUserName)

        val symAlgo = decryptedWithFriendConfig(account!!.algo)
        val desc = SymmetricEncryptionDesc.fromString(symAlgo)
        friendSymKeyCipherProvider = CipherProvider.Symmetric(desc)

        val encryptedKey = decryptedFriendSymKey(account.sym)

        friendSymKey = desc.secretKeyFromBytes(encryptedKey)
    }

    private fun loadUserReadKey() {
        val encryptedUserName = encryptedWithUserConfig(USER_NAME)
        val account = SecureDatabase.instance!!.accountDao().findAccount(encryptedUserName)

        val readKeyName = account!!.key2

        val readCliqueKey = SecureDatabase.instance!!.keyDao().findKey(readKeyName)
        Assert.assertNotNull("Could not find user read key in keyDao!", readCliqueKey)

        userReadKey = CliqueConfig.encodedStringToString(readCliqueKey!!.key, userSymKeyCipherProvider.cipher(Cipher.DECRYPT_MODE, userSymKey))
    }

    private fun loadFriendReadKey() {
        val encryptedFriendName = encryptedWithFriendConfig(FRIEND_ONE_NAME)
        val account = SecureDatabase.instance!!.accountDao().findAccount(encryptedFriendName)

        val readKeyName = account!!.key2

        val readCliqueKey = SecureDatabase.instance!!.keyDao().findKey(readKeyName)
        Assert.assertNotNull("Could not find friend read key in keyDao!", readCliqueKey)

        friendReadKey = CliqueConfig.encodedStringToString(readCliqueKey!!.key, friendSymKeyCipherProvider.cipher(Cipher.DECRYPT_MODE, friendSymKey))
    }

    private fun setupUser() {
        user = setupUser(USER_NAME, USER_PASSWORD, USER_DISPLAY_NAME, USER_URL, userAsym, userSym, true)
        Mockito.verify(keyStoreSpi).engineGetKey(USER_NAME, USER_PASSWORD.toCharArray())

        loadUserSymKey()
        loadUserReadKey()
    }

    private fun setupFriend() {
        friend = setupUser(FRIEND_ONE_NAME, USER_PASSWORD, FRIEND_ONE_DISPLAY_NAME, FRIEND_ONE_URL, userAsym, userSym, false)
        Mockito.verify(keyStoreSpi).engineGetKey(FRIEND_ONE_NAME, USER_PASSWORD.toCharArray())

        loadFriendSymKey()
        loadFriendReadKey()
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
            // We rely on knowing the order of calls here in order to correctly set the values.
            if(userConfigKey == null) {
                userConfigKey = key
            } else if(friendConfigKey == null) {
                friendConfigKey = key
            }
        }

        val originalEncryption = CliqueConfig.tableNameEncryption
        val wrappedEncryption = SymetricEncryptionWrapper(originalEncryption, captureKey)
        CliqueConfig.tableNameEncryption = wrappedEncryption


        val exchangeEncryption = EncryptionBuilder.symmetric().build() as SymmetricEncryption
        exchangeEncryption.createKeyGenSpec = CliqueTestHelper.createTestAESParameters()

        val key = exchangeEncryption.generateSecretKey("exchangeKey")

        val exchangeCipherProvider = CipherProvider.Symmetric(exchangeEncryption)
        exchangeCipher = fun(mode: Int) : Cipher {
            return exchangeCipherProvider.cipher(mode, key)
        }

        setupUser()
        setupFriend()

        exchange = SubscriptionExchange.createExchange(user!!, exchangeCipher)

        decoder = fun(string: String) : String {
            return CliqueConfig.encodedStringToString(string, exchangeCipher.invoke(Cipher.DECRYPT_MODE))
        }

        encoder = fun(string: String) : String {
            return CliqueConfig.stringToEncodedString(string, exchangeCipher.invoke(Cipher.ENCRYPT_MODE))
        }
    }

    private fun setupUser(
            userName: String,
            userPassword: String,
            userDisplayName: String,
            userUrl: String,
            userAsym: AsymmetricEncryption,
            userSym: SymmetricEncryption,
            userConfigKey: Boolean
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
            if(userConfigKey) this.userConfigKey else friendConfigKey
        }

        return User.loadUser(mockContext, userName, userPassword)!!
    }

    @After
    fun tearDown() {
        SecureDAOTestHelper.clear()
        CliqueConfig.getKeyStore()?.deleteEntry(USER_NAME)
        CliqueConfig.getKeyStore()?.deleteEntry(FRIEND_ONE_NAME)
    }

    @Test
    fun testExchangeSubscriptionRequest() {
        var capturedRotateWriteKey: String? = null
        val captureRotationKeyPair = fun(keyPair: KeyPair) {
            capturedRotateWriteKey = CliqueConfig.byteArrayToEncodedString(keyPair.private.encoded, exchangeCipher.invoke(Cipher.ENCRYPT_MODE))
        }
        val rotCipherDesc = AsymetricEncryptionWrapper(AsymmetricEncryptionDesc.DEFAULT, captureRotationKeyPair)
        val invitation = exchange.createInvitation(FRIEND_ONE_DISPLAY_NAME, rotCipherDesc)

        Assert.assertNotNull("Invitation should not be null!", invitation)
        Assert.assertEquals("Invitation URL does not match expected!", USER_URL, decoder(invitation!!.url))
        Assert.assertEquals("Invitation read key does not match expected!", userReadKey, decoder(invitation.readKey))
        Assert.assertEquals("Invitation read key algo does not match expected!", userAsym.toString(), decoder(invitation.readAlgo))
        Assert.assertEquals("Invitation rotate key does not match expected!", capturedRotateWriteKey, invitation.rotateKey)
        Assert.assertEquals("Invitation rotate key algo does not match expected!", rotCipherDesc.toString(), decoder(invitation.rotateAlgo))
    }

    @Test
    fun testExchangeSubscriptionRespond() {
        val rotCipherDesc = AsymmetricEncryptionDesc.DEFAULT
        val invitation = Mockito.mock(Invitation::class.java)

        val keyPair = rotCipherDesc.generateKeyPair(FRIEND_ONE_NAME)
        val rotateKey = CliqueConfig.byteArrayToEncodedString(keyPair.private.encoded, exchangeCipher.invoke(Cipher.ENCRYPT_MODE))

        Mockito.`when`(invitation.readAlgo).thenReturn(CliqueConfig.stringToEncodedString(userAsym.toString(), exchangeCipher.invoke(Cipher.ENCRYPT_MODE)))
        Mockito.`when`(invitation.readKey).thenReturn(
            CliqueConfig.stringToEncodedString(
                    friendReadKey,
                    exchangeCipher.invoke(Cipher.ENCRYPT_MODE)
            )
        )
        Mockito.`when`(invitation.rotateAlgo).thenReturn(CliqueConfig.stringToEncodedString(rotCipherDesc.toString(), exchangeCipher.invoke(Cipher.ENCRYPT_MODE)))
        Mockito.`when`(invitation.rotateKey).thenReturn(rotateKey)
        Mockito.`when`(invitation.url).thenReturn(CliqueConfig.stringToEncodedString(FRIEND_ONE_URL, exchangeCipher.invoke(Cipher.ENCRYPT_MODE)))

        exchange.readInvitation(invitation)

        val userDecrypter = fun(string: String) : String =
                CliqueConfig.encodedStringToString(string, userSymKeyCipherProvider.cipher(Cipher.DECRYPT_MODE, userSymKey))

        Assert.assertEquals("Friend read algorithm does not match!", userAsym.toString(), userDecrypter(exchange.friendInfo.readAlgo!!))
        Assert.assertEquals("Friend read key does not match!",
                friendReadKey,
                userDecrypter(exchange.friendInfo.readKey!!)
        )
        Assert.assertEquals("Friend rotate algorithm does not match!", rotCipherDesc.toString(), userDecrypter(exchange.friendInfo.rotateReadAlgo!!))
        Assert.assertEquals("Friend rotate key does not match!",
                CliqueConfig.encodedStringToString(rotateKey, exchangeCipher.invoke(Cipher.DECRYPT_MODE)),
                userDecrypter(exchange.friendInfo.rotateReadKey!!)
        )
        Assert.assertEquals("Friend publish url does not match!", FRIEND_ONE_URL, userDecrypter(exchange.friendInfo.url!!))
    }

    /**
     * You're creating a request, then creating the friend on the response.
     */
    @Test
    fun testCreateFriendFromResponse() {
        // First, do what we did above to create a friend request (invitation)
        var capturedRotatePublishKey: String? = null
        var capturedRotateReadKey: String? = null
        val captureRotationKeyPair = fun(keyPair: KeyPair) {
            capturedRotateReadKey = CliqueConfig.byteArrayToEncodedString(keyPair.private.encoded, exchangeCipher.invoke(Cipher.ENCRYPT_MODE))
            capturedRotatePublishKey = CliqueConfig.byteArrayToEncodedString(keyPair.public.encoded, userSymKeyCipherProvider.cipher(Cipher.ENCRYPT_MODE, userSymKey))
        }
        var rotCipherDesc: AsymmetricEncryption = AsymetricEncryptionWrapper(AsymmetricEncryptionDesc.DEFAULT, captureRotationKeyPair)
        val invitation = exchange.createInvitation(FRIEND_ONE_DISPLAY_NAME, rotCipherDesc)

        Assert.assertNotNull("Invitation should not be null!", invitation)
        Assert.assertEquals("Invitation URL does not match expected!", USER_URL, decoder(invitation!!.url))
        Assert.assertEquals("Invitation read key does not match expected!", userReadKey, decoder(invitation.readKey))
        Assert.assertEquals("Invitation read key algo does not match expected!", userAsym.toString(), decoder(invitation.readAlgo))
        Assert.assertEquals("Invitation rotate key does not match expected!", capturedRotateReadKey, invitation.rotateKey)
        Assert.assertEquals("Invitation rotate key algo does not match expected!", rotCipherDesc.toString(), decoder(invitation.rotateAlgo))


        // Second, do what we did above to create a mock response to the invitation (response)
        val response = Mockito.mock(Invitation::class.java)

        rotCipherDesc = AsymmetricEncryptionDesc.DEFAULT

        val keyPair = rotCipherDesc.generateKeyPair(FRIEND_ONE_NAME)
        val rotateKey = CliqueConfig.byteArrayToEncodedString(keyPair.private.encoded, exchangeCipher.invoke(Cipher.ENCRYPT_MODE))

        Mockito.`when`(response.readAlgo).thenReturn(CliqueConfig.stringToEncodedString(userAsym.toString(), exchangeCipher.invoke(Cipher.ENCRYPT_MODE)))
        Mockito.`when`(response.readKey).thenReturn(
                CliqueConfig.stringToEncodedString(
                        friendReadKey,
                        exchangeCipher.invoke(Cipher.ENCRYPT_MODE)
                )
        )
        Mockito.`when`(response.rotateAlgo).thenReturn(CliqueConfig.stringToEncodedString(rotCipherDesc.toString(), exchangeCipher.invoke(Cipher.ENCRYPT_MODE)))
        Mockito.`when`(response.rotateKey).thenReturn(rotateKey)
        Mockito.`when`(response.url).thenReturn(CliqueConfig.stringToEncodedString(FRIEND_ONE_URL, exchangeCipher.invoke(Cipher.ENCRYPT_MODE)))

        // Read the response, putting the data into the exchange.
        exchange.readInvitation(response)

        // Assert that the data matches what you expect.
        val userDecrypter = fun(string: String) : String =
                CliqueConfig.encodedStringToString(string, userSymKeyCipherProvider.cipher(Cipher.DECRYPT_MODE, userSymKey))

        Assert.assertEquals("Friend read algorithm does not match!", userAsym.toString(), userDecrypter(exchange.friendInfo.readAlgo!!))
        Assert.assertEquals("Friend read key does not match!",
                friendReadKey,
                userDecrypter(exchange.friendInfo.readKey!!)
        )
        Assert.assertEquals("Friend rotate algorithm does not match!", rotCipherDesc.toString(), userDecrypter(exchange.friendInfo.rotateReadAlgo!!))
        Assert.assertEquals("Friend rotate key does not match!",
                CliqueConfig.encodedStringToString(rotateKey, exchangeCipher.invoke(Cipher.DECRYPT_MODE)),
                userDecrypter(exchange.friendInfo.rotateReadKey!!)
        )
        Assert.assertEquals("Friend publish url does not match!", FRIEND_ONE_URL, userDecrypter(exchange.friendInfo.url!!))

        // Load up the existing friends list to have something to compare to.
        val preFriendList = SecureDatabase.instance?.accountDao()?.findSubscriptionKeys(user!!.filter)
        Assert.assertEquals("Unexpected number of friends in friends list!",1, preFriendList?.value?.size)

        // Finalize that exchange to add the new friend to the user's account.
        exchange.finalizeExchange()

        // Grab all the information that you'll need to verify that a friend account has been set up.
        val userConfigCipher = fun(mode: Int): Cipher {
            return configCipherPublicProvider.cipher(mode, userConfigKey!!)
        }

        val friendAccountName = CliqueConfig.stringToEncodedString(FRIEND_ONE_DISPLAY_NAME, userConfigCipher.invoke(Cipher.ENCRYPT_MODE))
        val friendAccount = SecureDatabase.instance?.accountDao()?.findAccount(friendAccountName)
        val userAccountName = CliqueConfig.stringToEncodedString(user!!.name, userConfigCipher.invoke(Cipher.ENCRYPT_MODE))
        val userAccount = SecureDatabase.instance?.accountDao()?.findAccount(userAccountName)
                ?: throw NullPointerException("Could not find user account!")

        val userConfigDecode = fun(string: String) : String {
            return CliqueConfig.encodedStringToString(string, userConfigCipher.invoke(Cipher.DECRYPT_MODE))
        }

        val userSymmetricDecode = fun(string: String) : String {
            return CliqueConfig.encodedStringToString(string, userSymKeyCipherProvider.cipher(Cipher.DECRYPT_MODE, userSymKey))
        }

        // Verify that the friend is there and has the right information.
        Assert.assertNotNull("A friend account should be present!", friendAccount)
        Assert.assertEquals("Friend's display name does not match expected!", FRIEND_ONE_DISPLAY_NAME, userSymmetricDecode(friendAccount!!.displayName))
        Assert.assertEquals("Friend's filter is not the user's filter!", userAccount.filter, friendAccount.filter)
        Assert.assertEquals("Friend's symmetric key is not the users' symmetric key!", userAccount.sym, friendAccount.sym)
        Assert.assertEquals("Friend's symmetric algorithm is not the users' symmetric algorithm!", userAccount.algo, friendAccount.algo)
        Assert.assertEquals("Friend's publish url is not the expected url!", FRIEND_ONE_URL, userSymmetricDecode(friendAccount.url))

        // Check to see that the keys and algo descriptions are there as well.
        val subscriptionRotatePublish = SecureDatabase.instance?.keyDao()?.findKey(friendAccount.key1)
        val subscriptionRead = SecureDatabase.instance?.keyDao()?.findKey(friendAccount.key2)
        val subscriptionRotateRead = SecureDatabase.instance?.keyDao()?.findKey(friendAccount.key3)

        // Key 1: Subscription rotation notification publish key (the key used to notify a subscriber that you're rotating
        Assert.assertEquals("Friend's rotate notification publish key algorithm does not match the expected algorithm!",
                rotCipherDesc.toString(),
                userSymmetricDecode(subscriptionRotatePublish!!.cipher)
        )

        Assert.assertEquals("Friend's rotate notification publish key data does not match the expected key data!",
                capturedRotatePublishKey!!,
                subscriptionRotatePublish.key
        )

        // Key 2: Subscription Read Key (the key used to read a subscriber's feed)
        Assert.assertEquals("Friend's subscription read key algorithm does not match the expected algorithm!",
                userAsym.toString(),
                userSymmetricDecode(subscriptionRead!!.cipher)
        )
        Assert.assertEquals("Friend's subscription read key data does not match the expected key data!",
                friendReadKey,
                userSymmetricDecode(subscriptionRead.key)
        )

        // Key 3: Subscription rotation read key (the key you use to decode a subscription rotation event from the subscriber).
        Assert.assertEquals("Friend's subscription rotation read key algorithm does not match the expected algorithm!",
                rotCipherDesc.toString(),
                userSymmetricDecode(subscriptionRotateRead!!.cipher)
        )
        Assert.assertEquals("Friend's subscription rotation read key data does not match the expected key data!",
                CliqueConfig.encodedStringToString(rotateKey, exchangeCipher.invoke(Cipher.DECRYPT_MODE)),
                userSymmetricDecode(subscriptionRotateRead.key)
        )

        // Finally, check to see that the list of friends matches what is expected.
        Assert.assertEquals("Unexpected number of friends in friends list!",2, preFriendList?.value?.size)
        Assert.assertNotNull("Could not find the added friend!", preFriendList?.value?.firstOrNull { friend ->
            userSymmetricDecode(friend.subscriber) ==  FRIEND_ONE_DISPLAY_NAME
        })
    }

    /**
     * You're responding to a request, then creating a friend after you send a response.
     */
    @Test
    fun testCreateFriendFromRequest() {
        // First, do what we did above to create a mock response to the invitation (request)
        var rotCipherDesc: AsymmetricEncryption  = AsymmetricEncryptionDesc.DEFAULT

        val keyPair = rotCipherDesc.generateKeyPair(FRIEND_ONE_NAME)
        val rotateKey = CliqueConfig.byteArrayToEncodedString(keyPair.private.encoded, exchangeCipher.invoke(Cipher.ENCRYPT_MODE))

        val request = Mockito.mock(Invitation::class.java)

        Mockito.`when`(request.readAlgo).thenReturn(CliqueConfig.stringToEncodedString(userAsym.toString(), exchangeCipher.invoke(Cipher.ENCRYPT_MODE)))
        Mockito.`when`(request.readKey).thenReturn(
                CliqueConfig.stringToEncodedString(
                        friendReadKey,
                        exchangeCipher.invoke(Cipher.ENCRYPT_MODE)
                )
        )
        Mockito.`when`(request.rotateAlgo).thenReturn(CliqueConfig.stringToEncodedString(rotCipherDesc.toString(), exchangeCipher.invoke(Cipher.ENCRYPT_MODE)))
        Mockito.`when`(request.rotateKey).thenReturn(rotateKey)
        Mockito.`when`(request.url).thenReturn(CliqueConfig.stringToEncodedString(FRIEND_ONE_URL, exchangeCipher.invoke(Cipher.ENCRYPT_MODE)))

        // Read the response, putting the data into the exchange.
        exchange.readInvitation(request)

        // Assert that the data matches what you expect.
        val userDecrypter = fun(string: String) : String =
                CliqueConfig.encodedStringToString(string, userSymKeyCipherProvider.cipher(Cipher.DECRYPT_MODE, userSymKey))

        Assert.assertEquals("Friend read algorithm does not match!", userAsym.toString(), userDecrypter(exchange.friendInfo.readAlgo!!))
        Assert.assertEquals("Friend read key does not match!",
                friendReadKey,
                userDecrypter(exchange.friendInfo.readKey!!)
        )
        Assert.assertEquals("Friend rotate algorithm does not match!", rotCipherDesc.toString(), userDecrypter(exchange.friendInfo.rotateReadAlgo!!))
        Assert.assertEquals("Friend rotate key does not match!",
                CliqueConfig.encodedStringToString(rotateKey, exchangeCipher.invoke(Cipher.DECRYPT_MODE)),
                userDecrypter(exchange.friendInfo.rotateReadKey!!)
        )
        Assert.assertEquals("Friend publish url does not match!", FRIEND_ONE_URL, userDecrypter(exchange.friendInfo.url!!))

        // Second, do what we did above to create a friend request (invitation)
        var capturedRotatePublishKey: String? = null
        var capturedRotateReadKey: String? = null
        val captureRotationKeyPair = fun(keyPair: KeyPair) {
            capturedRotateReadKey = CliqueConfig.byteArrayToEncodedString(keyPair.private.encoded, exchangeCipher.invoke(Cipher.ENCRYPT_MODE))
            capturedRotatePublishKey = CliqueConfig.byteArrayToEncodedString(keyPair.public.encoded, userSymKeyCipherProvider.cipher(Cipher.ENCRYPT_MODE, userSymKey))
        }
        rotCipherDesc = AsymetricEncryptionWrapper(AsymmetricEncryptionDesc.DEFAULT, captureRotationKeyPair)

        val invitation = exchange.createInvitation(FRIEND_ONE_DISPLAY_NAME, rotCipherDesc)

        Assert.assertNotNull("Invitation should not be null!", invitation)
        Assert.assertEquals("Invitation URL does not match expected!", USER_URL, decoder(invitation!!.url))
        Assert.assertEquals("Invitation read key does not match expected!", userReadKey, decoder(invitation.readKey))
        Assert.assertEquals("Invitation read key algo does not match expected!", userAsym.toString(), decoder(invitation.readAlgo))
        Assert.assertEquals("Invitation rotate key does not match expected!", capturedRotateReadKey, invitation.rotateKey)
        Assert.assertEquals("Invitation rotate key algo does not match expected!", rotCipherDesc.toString(), decoder(invitation.rotateAlgo))

        // Load up the existing friends list to have something to compare to.
        val preFriendList = SecureDatabase.instance?.accountDao()?.findSubscriptionKeys(user!!.filter)
        Assert.assertEquals("Unexpected number of friends in friends list!",1, preFriendList?.value?.size)

        exchange.finalizeExchange()

        // Grab all the information that you'll need to verify that a friend account has been set up.
        val userConfigCipher = fun(mode: Int): Cipher {
            return configCipherPublicProvider.cipher(mode, userConfigKey!!)
        }

        val friendAccountName = CliqueConfig.stringToEncodedString(FRIEND_ONE_DISPLAY_NAME, userConfigCipher.invoke(Cipher.ENCRYPT_MODE))
        val friendAccount = SecureDatabase.instance?.accountDao()?.findAccount(friendAccountName)
        val userAccountName = CliqueConfig.stringToEncodedString(user!!.name, userConfigCipher.invoke(Cipher.ENCRYPT_MODE))
        val userAccount = SecureDatabase.instance?.accountDao()?.findAccount(userAccountName)
                ?: throw NullPointerException("Could not find user account!")

        val userConfigDecode = fun(string: String) : String {
            return CliqueConfig.encodedStringToString(string, userConfigCipher.invoke(Cipher.DECRYPT_MODE))
        }

        val userSymmetricDecode = fun(string: String) : String {
            return CliqueConfig.encodedStringToString(string, userSymKeyCipherProvider.cipher(Cipher.DECRYPT_MODE, userSymKey))
        }

        // Verify that the friend is there and has the right information.
        Assert.assertNotNull("A friend account should be present!", friendAccount)
        Assert.assertEquals("Friend's display name does not match expected!", FRIEND_ONE_DISPLAY_NAME, userSymmetricDecode(friendAccount!!.displayName))
        Assert.assertEquals("Friend's filter is not the user's filter!", userAccount.filter, friendAccount.filter)
        Assert.assertEquals("Friend's symmetric key is not the users' symmetric key!", userAccount.sym, friendAccount.sym)
        Assert.assertEquals("Friend's symmetric algorithm is not the users' symmetric algorithm!", userAccount.algo, friendAccount.algo)
        Assert.assertEquals("Friend's publish url is not the expected url!", FRIEND_ONE_URL, userSymmetricDecode(friendAccount.url))

        // Check to see that the keys and algo descriptions are there as well.
        val subscriptionRotatePublish = SecureDatabase.instance?.keyDao()?.findKey(friendAccount.key1)
        val subscriptionRead = SecureDatabase.instance?.keyDao()?.findKey(friendAccount.key2)
        val subscriptionRotateRead = SecureDatabase.instance?.keyDao()?.findKey(friendAccount.key3)

        // Key 1: Subscription rotation notification publish key (the key used to notify a subscriber that you're rotating
        Assert.assertEquals("Friend's rotate notification publish key algorithm does not match the expected algorithm!",
                rotCipherDesc.toString(),
                userSymmetricDecode(subscriptionRotatePublish!!.cipher)
        )

        Assert.assertEquals("Friend's rotate notification publish key data does not match the expected key data!",
                capturedRotatePublishKey!!,
                subscriptionRotatePublish.key
        )

        // Key 2: Subscription Read Key (the key used to read a subscriber's feed)
        Assert.assertEquals("Friend's subscription read key algorithm does not match the expected algorithm!",
                userAsym.toString(),
                userSymmetricDecode(subscriptionRead!!.cipher)
        )
        Assert.assertEquals("Friend's subscription read key data does not match the expected key data!",
                friendReadKey,
                userSymmetricDecode(subscriptionRead.key)
        )

        // Key 3: Subscription rotation read key (the key you use to decode a subscription rotation event from the subscriber).
        Assert.assertEquals("Friend's subscription rotation read key algorithm does not match the expected algorithm!",
                rotCipherDesc.toString(),
                userSymmetricDecode(subscriptionRotateRead!!.cipher)
        )
        Assert.assertEquals("Friend's subscription rotation read key data does not match the expected key data!",
                CliqueConfig.encodedStringToString(rotateKey, exchangeCipher.invoke(Cipher.DECRYPT_MODE)),
                userSymmetricDecode(subscriptionRotateRead.key)
        )

        // Finally, check to see that the list of friends matches what is expected.
        Assert.assertEquals("Unexpected number of friends in friends list!",2, preFriendList?.value?.size)
        Assert.assertNotNull("Could not find the added friend!", preFriendList?.value?.firstOrNull { friend ->
            userSymmetricDecode(friend.subscriber) ==  FRIEND_ONE_DISPLAY_NAME
        })
    }

    companion object {
        const val USER_NAME = UserFacadeTest.USER_NAME
        const val USER_URL = UserFacadeTest.USER_URL
        const val USER_PASSWORD = UserFacadeTest.USER_PASSWORD
        const val USER_DISPLAY_NAME = UserFacadeTest.USER_DISPLAY_NAME
        const val USER_READ_KEY = "UserPublicReadKey"
        const val USER_ROTATE_READ_KEY = "UserRotateReadKey"
        const val USER_ROTATE_WRITE_KEY = "UserRotateReadKey"

        const val FRIEND_ONE_NAME = "FriendOneName"
        const val FRIEND_ONE_READ_KEY = UserFacadeTest.FRIEND_ONE_READ_KEY
        const val FRIEND_ONE_DISPLAY_NAME = UserFacadeTest.FRIEND_ONE_DISPLAY_NAME
        const val FRIEND_ONE_ROTATE_KEY = "FriendOneRotateKey"
        const val FRIEND_ONE_URL = UserFacadeTest.FRIEND_ONE_URL
    }
}