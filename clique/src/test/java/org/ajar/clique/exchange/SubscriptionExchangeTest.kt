package org.ajar.clique.exchange

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import org.ajar.clique.*
import org.ajar.clique.database.SecureDAOTestHelper
import org.ajar.clique.database.SecureDatabase
import org.ajar.clique.encryption.AsymmetricEncryptionDescription
import org.ajar.clique.facade.User
import org.ajar.clique.transaction.Invitation
import org.ajar.clique.transaction.SubscriptionExchange
import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito
import java.lang.NullPointerException
import java.security.*
import java.util.*
import javax.crypto.Cipher

class SubscriptionExchangeTest {
    private lateinit var keyStoreSpi: KeyStoreSpi
    private lateinit var keyStore: KeyStore

    private val mockContext = Mockito.mock(Context::class.java)
    private val mockSystemAsym = CliqueConfigTestHelper.createAsymmetricEncryptionDescription(CliqueConfigTestHelper.ENCRYPTION_MINUS)
    private val mockUserSym = CliqueConfigTestHelper.createSymmetricEncryptionDescription(CliqueConfigTestHelper.ENCRYPTION_BACKWARDS)
    private val mockUserAsym = CliqueConfigTestHelper.createAsymmetricEncryptionDescription(CliqueConfigTestHelper.ENCRYPTION_PLUS)
    private var user: User? = null

    private lateinit var exchange: SubscriptionExchange
    private lateinit var exchangeCipher: (mode: Int) -> Cipher

    private lateinit var decoder: (String) -> String
    private lateinit var encoder: (String) -> String

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
        CliqueConfig.assymetricEncryption = mockSystemAsym

        val privateKey = Mockito.mock(PrivateKey::class.java)
        val publicKey = Mockito.mock(PublicKey::class.java)

        Mockito.`when`(publicKey.encoded).thenReturn(USER_READ_KEY.toByteArray(Charsets.UTF_8), USER_ROTATE_READ_KEY.toByteArray(Charsets.UTF_8))
        Mockito.`when`(privateKey.encoded).thenReturn(USER_WRITE_KEY.toByteArray(Charsets.UTF_8), USER_ROTATE_WRITE_KEY.toByteArray(Charsets.UTF_8))

        val keySpec = Mockito.mock(KeyGenParameterSpec::class.java)
        val mockPair = KeyPair(publicKey, privateKey)
        CliqueConfigTestHelper.createKeyPairSetup(keySpec, mockPair)

        User.createUser(mockContext, USER_NAME, USER_DISPLAY_NAME, USER_URL, mockUserSym, mockUserAsym)
        user = User.loadUser(mockContext, USER_NAME)

        val exchangeEncryption = CliqueConfigTestHelper.createSymmetricEncryptionDescription(CliqueConfigTestHelper.ENCRYPTION_STAR)
        val key = CliqueConfig.createSecretKey(exchangeEncryption, TestCipherProviderSpi.provider)

        exchangeCipher = fun (mode: Int) : Cipher {
            val cipher = Cipher.getInstance(exchangeEncryption.algorithm, TestCipherProviderSpi.provider)
            cipher.init(mode, key)
            return cipher
        }

        exchange = SubscriptionExchange.createExchange(user!!, exchangeCipher)

        val base64Decoder = Base64.getDecoder()
        val base64Encoder = Base64.getEncoder()

        decoder = fun(string: String) : String {
            return String(base64Decoder.decode(string), Charsets.UTF_8)
        }

        encoder = fun(string: String) : String {
            return base64Encoder.encodeToString(string.toByteArray(Charsets.UTF_8))
        }
    }

    @After
    fun tearDown() {
        SecureDAOTestHelper.clear()
    }

    @Test
    fun testExchangeSubscriptionRequest() {
        val rotCipherDesc = AsymmetricEncryptionDescription(CliqueConfigTestHelper.ENCRYPTION_MINUS, CliqueConfigTestHelper.BLOCKMODE_NONE, CliqueConfigTestHelper.PADDING_NONE, false)
        val invitation = exchange.createInvitation(FRIEND_ONE_DISPLAY_NAME, rotCipherDesc)

        Assert.assertNotNull("Invitation should not be null!", invitation)
        Assert.assertEquals("Invitation URL does not match expected!", USER_URL, decoder(invitation!!.url).substring(2))
        Assert.assertEquals("Invitation read key does not match expected!", USER_READ_KEY, decoder(invitation.readKey).substring(2))
        Assert.assertEquals("Invitation read key algo does not match expected!", mockUserAsym.toString(), decoder(invitation.readAlgo).substring(2))
        Assert.assertEquals("Invitation rotate key does not match expected!", USER_ROTATE_WRITE_KEY, decoder(invitation.rotateKey).substring(2))
        Assert.assertEquals("Invitation rotate key algo does not match expected!", rotCipherDesc.toString(), decoder(invitation.rotateAlgo).substring(2))
    }

    @Test
    fun testExchangeSubscriptionRespond() {
        val rotCipherDesc = AsymmetricEncryptionDescription(CliqueConfigTestHelper.ENCRYPTION_MINUS, CliqueConfigTestHelper.BLOCKMODE_NONE, CliqueConfigTestHelper.PADDING_NONE, false)

        val invitation = Mockito.mock(Invitation::class.java)

        Mockito.`when`(invitation.readAlgo).thenReturn(CliqueConfig.stringToEncodedString(mockUserAsym.toString(), exchangeCipher.invoke(Cipher.ENCRYPT_MODE)))
        Mockito.`when`(invitation.readKey).thenReturn(CliqueConfig.stringToEncodedString(FRIEND_ONE_READ_KEY, exchangeCipher.invoke(Cipher.ENCRYPT_MODE)))
        Mockito.`when`(invitation.rotateAlgo).thenReturn(CliqueConfig.stringToEncodedString(rotCipherDesc.toString(), exchangeCipher.invoke(Cipher.ENCRYPT_MODE)))
        Mockito.`when`(invitation.rotateKey).thenReturn(CliqueConfig.stringToEncodedString(FRIEND_ONE_ROTATE_KEY, exchangeCipher.invoke(Cipher.ENCRYPT_MODE)))
        Mockito.`when`(invitation.url).thenReturn(CliqueConfig.stringToEncodedString(FRIEND_ONE_URL, exchangeCipher.invoke(Cipher.ENCRYPT_MODE)))

        exchange.readInvitation(invitation)

        Assert.assertEquals("Friend read algorithm does not match!", mockUserAsym.toString(), decoder(exchange.friendInfo.readAlgo!!).reversed())
        Assert.assertEquals("Friend read key does not match!", FRIEND_ONE_READ_KEY, decoder(exchange.friendInfo.readKey!!).reversed())
        Assert.assertEquals("Friend rotate algorithm does not match!", rotCipherDesc.toString(), decoder(exchange.friendInfo.privateOneAlgo!!).reversed())
        Assert.assertEquals("Friend rotate key does not match!", FRIEND_ONE_ROTATE_KEY, decoder(exchange.friendInfo.privateOne!!).reversed())
        Assert.assertEquals("Friend publish url does not match!", FRIEND_ONE_URL, decoder(exchange.friendInfo.url!!).reversed())
    }

    private fun makeSystemCipher(): (Int) -> Cipher {
        return fun (mode: Int) : Cipher {
            val mockKey = Mockito.mock(Key::class.java)
            val cipher = Cipher.getInstance(mockSystemAsym.algorithm, TestCipherProviderSpi.provider)
            cipher.init(mode, mockKey)
            return cipher
        }
    }

    private fun makeUserSymDecoder(): (String) -> String {
        return fun (string: String) : String {
            val mockKey = Mockito.mock(Key::class.java)
            val cipher = Cipher.getInstance(mockUserSym.algorithm, TestCipherProviderSpi.provider)
            cipher.init(Cipher.DECRYPT_MODE, mockKey)

            return CliqueConfig.encodedStringToString(string, cipher)
        }
    }

    /**
     * You're creating a request, then creating the friend on the response.
     */
    @Test
    fun testCreateFriendFromResponse() {
        val rotCipherDesc = AsymmetricEncryptionDescription(CliqueConfigTestHelper.ENCRYPTION_MINUS, CliqueConfigTestHelper.BLOCKMODE_NONE, CliqueConfigTestHelper.PADDING_NONE, false)
        val invitation = exchange.createInvitation(FRIEND_ONE_DISPLAY_NAME, rotCipherDesc)

        Assert.assertNotNull("Invitation should not be null!", invitation)
        Assert.assertEquals("Invitation URL does not match expected!", USER_URL, decoder(invitation!!.url).substring(2))
        Assert.assertEquals("Invitation read key does not match expected!", USER_READ_KEY, decoder(invitation.readKey).substring(2))
        Assert.assertEquals("Invitation read key algo does not match expected!", mockUserAsym.toString(), decoder(invitation.readAlgo).substring(2))
        Assert.assertEquals("Invitation rotate key does not match expected!", USER_ROTATE_WRITE_KEY, decoder(invitation.rotateKey).substring(2))
        Assert.assertEquals("Invitation rotate key algo does not match expected!", rotCipherDesc.toString(), decoder(invitation.rotateAlgo).substring(2))

        val response = Mockito.mock(Invitation::class.java)

        // Consider using a cipher that isn't the same as userAsym
        Mockito.`when`(response.readAlgo).thenReturn(CliqueConfig.stringToEncodedString(mockUserAsym.toString(), exchangeCipher.invoke(Cipher.ENCRYPT_MODE)))
        Mockito.`when`(response.readKey).thenReturn(CliqueConfig.stringToEncodedString(FRIEND_ONE_READ_KEY, exchangeCipher.invoke(Cipher.ENCRYPT_MODE)))
        Mockito.`when`(response.rotateAlgo).thenReturn(CliqueConfig.stringToEncodedString(rotCipherDesc.toString(), exchangeCipher.invoke(Cipher.ENCRYPT_MODE)))
        Mockito.`when`(response.rotateKey).thenReturn(CliqueConfig.stringToEncodedString(FRIEND_ONE_ROTATE_KEY, exchangeCipher.invoke(Cipher.ENCRYPT_MODE)))
        Mockito.`when`(response.url).thenReturn(CliqueConfig.stringToEncodedString(FRIEND_ONE_URL, exchangeCipher.invoke(Cipher.ENCRYPT_MODE)))

        exchange.readInvitation(response)

        Assert.assertEquals("Friend read algorithm does not match!", mockUserAsym.toString(), decoder(exchange.friendInfo.readAlgo!!).reversed())
        Assert.assertEquals("Friend read key does not match!", FRIEND_ONE_READ_KEY, decoder(exchange.friendInfo.readKey!!).reversed())
        Assert.assertEquals("Friend rotate algorithm does not match!", rotCipherDesc.toString(), decoder(exchange.friendInfo.privateOneAlgo!!).reversed())
        Assert.assertEquals("Friend rotate key does not match!", FRIEND_ONE_ROTATE_KEY, decoder(exchange.friendInfo.privateOne!!).reversed())
        Assert.assertEquals("Friend publish url does not match!", FRIEND_ONE_URL, decoder(exchange.friendInfo.url!!).reversed())

        val preFriendList = SecureDatabase.instance?.accountDao()?.findSubscriptionKeys(user!!.filter)
        Assert.assertEquals("Unexpected number of friends in friends list!",1, preFriendList?.value?.size)
        exchange.finalizeExchange()

        val systemEncoder = makeSystemCipher()

        val friendAccountName = CliqueConfig.stringToEncodedString(FRIEND_ONE_DISPLAY_NAME, systemEncoder.invoke(Cipher.ENCRYPT_MODE))
        val friendAccount = SecureDatabase.instance?.accountDao()?.findAccount(friendAccountName)
        val userAccountName = CliqueConfig.stringToEncodedString(user!!.name, systemEncoder.invoke(Cipher.ENCRYPT_MODE))
        val userAccount = SecureDatabase.instance?.accountDao()?.findAccount(userAccountName)

        val symDecoder = makeUserSymDecoder()

        if(userAccount == null) {
            throw NullPointerException("Could not find user account!")
        }

        Assert.assertNotNull("A friend account should be present!", friendAccount)
        Assert.assertEquals("Friend's display name does not match expected!", FRIEND_ONE_DISPLAY_NAME, symDecoder(friendAccount!!.displayName))
        Assert.assertEquals("Friend's filter is not the user's filter!", userAccount.filter, friendAccount.filter)
        Assert.assertEquals("Friend's symmetric key is not the users' symmetric key!", userAccount.sym, friendAccount.sym)
        Assert.assertEquals("Friend's symmetric algorithm is not the users' symmetric algorithm!", userAccount.algo, friendAccount.algo)
        Assert.assertEquals("Friend's publish url is not the expected url!", FRIEND_ONE_URL, symDecoder(friendAccount.url))

        val friendPublicOne = SecureDatabase.instance?.keyDao()?.findKey(friendAccount.publicOne)
        val friendPrivateOne = SecureDatabase.instance?.keyDao()?.findKey(friendAccount.privateOne)
        val friendPublicTwo = SecureDatabase.instance?.keyDao()?.findKey(friendAccount.publicTwo)

        Assert.assertEquals("Friend's publicOne key algorithm does not match the expected algorithm!", mockUserAsym.toString(), symDecoder(friendPublicOne!!.cipher))
        Assert.assertEquals("Friend's publicOne key data does not match the expected key data!", FRIEND_ONE_READ_KEY, symDecoder(friendPublicOne.key))

        Assert.assertEquals("Friend's privateOne key algorithm does not match the expected algorithm!", rotCipherDesc.toString(), symDecoder(friendPrivateOne!!.cipher))
        Assert.assertEquals("Friend's privateOne key data does not match the expected key data!", FRIEND_ONE_ROTATE_KEY, symDecoder(friendPrivateOne.key))

        Assert.assertEquals("Friend's publicTwo key algorithm does not match the expected algorithm!", rotCipherDesc.toString(), symDecoder(friendPublicTwo!!.cipher))
        Assert.assertEquals("Friend's publicTwo key data does not match the expected key data!", USER_ROTATE_READ_KEY, symDecoder(friendPublicTwo.key))

        Assert.assertEquals("Unexpected number of friends in friends list!",2, preFriendList?.value?.size)
        Assert.assertNotNull("Could not find the added friend!", preFriendList?.value?.firstOrNull { friend -> symDecoder(friend.subscriber) ==  FRIEND_ONE_DISPLAY_NAME })
    }

    /**
     * You're responding to a request, then creating a friend after you send a response.
     */
    @Test
    fun testCreateFriendFromRequest() {
        val rotCipherDesc = AsymmetricEncryptionDescription(CliqueConfigTestHelper.ENCRYPTION_MINUS, CliqueConfigTestHelper.BLOCKMODE_NONE, CliqueConfigTestHelper.PADDING_NONE, false)

        val request = Mockito.mock(Invitation::class.java)

        Mockito.`when`(request.readAlgo).thenReturn(CliqueConfig.stringToEncodedString(mockUserAsym.toString(), exchangeCipher.invoke(Cipher.ENCRYPT_MODE)))
        Mockito.`when`(request.readKey).thenReturn(CliqueConfig.stringToEncodedString(FRIEND_ONE_READ_KEY, exchangeCipher.invoke(Cipher.ENCRYPT_MODE)))
        Mockito.`when`(request.rotateAlgo).thenReturn(CliqueConfig.stringToEncodedString(rotCipherDesc.toString(), exchangeCipher.invoke(Cipher.ENCRYPT_MODE)))
        Mockito.`when`(request.rotateKey).thenReturn(CliqueConfig.stringToEncodedString(FRIEND_ONE_ROTATE_KEY, exchangeCipher.invoke(Cipher.ENCRYPT_MODE)))
        Mockito.`when`(request.url).thenReturn(CliqueConfig.stringToEncodedString(FRIEND_ONE_URL, exchangeCipher.invoke(Cipher.ENCRYPT_MODE)))

        exchange.readInvitation(request)

        Assert.assertEquals("Friend read algorithm does not match!", mockUserAsym.toString(), decoder(exchange.friendInfo.readAlgo!!).reversed())
        Assert.assertEquals("Friend read key does not match!", FRIEND_ONE_READ_KEY, decoder(exchange.friendInfo.readKey!!).reversed())
        Assert.assertEquals("Friend rotate algorithm does not match!", rotCipherDesc.toString(), decoder(exchange.friendInfo.privateOneAlgo!!).reversed())
        Assert.assertEquals("Friend rotate key does not match!", FRIEND_ONE_ROTATE_KEY, decoder(exchange.friendInfo.privateOne!!).reversed())
        Assert.assertEquals("Friend publish url does not match!", FRIEND_ONE_URL, decoder(exchange.friendInfo.url!!).reversed())

        val invitation = exchange.createInvitation(FRIEND_ONE_DISPLAY_NAME, rotCipherDesc)

        Assert.assertNotNull("Invitation should not be null!", invitation)
        Assert.assertEquals("Invitation URL does not match expected!", USER_URL, decoder(invitation!!.url).substring(2))
        Assert.assertEquals("Invitation read key does not match expected!", USER_READ_KEY, decoder(invitation.readKey).substring(2))
        Assert.assertEquals("Invitation read key algo does not match expected!", mockUserAsym.toString(), decoder(invitation.readAlgo).substring(2))
        Assert.assertEquals("Invitation rotate key does not match expected!", USER_ROTATE_WRITE_KEY, decoder(invitation.rotateKey).substring(2))
        Assert.assertEquals("Invitation rotate key algo does not match expected!", rotCipherDesc.toString(), decoder(invitation.rotateAlgo).substring(2))

        val preFriendList = SecureDatabase.instance?.accountDao()?.findSubscriptionKeys(user!!.filter)
        Assert.assertEquals("Unexpected number of friends in friends list!",1, preFriendList?.value?.size)
        exchange.finalizeExchange()

        val systemEncoder = makeSystemCipher()

        val friendAccountName = CliqueConfig.stringToEncodedString(FRIEND_ONE_DISPLAY_NAME, systemEncoder.invoke(Cipher.ENCRYPT_MODE))
        val friendAccount = SecureDatabase.instance?.accountDao()?.findAccount(friendAccountName)
        val userAccountName = CliqueConfig.stringToEncodedString(user!!.name, systemEncoder.invoke(Cipher.ENCRYPT_MODE))
        val userAccount = SecureDatabase.instance?.accountDao()?.findAccount(userAccountName)

        val symDecoder = makeUserSymDecoder()

        if(userAccount == null) {
            throw NullPointerException("Could not find user account!")
        }

        Assert.assertNotNull("A friend account should be present!", friendAccount)
        Assert.assertEquals("Friend's display name does not match expected!", FRIEND_ONE_DISPLAY_NAME, symDecoder(friendAccount!!.displayName))
        Assert.assertEquals("Friend's filter is not the user's filter!", userAccount.filter, friendAccount.filter)
        Assert.assertEquals("Friend's symmetric key is not the users' symmetric key!", userAccount.sym, friendAccount.sym)
        Assert.assertEquals("Friend's symmetric algorithm is not the users' symmetric algorithm!", userAccount.algo, friendAccount.algo)
        Assert.assertEquals("Friend's publish url is not the expected url!", FRIEND_ONE_URL, symDecoder(friendAccount.url))

        val friendPublicOne = SecureDatabase.instance?.keyDao()?.findKey(friendAccount.publicOne)
        val friendPrivateOne = SecureDatabase.instance?.keyDao()?.findKey(friendAccount.privateOne)
        val friendPublicTwo = SecureDatabase.instance?.keyDao()?.findKey(friendAccount.publicTwo)

        Assert.assertEquals("Friend's publicOne key algorithm does not match the expected algorithm!", mockUserAsym.toString(), symDecoder(friendPublicOne!!.cipher))
        Assert.assertEquals("Friend's publicOne key data does not match the expected key data!", FRIEND_ONE_READ_KEY, symDecoder(friendPublicOne.key))

        Assert.assertEquals("Friend's privateOne key algorithm does not match the expected algorithm!", rotCipherDesc.toString(), symDecoder(friendPrivateOne!!.cipher))
        Assert.assertEquals("Friend's privateOne key data does not match the expected key data!", FRIEND_ONE_ROTATE_KEY, symDecoder(friendPrivateOne.key))

        Assert.assertEquals("Friend's publicTwo key algorithm does not match the expected algorithm!", rotCipherDesc.toString(), symDecoder(friendPublicTwo!!.cipher))
        Assert.assertEquals("Friend's publicTwo key data does not match the expected key data!", USER_ROTATE_READ_KEY, symDecoder(friendPublicTwo.key))

        Assert.assertEquals("Unexpected number of friends in friends list!",2, preFriendList?.value?.size)
        Assert.assertNotNull("Could not find the added friend!", preFriendList?.value?.firstOrNull { friend -> symDecoder(friend.subscriber) ==  FRIEND_ONE_DISPLAY_NAME })
    }

    companion object {
        const val USER_NAME = UserFacadeTest.USER_NAME
        const val USER_DISPLAY_NAME = UserFacadeTest.USER_DISPLAY_NAME
        const val USER_URL = UserFacadeTest.USER_URL
        const val USER_READ_KEY = "UserPublicReadKey"
        const val USER_WRITE_KEY = "UserPrivateWriteKey"
        const val USER_ROTATE_READ_KEY = "UserRotateReadKey"
        const val USER_ROTATE_WRITE_KEY = "UserRotateReadKey"

        const val FRIEND_ONE_READ_KEY = UserFacadeTest.FRIEND_ONE_READ_KEY
        const val FRIEND_ONE_DISPLAY_NAME = UserFacadeTest.FRIEND_ONE_DISPLAY_NAME
        const val FRIEND_ONE_ROTATE_KEY = "FriendOneRotateKey"
        const val FRIEND_ONE_URL = UserFacadeTest.FRIEND_ONE_URL
    }
}