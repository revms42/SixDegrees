package org.ajar.clique

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import org.ajar.clique.database.SecureDAOTestHelper
import org.ajar.clique.facade.User
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import org.mockito.Mock
import org.mockito.Mockito
import java.security.*
import javax.crypto.SecretKey

class UserFacadeTest {

    private lateinit var keyStoreSpi: KeyStoreSpi
    private lateinit var keyStore: KeyStore

    val privateKey = Mockito.mock(PrivateKey::class.java)
    val publicKey = Mockito.mock(PublicKey::class.java)
    val secretKey = Mockito.mock(SecretKey::class.java)

    val mockContext = Mockito.mock(Context::class.java)
    val mockUserSym = CliqueConfigTestHelper.createSymmetricEncryptionDescription(CliqueConfigTestHelper.ENCRYPTION_CAPITAL)
    val mockUserAsym = CliqueConfigTestHelper.createAsymmetricEncryptionDescription(CliqueConfigTestHelper.ENCRYPTION_BACKWARDS)
    var user: User? = null

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
    }

    @Test
    fun testCreateUser() {
        val keySpec = Mockito.mock(KeyGenParameterSpec::class.java)
        val mockPair = KeyPair(publicKey, privateKey)
        CliqueConfigTestHelper.createKeyPairSetup(keySpec, mockPair)

        User.createUser(mockContext, USER_NAME, USER_DISPLAY_NAME, USER_URL, mockUserSym, mockUserAsym)
        user = User.loadUser(mockContext, USER_NAME)

        Assert.assertEquals("User name does not match expected!", USER_NAME, user!!.name)
        Assert.assertEquals("User url does not match expected!", USER_URL, user!!.url)

        Assert.assertNull("User should not have friends on initial creation!", user!!.friends.value)
        Assert.assertNull("User should not have rotations on initial creation!", user!!.rotation.value)
    }

    companion object {
        const val USER_NAME = "MockUser"
        const val USER_DISPLAY_NAME = "Mock User"
        const val USER_URL = "https://mockstorage.net"
    }
}