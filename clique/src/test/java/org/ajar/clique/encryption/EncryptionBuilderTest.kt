package org.ajar.clique.encryption

import org.ajar.clique.CliqueTestHelper.createTestAESParameters
import org.ajar.clique.CliqueTestHelper.createTestRSAParameters
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import javax.crypto.Cipher

class EncryptionBuilderTest {

    @Test
    fun createKeyPair() {
        val encryption = EncryptionBuilder.asymetric().build() as AsymmetricEncryptionDesc
        encryption.createKeyGenSpec = createTestRSAParameters(encryption)
        val keyPair = encryption.generateKeyPair()
        assertNotNull(keyPair)
    }

    @Test
    fun roundTripAsymmetric() {
        val encryption = EncryptionBuilder.asymetric().build() as AsymmetricEncryptionDesc
        encryption.createKeyGenSpec = createTestRSAParameters(encryption)
        val keyPair = encryption.generateKeyPair()
        val providerPrivate = CipherProvider.Private(encryption)
        var cipher = providerPrivate.cipher(Cipher.ENCRYPT_MODE, keyPair.public)

        var byteArray = "The String to be encoded".toByteArray(Charsets.UTF_8)

        var encrypted = cipher.doFinal(byteArray)

        cipher = providerPrivate.cipher(Cipher.DECRYPT_MODE, keyPair.private)

        var decrypted = cipher.doFinal(encrypted)

        assertArrayEquals(byteArray, decrypted)

        // In theory this shouldn't make a difference for this test, but just for completeness
        val providerPublic = CipherProvider.Public(encryption)
        cipher = providerPublic.cipher(Cipher.ENCRYPT_MODE, keyPair.public)

        byteArray = "The String to be encoded".toByteArray(Charsets.UTF_8)

        encrypted = cipher.doFinal(byteArray)

        cipher = providerPublic.cipher(Cipher.DECRYPT_MODE, keyPair.private)

        decrypted = cipher.doFinal(encrypted)

        assertArrayEquals(byteArray, decrypted)
    }

    @Test
    fun createSecretKey() {
        val encryption = EncryptionBuilder.symmetric().build() as SymmetricEncryptionDesc
        encryption.createKeyGenSpec = createTestAESParameters()
        val secretKey = encryption.generateSecretKey()
        assertNotNull(secretKey)
    }

    @Test
    fun roundTripSymmetric() {
        val encryption = EncryptionBuilder.symmetric().build() as SymmetricEncryptionDesc
        encryption.createKeyGenSpec = createTestAESParameters()
        val secretKey = encryption.generateSecretKey()
        val provider = CipherProvider.Symmetric(encryption)

        var cipher = provider.cipher(Cipher.ENCRYPT_MODE, secretKey)

        val byteArray = "The String to be encoded".toByteArray(Charsets.UTF_8)

        val encrypted = cipher.doFinal(byteArray)

        cipher = provider.cipher(Cipher.DECRYPT_MODE, secretKey)

        val decrypted = cipher.doFinal(encrypted)

        assertArrayEquals(byteArray, decrypted)
    }

    @Test
    fun privateKeyFromBytes() {
        val encryption = EncryptionBuilder.asymetric().build() as AsymmetricEncryptionDesc
        encryption.createKeyGenSpec = createTestRSAParameters(encryption)
        val keyPair = encryption.generateKeyPair()

        val privateBytes = keyPair.private.encoded

        val providerPrivate = CipherProvider.Private(encryption)
        var cipher = providerPrivate.cipher(Cipher.ENCRYPT_MODE, keyPair.public)

        val byteArray = "The String to be encoded".toByteArray(Charsets.UTF_8)

        val encrypted = cipher.doFinal(byteArray)

        cipher = providerPrivate.cipher(Cipher.DECRYPT_MODE, privateBytes)

        val decrypted = cipher.doFinal(encrypted)

        assertArrayEquals(byteArray, decrypted)
    }

    @Test
    fun publicKeyFromBytes() {
        val encryption = EncryptionBuilder.asymetric().build() as AsymmetricEncryptionDesc
        encryption.createKeyGenSpec = createTestRSAParameters(encryption)
        val keyPair = encryption.generateKeyPair()

        val publicBytes = keyPair.public.encoded

        val providerPrivate = CipherProvider.Public(encryption)
        var cipher = providerPrivate.cipher(Cipher.ENCRYPT_MODE, publicBytes)

        val byteArray = "The String to be encoded".toByteArray(Charsets.UTF_8)

        val encrypted = cipher.doFinal(byteArray)

        cipher = providerPrivate.cipher(Cipher.DECRYPT_MODE, keyPair.private)

        val decrypted = cipher.doFinal(encrypted)

        assertArrayEquals(byteArray, decrypted)
    }

    @Test
    fun secretKeyFromBytes() {
        val encryption = EncryptionBuilder.symmetric().build() as SymmetricEncryptionDesc
        encryption.createKeyGenSpec = createTestAESParameters()
        val secretKey = encryption.generateSecretKey()

        val keyBytes = secretKey.encoded

        val provider = CipherProvider.Symmetric(encryption)

        var cipher = provider.cipher(Cipher.ENCRYPT_MODE, keyBytes)

        val byteArray = "The String to be encoded".toByteArray(Charsets.UTF_8)

        val encrypted = cipher.doFinal(byteArray)

        cipher = provider.cipher(Cipher.DECRYPT_MODE, secretKey)

        val decrypted = cipher.doFinal(encrypted)

        assertArrayEquals(byteArray, decrypted)
    }
}