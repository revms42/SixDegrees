package org.ajar.clique.encryption

import android.security.keystore.KeyProperties

interface EncryptionDescription {
    val algorithm: String
    val blockMode: String
    val padding: String

    val cipher: String
        get() = "$algorithm/$blockMode/$padding"
}

data class SymmetricEncryptionDescription(override val algorithm: String, override val blockMode: String, override val padding: String, val keySize: Int) : EncryptionDescription {

    override fun toString(): String {
        return "$algorithm/$blockMode/$padding/$keySize"
    }

    companion object {
        internal val default = SymmetricEncryptionDescription(KeyProperties.KEY_ALGORITHM_AES, KeyProperties.BLOCK_MODE_ECB, KeyProperties.ENCRYPTION_PADDING_PKCS7, 256)

        fun fromString(description: String): SymmetricEncryptionDescription {
            val split = description.split("/")
            return SymmetricEncryptionDescription(split[0], split[1], split[2], split[3].toInt())
        }
    }
}

data class AsymmetricEncryptionDescription(override val algorithm: String, override val blockMode: String, override val padding: String, val requireRandom: Boolean) : EncryptionDescription {

    override fun toString(): String {
        return "$algorithm/$blockMode/$padding/$requireRandom"
    }

    companion object {
        internal val default = AsymmetricEncryptionDescription(KeyProperties.KEY_ALGORITHM_RSA, KeyProperties.BLOCK_MODE_ECB, KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1, false)

        fun fromString(description: String): AsymmetricEncryptionDescription {
            val split = description.split("/")
            return AsymmetricEncryptionDescription(split[0], split[1], split[2], split[3].toBoolean())
        }
    }
}