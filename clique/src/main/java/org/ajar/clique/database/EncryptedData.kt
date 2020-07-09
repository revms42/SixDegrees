package org.ajar.clique.database

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Represents a key entry in a table that handles clique keys. These can be user keys or account keys.
 */
@Entity(tableName = CliqueKey.TABLE_NAME)
data class CliqueKey(
        @PrimaryKey @ColumnInfo(name = COLUMN_NAME) var name: String,
        @ColumnInfo(name = COLUMN_KEY) var key: String,
        @ColumnInfo(name = COLUMN_CIPHER) var cipher: String
) {

    companion object {
        const val TABLE_NAME = "table_1"
        /**
         * Key name
         */
        const val COLUMN_NAME = "first" // Encrypted with the active user's symmetric encryption
        /**
         * Encoded Key
         */
        const val COLUMN_KEY = "second" // Encrypted with the active user's symmetric encryption
        /**
         * Cipher name, not the full description
         */
        const val COLUMN_CIPHER = "third" // Encrypted with the active user's symmetric encryption
    }
}

/**
 * Represents a single user account, either for a subscribed user or the user of the account.
 *
 * User
 * - Write Key: Asym Public - COLUMN_KEY_1
 * - Read Key: Asym Private - COLUMN_KEY_2
 * - Garbage Key: Asym Private - COLUMN_KEY_3
 *
 * Subscription
 * - Rotate Write Key (Rotate Message to Subscriber): Asym Public - COLUMN_KEY_1
 * - Read Key: Asym Private - COLUMN_KEY_2
 * - Rotate Read Key (Rotate Message from Subscription): Asym Private - COLUMN_KEY_3
 */
@Entity(tableName = CliqueAccount.TABLE_NAME)
data class CliqueAccount(
        @PrimaryKey @ColumnInfo(name = COLUMN_USER) var user: String, // User/Subscription name, keychain encoded
        @ColumnInfo(name = COLUMN_DISPLAY_NAME) var displayName: String, // User/Subscription display Name, sym encoded
        @ColumnInfo(name = COLUMN_FILTER) var filter: String, // User Account Name, sym encoded
        @ColumnInfo(name = COLUMN_KEY_1) var key1: String, // CliqueKey name sym encoded
        @ColumnInfo(name = COLUMN_KEY_2) var key2: String, // CliqueKey name sym encoded
        @ColumnInfo(name = COLUMN_SYMMETRIC) var sym: String, // Symmetric Key, RSA encoded
        @ColumnInfo(name = COLUMN_SYMMETRIC_ALGO) var algo: String, // Symmetric Key, RSA encoded
        @ColumnInfo(name = COLUMN_URL) var url: String // URL, sym encoded
) {

    companion object {
        const val TABLE_NAME = "table_2"
        /**
         * In a User this is the user name encoded in the keychain RSA
         * In a Subscription this is the subscription name encoded in the user private RSA
         */
        const val COLUMN_USER = "first" // Encrypted using the keychain RSA

        /**
         * In a User/Subscription this is the symmetric key encoded display name for the account.
         */
        const val COLUMN_DISPLAY_NAME = "second" // Encrypted using the sym of a given User account

        /**
         * In a User this is the filter string that is used to search for friends
         * In a subscription this is the filter string associated with the user that added this account.
         */
        const val COLUMN_FILTER = "third" // Encrypted using the sym of a given User account

        /**
         * In a User this is the key to publish this user's feed.
         * In a Subscription this the shared secret key used to send rotation and personal messages.
         */
        const val COLUMN_KEY_1 = "fourth" // Encrypted using the sym of a given User account

        /**
         * In a User/Subscription this is the private key to read to this user's feed.
         * This is the first part of a friend message
         */
        const val COLUMN_KEY_2 = "fifth" // Encrypted using the sym of a given User account

        /**
         * In a User this is the symmetric key used to encode other keys.
         * In a Subscription this points to the User's symmetric key.
         */
        const val COLUMN_SYMMETRIC = "sixth" // Encrypted using the keychain RSA

        /**
         * In a User this is the symmetric key algorithm used to generate a cipher with the symmetric key
         * In a Subscription this is the User's symmetric encryption algorithm.
         */
        const val COLUMN_SYMMETRIC_ALGO = "seventh" // Encrypted using the keychain RSA

        /**
         * In a User this is the url you'll publish to
         * In a Subscriber this is the url you'll read from
         * This is the third part of a friend message.
         */
        const val COLUMN_URL = "eighth" // Encrypted using the sym of a given User account
    }
}

data class CliqueSymmetricDescription (
        @ColumnInfo(name = CliqueAccount.COLUMN_SYMMETRIC) var symKey: String, // Symmetric key RSA encoded
        @ColumnInfo(name = CliqueAccount.COLUMN_SYMMETRIC_ALGO) var symAlgo: String // Symmetric key RSA encoded
)

data class CliqueSubscription (
        @ColumnInfo(name = CliqueAccount.COLUMN_DISPLAY_NAME) var subscriber: String, // Subscriber account name sym encoded
        @ColumnInfo(name = CliqueAccount.COLUMN_URL) var subscription: String, // Subscription url, sym encoded
        @ColumnInfo(name = CliqueAccount.COLUMN_KEY_2) var feedReadKey: String, // CliqueKey name sym encoded
        @ColumnInfo(name = CliqueAccount.COLUMN_KEY_1) var rotateKey: String // CliqueKey name sym encoded
)
