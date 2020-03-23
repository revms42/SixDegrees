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
        const val COLUMN_NAME = "first" // Encrypted with the active user's symmetric encryption
        const val COLUMN_KEY = "second" // Encrypted with the active user's symmetric encryption
        const val COLUMN_CIPHER = "third" // Encrypted with the active user's symmetric encryption
    }
}

/**
 * Represents a single user account, either for a subscribed user or the user of the account.
 */
@Entity(tableName = CliqueAccount.TABLE_NAME)
data class CliqueAccount(
        @PrimaryKey @ColumnInfo(name = COLUMN_USER) var user: String, // User/Subscription name, keychain encoded
        @ColumnInfo(name = COLUMN_DISPLAY_NAME) var displayName: String, // User/Subscription display Name, sym encoded
        @ColumnInfo(name = COLUMN_FILTER) var filter: String, // User Account Name, sym encoded
        @ColumnInfo(name = COLUMN_PUBLIC_1) var publicOne: String, // CliqueKey name sym encoded
        @ColumnInfo(name = COLUMN_PRIVATE_1) var privateOne: String, // CliqueKey name sym encoded
        @ColumnInfo(name = COLUMN_PUBLIC_2) var publicTwo: String, // CliqueKey name sym encoded
        @ColumnInfo(name = COLUMN_SYMMETRIC) var sym: String, // Symmetric Key, RSA encoded
        @ColumnInfo(name = COLUMN_SYMMETRIC_ALGO) var algo: String, // Symmetric Key, RSA encoded
        @ColumnInfo(name = COLUMN_URL) var url: String // URL, sym encoded
) {

    companion object {
        const val TABLE_NAME = "table_2"
        const val COLUMN_USER = "first" // Encrypted using the keychain RSA
        const val COLUMN_DISPLAY_NAME = "second" // Encrypted using the sym of a given User account
        const val COLUMN_FILTER = "third" // Encrypted using the sym of a given User account

        /**
         * In a User/Subscription this is the key to read this user's feed.
         * This is the first part of a friend message that gets sent.
         */
        const val COLUMN_PUBLIC_1 = "fourth" // Encrypted using the sym of a given User account

        /**
         * In a User this is the key to write to this user's feed.
         * In a Subscription this is the key to send a rotation message to the specified subscriber (the second part of a friend message received)
         */
        const val COLUMN_PRIVATE_1 = "fifth" // Encrypted using the sym of a given User account

        /**
         * In a User this is a made-up garbage key.
         * In a Subscription this is the key that decodes a rotation message from a given subscriber (the second part of a friend message that you keep)
         */
        const val COLUMN_PUBLIC_2 = "sixth" // Encrypted using the sym of a given User account

        /**
         * In a User this is the symmetric key used to encode other keys.
         * In a Subscription this is a made-up garbage key.
         */
        const val COLUMN_SYMMETRIC = "seventh" // Encrypted using the keychain RSA

        /**
         * In a User this is the symmetric key algorithm used to generate a cipher with the symmetric key
         * In a Subscription this is a made-up garbage value.
         */
        const val COLUMN_SYMMETRIC_ALGO = "eighth" // Encrypted using the keychain RSA

        /**
         * In a User this is the url you'll publish to
         * In a Subscriber this is the url you'll read from
         * This is the third part of a friend message.
         */
        const val COLUMN_URL = "ninth" // Encrypted using the sym of a given User account
    }
}

data class CliqueSymmetricDescription (
        @ColumnInfo(name = CliqueAccount.COLUMN_SYMMETRIC) var symKey: String, // Symmetric key RSA encoded
        @ColumnInfo(name = CliqueAccount.COLUMN_SYMMETRIC_ALGO) var symAlgo: String // Symmetric key RSA encoded
)

data class CliqueSubscription (
        @ColumnInfo(name = CliqueAccount.COLUMN_DISPLAY_NAME) var subscriber: String, // Subscriber account name sym encoded
        @ColumnInfo(name = CliqueAccount.COLUMN_URL) var subscription: String, // Subscription url, sym encoded
        @ColumnInfo(name = CliqueAccount.COLUMN_PUBLIC_1) var feedReadKey: String // CliqueKey name sym encoded
)

data class CliqueRotateDescription (
        @ColumnInfo(name = CliqueAccount.COLUMN_DISPLAY_NAME) var subscriber: String, // Subscriber account name sym encoded
        @ColumnInfo(name = CliqueAccount.COLUMN_PRIVATE_1) var rotateKey: String // CliqueKey name sym encoded
)
