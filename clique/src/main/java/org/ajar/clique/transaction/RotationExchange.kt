package org.ajar.clique.transaction

import org.ajar.clique.CliqueConfig
import org.ajar.clique.database.SecureDatabase
import org.ajar.clique.encryption.AsymmetricEncryption
import org.ajar.clique.facade.Friend
import org.ajar.clique.facade.User
import javax.crypto.Cipher

/**
 * The idea behind a RotationExchange is to remove a selected group of friends (and necessarily change
 * the asymmetric encryption associated with publication), to change the
 * publication url, or both, and then publish that information as a series of rotation messages
 * to your feed.
 */
class RotationExchange private constructor(private val user: User) {

    private val _removedFriends: MutableList<Friend> = ArrayList()
    val removedFriends: List<Friend>
        get() = _removedFriends
    private var _asymDesc: AsymmetricEncryption? = null
    val asymDesc: AsymmetricEncryption?
        get() = _asymDesc
    private var _url: String? = null
    val url: String?
        get() = _url

    fun removeFriend(friend: Friend) {
        _removedFriends.add(friend)
    }

    fun changeEncryption(desc: AsymmetricEncryption) {
        _asymDesc = desc
    }

    fun changeUrl(url: String) {
        _url = url
    }

    /**
     * Here we should first remove the associated friends and their keys.
     *
     * Then, for the remaining friends, we should iterate through and for each friend we
     * create a rotation message with the url, private key for the new encryption, and encrypt
     * it all with each friend's rotation encryption public key.
     *
     * Then we should update our own key for publication (our saved write - public - key).
     *
     * With all that completed we should output a list of rotation encryption messages ready to
     * publish to the old URL (which we should publish).
     *
     * @return a bunch of rotation encryption messages in an object that you should call the cleanUp method on.
     */

    fun finalizeExchange(): RotationPublicationBatch? {
        val toRemove = removedFriends.mapNotNull { exFriend ->
            val name = CliqueConfig.stringToEncodedString(exFriend.displayName, user.symCipher.invoke(Cipher.ENCRYPT_MODE)!!)
            SecureDatabase.instance?.accountDao()?.findAccountByDisplayName(name)
        }
        return SecureDatabase.instance?.accountDao()?.let { accountDao ->
            accountDao.deleteAccounts(*toRemove.toTypedArray())

            val encryptedName = CliqueConfig.stringToEncodedString(user.name, user.symCipher.invoke(Cipher.ENCRYPT_MODE)!!)
            val userAccount = SecureDatabase.instance!!.accountDao().findAccount(encryptedName)

            var userFeedRead = userAccount!!.key2
            var userFeedWrite = userAccount.key1
            var userUrl = userAccount.url

            if(asymDesc != null) {
                val encode = fun(): Cipher {
                    return user.symCipher.invoke(Cipher.ENCRYPT_MODE)!!
                }
                val keyPair = User.generateUserFeedKeys(user.name, asymDesc!!, encode)

                SecureDatabase.instance!!.keyDao().addKey(keyPair.feedPublicKey)
                SecureDatabase.instance!!.keyDao().addKey(keyPair.feedPrivateKey)

                userFeedRead = keyPair.feedPrivate
                userFeedWrite = keyPair.feedPublic
            }

            if(url != null) {
                userUrl = CliqueConfig.stringToEncodedString(url!!, user.symCipher.invoke(Cipher.ENCRYPT_MODE)!!)
            }
            TODO("NYI!")
        }
    }

    companion object {
        fun startRotation(user: User) : RotationExchange {
            return RotationExchange(user)
        }
    }
}

data class RotationPublicationBatch(val oldUrl: String, val oldPublishKey: String, val oldReadKey: String, val messages: List<Friend>?) {

    fun cleanUp() {
        deleteKey(oldPublishKey)
        deleteKey(oldReadKey)
    }

    private fun deleteKey(name: String) {
        SecureDatabase.instance!!.keyDao().findKey(name)?.also { SecureDatabase.instance!!.keyDao().deleteKey(it) }
    }
}