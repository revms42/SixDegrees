package org.ajar.clique.transaction

import org.ajar.clique.CliqueConfig
import org.ajar.clique.database.CliqueSubscription
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
     * Then we should update our own key for publication (our saved write - public - key).
     *
     * With all that completed we should output a bundle of data with the old publishing info.
     *
     * @return a the old publishing info.
     */

    fun finalizeExchange(): RotationPublishData? {
        val toRemove = removedFriends.mapNotNull { exFriend ->
            Friend.toAccount(exFriend, user.symCipher)
        }
        return SecureDatabase.instance?.accountDao()?.let { accountDao ->
            accountDao.deleteAccounts(*toRemove.toTypedArray())

            val oldData = RotationPublishData(user.invitationInfo.invoke()!!)

            val userAccount = user.getAccount()

            userAccount?.let { account ->
                if(asymDesc != null) {
                    val encode = fun(): Cipher {
                        return user.symCipher.invoke(Cipher.ENCRYPT_MODE)!!
                    }
                    val keyPair = User.generateUserFeedKeys(user.name, asymDesc!!, encode)

                    SecureDatabase.instance!!.keyDao().addKey(keyPair.feedPublicKey)
                    SecureDatabase.instance!!.keyDao().addKey(keyPair.feedPrivateKey)

                    account.key2 = keyPair.feedPrivate
                    account.key1 = keyPair.feedPublic
                }

                if(url != null) {
                    account.url = CliqueConfig.stringToEncodedString(url!!, user.symCipher.invoke(Cipher.ENCRYPT_MODE)!!)
                }

                accountDao.updateAccounts(account)

                oldData
            }
        }
    }

    companion object {
        fun startRotation(user: User) : RotationExchange {
            return RotationExchange(user)
        }
    }
}

data class RotationPublishData(private val subscription: CliqueSubscription) {

    val oldUrl: String = subscription.subscription
    val oldPublishKey: String = subscription.rotateKey

    /**
     * When you're done publishing the rotation messages to this url, make sure you clean up.
     */
    fun cleanUp() {
        deleteKey(subscription.feedReadKey)
        deleteKey(subscription.rotateKey)
    }

    private fun deleteKey(name: String) {
        SecureDatabase.instance!!.keyDao().findKey(name)?.also { SecureDatabase.instance!!.keyDao().deleteKey(it) }
    }
}