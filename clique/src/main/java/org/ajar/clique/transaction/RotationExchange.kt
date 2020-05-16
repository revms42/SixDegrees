package org.ajar.clique.transaction

import org.ajar.clique.encryption.AsymmetricEncryption
import org.ajar.clique.facade.Friend
import org.ajar.clique.facade.User

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

    fun finalizeExchange() {

    }

    companion object {
        fun startRotation(user: User) : RotationExchange {
            return RotationExchange(user)
        }
    }
}