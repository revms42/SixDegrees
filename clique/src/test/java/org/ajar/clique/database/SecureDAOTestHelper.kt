package org.ajar.clique.database

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.room.DatabaseConfiguration
import androidx.room.InvalidationTracker
import androidx.sqlite.db.SupportSQLiteOpenHelper
import com.google.gson.Gson
import org.mockito.Mockito

open class SecureDaoTestMock {
    private val dataMap = HashMap<String, String>()

    protected fun addObject(key: String, value: Any) {
        dataMap[key] = gson.toJson(value)
    }

    protected fun <A> getObject(key: String, type: Class<A>): A? {
        return gson.fromJson(dataMap[key], type)
    }

    protected fun removeObject(key: String) {
        dataMap.remove(key)
    }

    protected fun <A> values(type: Class<A>) : List<A>? {
        return dataMap.values.map { gson.fromJson(it, type) }.toList()
    }

    open fun clear() {
        dataMap.clear()
    }

    companion object {
        private val gson = Gson()
    }
}

class CliqueKeyDAOMock : SecureDaoTestMock(), CliqueKeyDAO {
    override fun findKey(name: String): CliqueKey? {
        return getObject(name, CliqueKey::class.java)
    }

    override fun addKey(key: CliqueKey) {
        addObject(key.name, key)
    }

    override fun updateKey(vararg keys: CliqueKey) {
        keys.forEach { addKey(it) }
    }

    override fun deleteKey(vararg keys: CliqueKey) {
        keys.forEach { removeObject(it.name) }
    }
}

class MockMutableLiveData<T> : MutableLiveData<T>() {

    private var _value: T? = null

    override fun postValue(value: T) {
        _value = value
    }

    override fun getValue(): T? {
        return _value
    }
}

class CliqueAccountDAOMock : SecureDaoTestMock(), CliqueAccountDAO {

    private val filterSubscriptionMap = HashMap<String, MutableLiveData<List<CliqueSubscription>?>>()
    private val filterRotationMap = HashMap<String, MutableLiveData<List<CliqueRotateDescription>?>>()

    private fun postSubscriptionChange(filter: String) {
        filterSubscriptionMap[filter]?.postValue(filterAccounts(filter)?.map {account -> CliqueSubscription(account.displayName, account.url, account.publicOne) }?.toList())
    }

    private fun postRotationChange(filter: String) {
        filterRotationMap[filter]?.postValue(filterAccounts(filter)?.map { account -> CliqueRotateDescription(account.displayName, account.privateOne) }?.toList())
    }

    private fun postBothChanges(filter: String) {
        postSubscriptionChange(filter)
        postRotationChange(filter)
    }

    override fun clear() {
        super.clear()
        filterSubscriptionMap.clear()
        filterRotationMap.clear()
    }

    override fun findAccount(user: String): CliqueAccount? {
        return getObject(user, CliqueAccount::class.java)
    }

    override fun findSymmetricDesc(user: String): CliqueSymmetricDescription? {
        return findAccount(user)?.let { CliqueSymmetricDescription(it.sym, it.algo) }
    }

    override fun findPublishKey(user: String): String? {
        return findAccount(user)?.privateOne
    }

    override fun findFriendRequestInfo(user: String): CliqueSubscription? {
        return findAccount(user)?.let { CliqueSubscription(it.displayName, it.url, it.publicOne) }
    }

    override fun findPublishUrlForUser(user: String): String? {
        return findAccount(user)?.url
    }

    override fun findFilterForUser(user: String): String? {
        return findAccount(user)?.filter
    }

    private fun filterAccounts(filter: String): List<CliqueAccount>? {
        return values(CliqueAccount::class.java)?.filter { account -> account.filter == filter }
    }

    override fun findSubscriptionKeys(filter: String): LiveData<List<CliqueSubscription>?> {
        if(!filterSubscriptionMap.containsKey(filter)) {
            filterSubscriptionMap[filter] = MockMutableLiveData()
        }

        return filterSubscriptionMap[filter]!!.also {
            postSubscriptionChange(filter)
        }
    }

    override fun findRotationKeys(filter: String): LiveData<List<CliqueRotateDescription>?> {
        if(!filterRotationMap.containsKey(filter)) {
            filterRotationMap[filter] = MockMutableLiveData()
        }

        return filterRotationMap[filter]!!.also {
            postRotationChange(filter)
        }
    }

    override fun addAccount(account: CliqueAccount) {
        addObject(account.user, account)

        if(filterSubscriptionMap.containsKey(account.filter)) {
            postBothChanges(account.filter)
        }
    }

    override fun updateAccounts(vararg accounts: CliqueAccount) {
        accounts.forEach {
            addAccount(it)

            if(filterSubscriptionMap.containsKey(it.filter)) {
                postBothChanges(it.filter)
            }
        }
    }

    override fun deleteAccounts(vararg accounts: CliqueAccount) {
        accounts.forEach {
            removeObject(it.user)

            if(filterSubscriptionMap.containsKey(it.filter)) {
                postBothChanges(it.filter)
            }
        }
    }
}

object SecureDAOTestHelper {

    val accountMock = CliqueAccountDAOMock()
    val keyMock = CliqueKeyDAOMock()

    fun setupMockDatabase() {
        val mockDB = object : SecureDatabase() {
            override fun createOpenHelper(config: DatabaseConfiguration?): SupportSQLiteOpenHelper { TODO("not implemented") }
            override fun createInvalidationTracker(): InvalidationTracker {
                return Mockito.mock(InvalidationTracker::class.java)
            }
            override fun clearAllTables() { TODO("not implemented") }

            override fun accountDao(): CliqueAccountDAO { return accountMock }
            override fun keyDao(): CliqueKeyDAO { return keyMock }
        }
        SecureDatabase.setDatabaseForTesting(mockDB)
    }

    fun clear() {
        accountMock.clear()
        keyMock.clear()
    }
}