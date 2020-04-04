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

class CliqueAccountDAOMock : SecureDaoTestMock(), CliqueAccountDAO {
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
        return MutableLiveData<List<CliqueSubscription>?>().also {
            it.postValue(filterAccounts(filter)?.map {account -> CliqueSubscription(account.displayName, account.url, account.publicOne) }?.toList())
        }
    }

    override fun findRotationKeys(filter: String): LiveData<List<CliqueRotateDescription>?> {
        return MutableLiveData<List<CliqueRotateDescription>?>().also {
            it.postValue(filterAccounts(filter)?.map { account -> CliqueRotateDescription(account.displayName, account.privateOne) }?.toList())
        }
    }

    override fun addAccount(account: CliqueAccount) {
        addObject(account.user, account)
    }

    override fun updateAccounts(vararg accounts: CliqueAccount) {
        accounts.forEach { addAccount(it) }
    }

    override fun deleteAccounts(vararg accounts: CliqueAccount) {
        accounts.forEach { removeObject(it.user) }
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
}