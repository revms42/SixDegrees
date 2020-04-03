package org.ajar.clique.database

import androidx.lifecycle.LiveData
import androidx.room.DatabaseConfiguration
import androidx.room.InvalidationTracker
import androidx.sqlite.db.SupportSQLiteOpenHelper
import com.google.gson.Gson

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

    override fun findSubscriptionKeys(filter: String): LiveData<List<CliqueSubscription>?> {
        TODO("This will require not only mocking the livedata, but the behavior behind it")
    }

    override fun findRotationKeys(filter: String): LiveData<List<CliqueRotateDescription>?> {
        TODO("This will require not only mocking the livedata, but the behavior behind it")
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
            override fun createInvalidationTracker(): InvalidationTracker { TODO("not implemented") }
            override fun clearAllTables() { TODO("not implemented") }

            override fun accountDao(): CliqueAccountDAO { return accountMock }
            override fun keyDao(): CliqueKeyDAO { return keyMock }
        }
        SecureDatabase.setDatabaseForTesting(mockDB)
    }
}