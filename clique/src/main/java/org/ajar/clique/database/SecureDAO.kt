package org.ajar.clique.database

import androidx.lifecycle.LiveData
import androidx.room.*

@Dao
interface CliqueKeyDAO {
    @Query("SELECT * FROM ${CliqueKey.TABLE_NAME} WHERE ${CliqueKey.COLUMN_NAME} = :name")
    fun findKey(name: String): CliqueKey

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun addKey(key: CliqueKey)

    @Update
    fun updateKey(vararg keys: CliqueKey)

    @Delete
    fun deleteKey(vararg keys: CliqueKey)
}

@Dao
interface CliqueAccountDAO {
    @Query("SELECT * FROM ${CliqueAccount.TABLE_NAME} WHERE ${CliqueAccount.COLUMN_USER} = :user LIMIT 1")
    fun findAccount(user: String): CliqueAccount

    @Query("SELECT ${CliqueAccount.COLUMN_SYMMETRIC}, ${CliqueAccount.COLUMN_SYMMETRIC_ALGO} FROM ${CliqueAccount.TABLE_NAME} WHERE ${CliqueAccount.COLUMN_USER} = :user LIMIT 1" )
    fun findSymmetricDesc(user: String): CliqueSymmetricDescription

    @Query("SELECT ${CliqueAccount.COLUMN_PRIVATE_1} FROM ${CliqueAccount.TABLE_NAME} WHERE ${CliqueAccount.COLUMN_USER} = :user LIMIT 1")
    fun findPublishKey(user: String): String

    @Query("SELECT ${CliqueAccount.COLUMN_DISPLAY_NAME}, ${CliqueAccount.COLUMN_URL}, ${CliqueAccount.COLUMN_PUBLIC_1} FROM ${CliqueAccount.TABLE_NAME} WHERE ${CliqueAccount.COLUMN_USER} = :user LIMIT 1")
    fun findFriendRequestInfo(user: String): CliqueSubscription

    @Query("SELECT ${CliqueAccount.COLUMN_DISPLAY_NAME}, ${CliqueAccount.COLUMN_URL}, ${CliqueAccount.COLUMN_PUBLIC_1} FROM ${CliqueAccount.TABLE_NAME} WHERE ${CliqueAccount.COLUMN_FILTER} = :filter")
    fun findSubscriptionKeys(filter: String): LiveData<List<CliqueSubscription>>

    @Query("SELECT ${CliqueAccount.COLUMN_DISPLAY_NAME}, ${CliqueAccount.COLUMN_PRIVATE_1} FROM ${CliqueAccount.TABLE_NAME} WHERE ${CliqueAccount.COLUMN_FILTER} = :filter")
    fun findRotationKeys(filter: String): LiveData<List<CliqueRotateDescription>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun addAccount(account: CliqueAccount)

    @Update
    fun updateAccounts(vararg accounts: CliqueAccount)

    @Delete
    fun deleteAccounts(vararg accounts: CliqueAccount)
}