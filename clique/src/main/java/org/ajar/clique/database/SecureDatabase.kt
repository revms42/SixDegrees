package org.ajar.clique.database

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(entities = [ CliqueKey::class, CliqueAccount::class ], version = 1)
abstract class SecureDatabase : RoomDatabase() {
    abstract fun keyDao(): CliqueKeyDAO
    abstract fun accountDao(): CliqueAccountDAO

    companion object {
        private var database: SecureDatabase? = null
        val instance: SecureDatabase?
            get() = database

        fun init(context: Context, name: String): Boolean {
            if(database == null) {
                //TODO: This should take considerably more thought as this builder has a lot of options.
                database = Room.databaseBuilder(context, SecureDatabase::class.java, name
                ).allowMainThreadQueries().build()
            }
            return database != null
        }
    }
}