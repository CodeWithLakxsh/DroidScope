package com.droidscope.secure;

import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;

/** Recommended storage: private mode and parameter binding. */
public final class StorageUtil {

    private StorageUtil() {}

    /** MODE_PRIVATE keeps the file inside the application sandbox. */
    public static void saveDisplayName(Context context, String displayName) {
        SharedPreferences prefs = context.getSharedPreferences("profile", Context.MODE_PRIVATE);
        prefs.edit().putString("display_name", displayName).apply();
    }

    /** Values are bound, so input cannot change the query structure. */
    public static Cursor findUser(SQLiteDatabase db, String username) {
        return db.rawQuery("SELECT * FROM users WHERE name = ?", new String[] {username});
    }
}
