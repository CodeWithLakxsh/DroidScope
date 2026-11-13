package com.droidscope.vulnerable;

import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.os.Environment;
import java.io.File;

/** DroidScope fixture: deliberately insecure storage. */
public final class StorageUtil {

    private StorageUtil() {}

    /** DS-STORAGE-001 world readable mode, DS-STORAGE-002 credential in preferences. */
    @SuppressWarnings("deprecation")
    public static void saveToken(Context context, String token) {
        SharedPreferences prefs =
                context.getSharedPreferences("session", Context.MODE_WORLD_READABLE);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putString("auth_token", token);
        editor.putString("user_password", "hunter2-not-a-real-password");
        editor.apply();
    }

    /** DS-STORAGE-005: SQL built by concatenation. */
    public static Cursor findUser(SQLiteDatabase db, String username) {
        return db.rawQuery("SELECT * FROM users WHERE name = '" + username + "'", null);
    }

    /** Correct usage: parameter binding must NOT be reported. */
    public static Cursor findUserSafely(SQLiteDatabase db, String username) {
        return db.rawQuery("SELECT * FROM users WHERE name = ?", new String[] {username});
    }

    /** DS-STORAGE-004: credentials written to shared external storage. */
    public static File credentialBackupFile() {
        File external = Environment.getExternalStorageDirectory();
        return new File(external, "backup/credentials.json");
    }
}
