package com.droidscope.vulnerable;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.net.Uri;

/** DroidScope fixture: an exported provider with no access control. */
public class NotesProvider extends ContentProvider {

    private SQLiteDatabase database;

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {
        String table = uri.getLastPathSegment();
        // DS-STORAGE-005: selection concatenated into the query
        return database.rawQuery("SELECT * FROM notes WHERE owner = '" + table + "'", null);
    }

    @Override
    public String getType(Uri uri) {
        return "vnd.android.cursor.dir/vnd.com.droidscope.vulnerable.notes";
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return uri;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        return 0;
    }
}
