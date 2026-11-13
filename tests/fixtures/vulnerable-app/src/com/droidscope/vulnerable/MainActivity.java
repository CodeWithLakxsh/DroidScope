/*
 * DroidScope test fixture -- DELIBERATELY INSECURE CODE.
 * Each method exists to trigger a specific detection rule. Never copy this.
 */
package com.droidscope.vulnerable;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

public class MainActivity extends Activity {
    private static final String TAG = "MainActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String password = getIntent().getStringExtra("password");
        // DS-STORAGE-003: credential written to the system log
        Log.d(TAG, "user password = " + password);
        Log.v(TAG, "starting up");

        CryptoUtil.hashPassword(password);
        StorageUtil.saveToken(this, "session-token-value");
        NetworkUtil.fetchConfig();
    }
}
