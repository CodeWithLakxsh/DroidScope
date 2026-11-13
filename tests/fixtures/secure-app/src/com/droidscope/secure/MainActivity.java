/*
 * DroidScope test fixture: the SECURE counterpart.
 * Each method is the recommended form of a weakness in vulnerable-app.
 */
package com.droidscope.secure;

import android.app.Activity;
import android.os.Bundle;

public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // No credential is logged, and no value from the Intent is trusted.
        CryptoUtil.secureRandomToken();
    }
}
