package com.droidscope.secure;

import android.app.Activity;
import android.os.Bundle;

/** Not exported: reachable only from inside this application. */
public class InternalActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }
}
