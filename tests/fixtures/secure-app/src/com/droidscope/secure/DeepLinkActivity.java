package com.droidscope.secure;

import android.app.Activity;
import android.net.Uri;
import android.os.Bundle;

/** Reached through a verified App Link; incoming data is validated. */
public class DeepLinkActivity extends Activity {

    private static final String EXPECTED_HOST = "secure.example.com";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Uri data = getIntent().getData();
        // The host is checked before anything from the link is used, and the
        // link is never treated as proof of identity.
        if (data == null || !EXPECTED_HOST.equals(data.getHost())) {
            finish();
        }
    }
}
