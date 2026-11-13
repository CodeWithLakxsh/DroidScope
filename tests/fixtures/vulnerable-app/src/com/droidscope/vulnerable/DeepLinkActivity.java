package com.droidscope.vulnerable;

import android.app.Activity;
import android.net.Uri;
import android.os.Bundle;

/** DroidScope fixture: activity reachable through an unverified deep link. */
public class DeepLinkActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Uri data = getIntent().getData();
        if (data != null) {
            String token = data.getQueryParameter("token");
            StorageUtil.saveToken(this, token);
        }
    }
}
