package com.droidscope.vulnerable;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** DroidScope fixture: exported receiver that forwards a nested Intent. */
public class CommandReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        // DS-CODE-004: Intent redirection
        Intent forwarded = intent.getParcelableExtra("forward_intent");
        if (forwarded != null) {
            context.startActivity(forwarded);
        }
    }
}
