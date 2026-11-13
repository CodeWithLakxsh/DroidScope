package com.droidscope.vulnerable;

import android.content.Context;
import android.content.SharedPreferences;

/** DroidScope fixture: deliberately weak authentication logic. */
public final class AuthManager {

    private AuthManager() {}

    /** DS-AUTH-001: credential compared against a compiled-in literal. */
    public static boolean login(String password) {
        if (password != null && password.equals("MasterUnlock2024")) {
            return true;
        }
        return false;
    }

    /** DS-AUTH-002: entitlement read from local storage and trusted. */
    public static boolean isPremium(Context context) {
        SharedPreferences prefs = context.getSharedPreferences("entitlements", Context.MODE_PRIVATE);
        return prefs.getBoolean("is_premium_user", false);
    }
}
