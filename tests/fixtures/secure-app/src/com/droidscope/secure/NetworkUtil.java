package com.droidscope.secure;

import java.net.URL;
import javax.net.ssl.HttpsURLConnection;

/** Recommended networking: HTTPS with the platform's default validation. */
public final class NetworkUtil {

    private static final String CONFIG_URL = "https://api.secure.example.com/v1/config";

    private NetworkUtil() {}

    /**
     * No custom TrustManager and no custom HostnameVerifier: the platform
     * performs full certificate chain and hostname validation.
     */
    public static int fetchConfig() throws Exception {
        URL url = new URL(CONFIG_URL);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setConnectTimeout(10000);
        try {
            return connection.getResponseCode();
        } finally {
            connection.disconnect();
        }
    }
}
