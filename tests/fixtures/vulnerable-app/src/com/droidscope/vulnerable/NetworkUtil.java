package com.droidscope.vulnerable;

import java.net.URL;
import java.security.cert.X509Certificate;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/** DroidScope fixture: deliberately broken TLS handling. */
public final class NetworkUtil {

    // DS-NETWORK-003: cleartext endpoint
    private static final String CONFIG_URL = "http://config.vulnerable-fixture.example.io/v1/config";
    private static final String INTERNAL_URL = "https://staging.internal.vulnerable-fixture.net/api";

    private NetworkUtil() {}

    /** DS-NETWORK-001: a trust manager that accepts every certificate. */
    public static SSLContext permissiveContext() throws Exception {
        TrustManager[] trustAll = new TrustManager[] {
            new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }
        };
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, trustAll, new java.security.SecureRandom());
        return context;
    }

    /** DS-NETWORK-002: hostname verification disabled. */
    public static void disableHostnameVerification() {
        HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        });
    }

    public static String fetchConfig() {
        try {
            URL url = new URL(CONFIG_URL);
            return url.getHost() + INTERNAL_URL;
        } catch (Exception e) {
            return null;
        }
    }
}
