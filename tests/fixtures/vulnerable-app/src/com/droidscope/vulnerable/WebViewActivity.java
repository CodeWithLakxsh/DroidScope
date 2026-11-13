package com.droidscope.vulnerable;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.net.http.SslError;
import android.os.Bundle;
import android.webkit.JavascriptInterface;
import android.webkit.SslErrorHandler;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

/** DroidScope fixture: deliberately unsafe WebView configuration. */
public class WebViewActivity extends Activity {

    private WebView webView;

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        webView = new WebView(this);
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        // DS-WEBVIEW-002: same-origin policy lifted for file:// pages
        settings.setAllowUniversalAccessFromFileURLs(true);
        settings.setAllowFileAccessFromFileURLs(true);
        // DS-WEBVIEW-003: mixed content permitted
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
        // DS-WEBVIEW-005: remote inspection enabled unconditionally
        WebView.setWebContentsDebuggingEnabled(true);

        // DS-WEBVIEW-001: a Java object bridged into the JavaScript context
        webView.addJavascriptInterface(new JsBridge(), "AndroidBridge");

        // DS-WEBVIEW-004: TLS certificate errors ignored
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
                handler.proceed();
            }
        });

        // DS-WEBVIEW-006: the loaded URL comes straight from the Intent
        String url = getIntent().getStringExtra("url");
        webView.loadUrl(url);
        setContentView(webView);
    }

    /** Exposed to any page the WebView loads. */
    public class JsBridge {
        @JavascriptInterface
        public String getAuthToken() {
            return CryptoUtil.generateToken();
        }

        @JavascriptInterface
        public void runCommand(String command) throws Exception {
            // DS-CODE-002: shell execution with a caller-supplied string
            Runtime.getRuntime().exec(command);
        }
    }
}
