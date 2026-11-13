package com.droidscope.vulnerable;

/**
 * DroidScope test fixture: deliberately embedded credentials.
 *
 * The values below are PLACEHOLDER TOKENS, not credentials. The fixture build
 * script (scripts/development/build_fixture_apk.sh) replaces each @@NAME@@
 * token with a randomly generated string that matches the *shape* of the
 * corresponding provider's credential format, so the secret detector can be
 * proven to fire on it.
 *
 * Generating them at build time rather than committing them keeps this
 * repository free of credential-shaped literals, which would otherwise trip
 * secret scanners for everyone who clones or forks it. The generated values
 * live only in the built APK, which is not committed, and authenticate to
 * nothing.
 */
public final class SecretsConfig {

    // DS-SECRET-001: AWS access key id shape
    public static final String AWS_ACCESS_KEY_ID = "@@AWS_ACCESS_KEY_ID@@";
    // DS-SECRET-002: high-entropy literal in a credential-named constant
    public static final String API_SECRET_KEY = "@@API_SECRET_KEY@@";
    // DS-SECRET-001: Slack token shape
    public static final String SLACK_WEBHOOK_TOKEN = "@@SLACK_TOKEN@@";
    // Not a secret: a public client identifier. Must be reported as such.
    public static final String GOOGLE_MAPS_KEY = "@@GOOGLE_API_KEY@@";

    // Must NOT be reported: benign constants.
    public static final String DEFAULT_LOCALE = "en_GB";
    public static final String CACHE_DIR_NAME = "image_cache";

    private SecretsConfig() {}
}
