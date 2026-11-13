package com.droidscope.vulnerable;

/**
 * DroidScope fixture: deliberately embedded credentials.
 *
 * Every value below is a randomly generated string that matches the *shape* of
 * a real credential so the corresponding detection rule can be proven to fire.
 * None of them authenticate to anything, and none were ever issued by the
 * services whose format they imitate.
 */
public final class SecretsConfig {

    // DS-SECRET-001: AWS access key id shape
    public static final String AWS_ACCESS_KEY_ID = "@@AWS_ACCESS_KEY_ID@@";
    // DS-SECRET-002: high-entropy literal in a credential-named constant
    public static final String API_SECRET_KEY = "x9K2mQ7vLp4wR8tN3bY6cZ1jH5sD0aF7gU4eI2oP";
    // DS-SECRET-001: Slack token shape
    public static final String SLACK_WEBHOOK_TOKEN = "@@SLACK_TOKEN@@";
    // Not a secret: a public client identifier. Must be reported as such.
    public static final String GOOGLE_MAPS_KEY = "@@GOOGLE_API_KEY@@";

    // Must NOT be reported: a benign constant.
    public static final String DEFAULT_LOCALE = "en_GB";
    public static final String CACHE_DIR_NAME = "image_cache";

    private SecretsConfig() {}
}
