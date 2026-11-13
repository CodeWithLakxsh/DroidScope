/*
 * DroidScope starter YARA rules.
 *
 * These rules describe *capabilities and indicators*, not malware families. A
 * match means "this content is present", which is a starting point for review,
 * never an attribution. Rules that would claim family attribution on a weak
 * signal are deliberately absent: see docs/analyzers/yara-rules.md.
 *
 * Scope: these run against DEX files, native libraries and assets inside an
 * APK, not against the APK container itself.
 */

rule DroidScope_DynamicCodeLoading
{
    meta:
        author = "DroidScope"
        description = "References APIs capable of loading executable code at runtime"
        severity = "medium"
        category = "suspicious-behaviour"
        confidence = "medium"
        reference = "https://developer.android.com/privacy-and-security/risks/dynamic-code-loading"
        note = "Legitimate for plugin architectures and some SDKs; review the source of the loaded code"

    strings:
        $dex_loader    = "dalvik/system/DexClassLoader" ascii
        $path_loader   = "dalvik/system/PathClassLoader" ascii
        $memory_loader = "dalvik/system/InMemoryDexClassLoader" ascii
        $dex_file      = "dalvik/system/DexFile" ascii

    condition:
        any of them
}

rule DroidScope_RuntimeCommandExecution
{
    meta:
        author = "DroidScope"
        description = "References runtime shell command execution"
        severity = "medium"
        category = "suspicious-behaviour"
        confidence = "medium"
        note = "Common in root checks and device diagnostics as well as in malware"

    strings:
        $exec    = "Ljava/lang/Runtime;->exec" ascii
        $pb      = "Ljava/lang/ProcessBuilder;" ascii
        $sh      = "/system/bin/sh" ascii

    condition:
        any of them
}

rule DroidScope_RootDetectionOrAccess
{
    meta:
        author = "DroidScope"
        description = "Contains strings associated with root detection or root access"
        severity = "low"
        category = "suspicious-behaviour"
        confidence = "high"
        note = "Indicates the application inspects for root; it does not indicate malice"

    strings:
        $su1      = "/system/bin/su" ascii
        $su2      = "/system/xbin/su" ascii
        $su3      = "/sbin/su" ascii
        $magisk   = "magisk" nocase ascii
        $supersu  = "supersu" nocase ascii
        $busybox  = "busybox" nocase ascii
        $testkeys = "test-keys" ascii

    condition:
        2 of them
}

rule DroidScope_EmulatorDetection
{
    meta:
        author = "DroidScope"
        description = "Contains strings used to detect an emulated device"
        severity = "low"
        category = "obfuscation-indicator"
        confidence = "medium"
        note = "Anti-analysis behaviour; also used legitimately for fraud prevention"

    strings:
        $goldfish = "goldfish" ascii
        $ranchu   = "ranchu" ascii
        $qemu     = "ro.kernel.qemu" ascii
        $generic  = "generic_x86" ascii
        $sdk_build = "ro.build.fingerprint" ascii
        $vbox     = "vbox86" ascii

    condition:
        2 of them
}

rule DroidScope_TelephonyAndSmsInterception
{
    meta:
        author = "DroidScope"
        description = "Combines SMS receiving with network transmission capability"
        severity = "medium"
        category = "suspicious-behaviour"
        confidence = "low"
        note = "The combination is used by one-time-passcode stealers, and also by legitimate messaging applications"

    strings:
        $sms_receiver = "android.provider.Telephony.SMS_RECEIVED" ascii
        $sms_manager  = "Landroid/telephony/SmsManager;" ascii
        $get_message  = "getMessageBody" ascii
        $http         = "Ljava/net/HttpURLConnection;" ascii
        $okhttp       = "Lokhttp3/" ascii

    condition:
        ($sms_receiver or $sms_manager) and $get_message and ($http or $okhttp)
}

rule DroidScope_AccessibilityServiceAbusePattern
{
    meta:
        author = "DroidScope"
        description = "Declares an accessibility service together with overlay and package query capability"
        severity = "medium"
        category = "suspicious-behaviour"
        confidence = "low"
        note = "This combination underlies overlay banking trojans; it is also used by legitimate assistive software"

    strings:
        $service   = "android.accessibilityservice.AccessibilityService" ascii
        $event     = "onAccessibilityEvent" ascii
        $overlay   = "TYPE_APPLICATION_OVERLAY" ascii
        $overlay2  = "SYSTEM_ALERT_WINDOW" ascii

    condition:
        $service and $event and ($overlay or $overlay2)
}

rule DroidScope_CommercialPackerArtifacts
{
    meta:
        author = "DroidScope"
        description = "Contains artifacts of a commercial APK packer or protector"
        severity = "info"
        category = "obfuscation-indicator"
        confidence = "medium"
        note = "Packing conceals code from static analysis; it is used by both commercial applications and malware"

    strings:
        $jiagu      = "libjiagu" ascii
        $bangcle    = "bangcle" nocase ascii
        $ijiami     = "ijiami" nocase ascii
        $secneo     = "libDexHelper" ascii
        $dexprotect = "DexProtector" nocase ascii
        $tencent    = "libshella" ascii
        $upx        = "UPX!" ascii

    condition:
        any of them
}

rule DroidScope_EmbeddedExecutablePayload
{
    meta:
        author = "DroidScope"
        description = "An executable payload (DEX, ELF or APK) is hidden in application assets or resources"
        severity = "medium"
        category = "embedded-payload"
        confidence = "high"
        reference = "https://developer.android.com/privacy-and-security/risks/dynamic-code-loading"
        note = "Legitimate for bundled runtimes and plugins; confirm the payload's origin and that its integrity is verified before loading"

    strings:
        $dex_magic = { 64 65 78 0A 30 33 ?? 00 }
        $elf_magic = { 7F 45 4C 46 }
        $apk_magic = { 50 4B 03 04 }

    condition:
        // entry_path is supplied by the scanner for each archive entry.  The
        // check keeps this rule from firing on the application's own
        // classes.dex and lib/*.so, where this content is expected.
        entry_path matches /^(assets|res)\// and
        (($dex_magic at 0) or ($elf_magic at 0) or ($apk_magic at 0))
}
