#!/usr/bin/env bash
#
# Build a DroidScope test fixture APK from source.
#
# Produces a genuine, signed APK using the Android SDK build tools -- no Gradle
# required. The fixture apps are analysed by the test suite; they are never
# installed on a device by CI.
#
# Usage:
#   scripts/development/build_fixture_apk.sh [vulnerable|secure|all]
#
# Requirements: Android SDK build-tools and a platform android.jar, plus a JDK.
# Run `droidscope doctor` to check what is available.

set -euo pipefail

APP="${1:-all}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURES="${REPO_ROOT}/tests/fixtures"

SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Library/Android/sdk}}"
if [[ ! -d "${SDK_ROOT}" ]]; then
    echo "error: Android SDK not found. Set ANDROID_SDK_ROOT." >&2
    exit 2
fi

# Pick the newest build-tools and platform available.
BUILD_TOOLS_DIR="$(ls -d "${SDK_ROOT}"/build-tools/*/ 2>/dev/null | sort -V | tail -1)"
PLATFORM_JAR="$(ls "${SDK_ROOT}"/platforms/android-*/android.jar 2>/dev/null | sort -V | tail -1)"
if [[ -z "${BUILD_TOOLS_DIR}" || -z "${PLATFORM_JAR}" ]]; then
    echo "error: build-tools or platform android.jar missing from ${SDK_ROOT}" >&2
    exit 2
fi

AAPT2="${BUILD_TOOLS_DIR}aapt2"
D8="${BUILD_TOOLS_DIR}d8"
ZIPALIGN="${BUILD_TOOLS_DIR}zipalign"
APKSIGNER="${BUILD_TOOLS_DIR}apksigner"

KEYSTORE="${FIXTURES}/.build/debug.keystore"
KEY_ALIAS="droidscope-fixture"
KEY_PASS="droidscope"

echo "SDK          : ${SDK_ROOT}"
echo "build-tools  : $(basename "${BUILD_TOOLS_DIR%/}")"
echo "platform jar : $(basename "$(dirname "${PLATFORM_JAR}")")"


# Generate a random string of a given length from a character set.
#
# The subshell disables pipefail: `head -c` closes the pipe once it has enough
# bytes, which sends SIGPIPE to `tr`, and under `set -o pipefail` that failure
# would abort the whole script.
rand_str() {
    local length="$1" charset="$2"
    (
        set +o pipefail
        LC_ALL=C tr -dc "${charset}" < /dev/urandom | head -c "${length}"
    )
}

# Replace @@TOKEN@@ placeholders in the staged fixture sources with values that
# match each provider's documented credential format.
substitute_placeholders() {
    local tree="$1"

    local aws_key="AKIA$(rand_str 16 'A-Z0-9')"
    local api_secret
    api_secret="$(rand_str 40 'A-Za-z0-9')"
    local slack_token="xoxb-$(rand_str 10 '0-9')-$(rand_str 10 '0-9')-$(rand_str 24 'A-Za-z0-9')"
    local google_key="AIza$(rand_str 35 'A-Za-z0-9_-')"
    local google_key_2="AIza$(rand_str 35 'A-Za-z0-9_-')"

    local file
    while IFS= read -r file; do
        # A temporary file keeps this portable across BSD and GNU sed.
        sed -e "s|@@AWS_ACCESS_KEY_ID@@|${aws_key}|g" \
            -e "s|@@API_SECRET_KEY@@|${api_secret}|g" \
            -e "s|@@SLACK_TOKEN@@|${slack_token}|g" \
            -e "s|@@GOOGLE_API_KEY@@|${google_key}|g" \
            -e "s|@@GOOGLE_API_KEY_2@@|${google_key_2}|g" \
            "${file}" > "${file}.tmp" && mv "${file}.tmp" "${file}"
    done < <(find "${tree}" \( -name '*.java' -o -name '*.xml' \))
}

ensure_keystore() {
    if [[ -f "${KEYSTORE}" ]]; then
        return
    fi
    mkdir -p "$(dirname "${KEYSTORE}")"
    echo "Generating a throwaway signing key for fixtures (not committed)"
    keytool -genkeypair -v \
        -keystore "${KEYSTORE}" \
        -storepass "${KEY_PASS}" -keypass "${KEY_PASS}" \
        -alias "${KEY_ALIAS}" \
        -keyalg RSA -keysize 2048 -validity 10000 \
        -sigalg SHA256withRSA \
        -dname "CN=DroidScope Fixture, OU=Testing, O=DroidScope, L=Nowhere, C=GB" \
        >/dev/null 2>&1
}

build_app() {
    local name="$1"
    local src_dir="${FIXTURES}/${name}-app"
    local out_apk="${FIXTURES}/${name}-app.apk"

    if [[ ! -d "${src_dir}" ]]; then
        echo "error: ${src_dir} does not exist" >&2
        return 1
    fi

    echo
    echo "=== building ${name}-app ==="
    local work
    work="$(mktemp -d)"
    trap 'rm -rf "${work}"' RETURN

    mkdir -p "${work}/compiled" "${work}/classes" "${work}/dex" "${work}/app"

    # Stage the manifest and resources so placeholder substitution applies to
    # them as well as to the Java sources.
    cp "${src_dir}/AndroidManifest.xml" "${work}/app/AndroidManifest.xml"
    if [[ -d "${src_dir}/res" ]]; then
        cp -R "${src_dir}/res" "${work}/app/res"
    fi
    substitute_placeholders "${work}/app"

    # 1. compile resources
    if [[ -d "${work}/app/res" ]]; then
        "${AAPT2}" compile --dir "${work}/app/res" -o "${work}/compiled/resources.zip"
        RES_ARG=("${work}/compiled/resources.zip")
    else
        RES_ARG=()
    fi

    # 2. link into a base APK carrying the manifest and resource table
    "${AAPT2}" link \
        -o "${work}/base.apk" \
        -I "${PLATFORM_JAR}" \
        --manifest "${work}/app/AndroidManifest.xml" \
        --java "${work}/gen" \
        --auto-add-overlay \
        "${RES_ARG[@]+"${RES_ARG[@]}"}"

    # 3. compile Java sources (including the generated R class).
    #    Sources are staged inside the work directory first: javac and d8 read
    #    @argfiles as whitespace-separated, so a repository path containing a
    #    space would otherwise be split into two invalid arguments.
    mkdir -p "${work}/gen" "${work}/src"
    cp -R "${src_dir}/src/." "${work}/src/"

    # Substitute credential placeholders with generated, shape-valid values.
    # These are generated per build and exist only in the APK, so no
    # credential-shaped literal is ever committed to the repository. They
    # authenticate to nothing; they exist so the secret detector has something
    # of the right shape to find.
    substitute_placeholders "${work}/src"
    (cd "${work}" && find src gen -name '*.java' > sources.txt 2>/dev/null) || true
    (cd "${work}" && javac -nowarn -source 8 -target 8 \
        -bootclasspath "${PLATFORM_JAR}" \
        -classpath "${PLATFORM_JAR}" \
        -d classes \
        @sources.txt) 2>&1 | grep -v 'bootstrap class path\|source value 8\|target value 8\|deprecat' || true

    if ! find "${work}/classes" -name '*.class' | read -r _; then
        echo "error: javac produced no class files" >&2
        return 1
    fi

    # 4. convert to DEX
    (cd "${work}" && find classes -name '*.class' > classes.txt)
    (cd "${work}" && "${D8}" --release --min-api 21 \
        --lib "${PLATFORM_JAR}" \
        --output dex \
        @classes.txt)

    # 5. assemble the APK: base.apk plus classes.dex
    cp "${work}/base.apk" "${work}/unsigned.apk"
    (cd "${work}/dex" && zip -q -X "${work}/unsigned.apk" classes*.dex)

    # 6. align and sign
    "${ZIPALIGN}" -f -p 4 "${work}/unsigned.apk" "${work}/aligned.apk"
    ensure_keystore
    "${APKSIGNER}" sign \
        --ks "${KEYSTORE}" \
        --ks-key-alias "${KEY_ALIAS}" \
        --ks-pass "pass:${KEY_PASS}" \
        --key-pass "pass:${KEY_PASS}" \
        --v1-signing-enabled true \
        --v2-signing-enabled true \
        --out "${out_apk}" \
        "${work}/aligned.apk"

    "${APKSIGNER}" verify --print-certs "${out_apk}" | head -4
    echo "built: ${out_apk} ($(wc -c < "${out_apk}" | tr -d ' ') bytes)"
    shasum -a 256 "${out_apk}" | awk '{print "sha256: " $1}'
}

case "${APP}" in
    vulnerable) build_app vulnerable ;;
    secure)     build_app secure ;;
    all)        build_app vulnerable; build_app secure ;;
    *) echo "usage: $0 [vulnerable|secure|all]" >&2; exit 2 ;;
esac
