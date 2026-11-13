"""Frida instrumentation modules.

Every module here is **observational**. They record what the application does;
none of them defeat a security control. In particular there is deliberately no
SSL-unpinning, root-detection-bypass or biometric-bypass module: such modules
change application behaviour and belong in a separately enabled research
toolkit limited to environments where that is explicitly authorised.

Each script posts structured events through ``send()``; the session collector
normalises them into runtime events.
"""

from __future__ import annotations

from dataclasses import dataclass

COMMON_PRELUDE = """
// Shared helpers. Values are truncated so a chatty application cannot flood
// the host, and arguments are summarised rather than dumped wholesale.
const MAX = 240;

function clip(value) {
  try {
    if (value === null || value === undefined) return String(value);
    const text = String(value);
    return text.length > MAX ? text.substring(0, MAX) + '\\u2026' : text;
  } catch (e) {
    return '<unprintable>';
  }
}

function emit(type, api, summary, data) {
  send({
    droidscope: true,
    type: type,
    api: api,
    summary: clip(summary),
    data: data || {},
    ts: Date.now()
  });
}

function stack() {
  try {
    return Thread.backtrace(this.context, Backtracer.ACCURATE)
      .map(DebugSymbol.fromAddress).slice(0, 6).join('\\n');
  } catch (e) {
    return null;
  }
}

function safeHook(className, methodName, builder) {
  try {
    const clazz = Java.use(className);
    if (!clazz[methodName]) {
      emit('instrumentation', className + '.' + methodName,
           'method not present on this platform version', {status: 'skipped'});
      return false;
    }
    builder(clazz);
    return true;
  } catch (e) {
    // Report the failure instead of silently producing no events.
    emit('instrumentation', className + '.' + methodName,
         'hook failed: ' + e.message, {status: 'failed'});
    return false;
  }
}
"""

FILE_ACCESS = """
Java.perform(function () {
  safeHook('java.io.FileOutputStream', '$init', function (clazz) {
    clazz.$init.overload('java.io.File').implementation = function (file) {
      emit('file', 'FileOutputStream(File)', file.getAbsolutePath(), {
        path: String(file.getAbsolutePath()), mode: 'write'
      });
      return this.$init(file);
    };
  });

  safeHook('java.io.FileInputStream', '$init', function (clazz) {
    clazz.$init.overload('java.io.File').implementation = function (file) {
      emit('file', 'FileInputStream(File)', file.getAbsolutePath(), {
        path: String(file.getAbsolutePath()), mode: 'read'
      });
      return this.$init(file);
    };
  });

  safeHook('android.content.SharedPreferences$Editor', 'putString', function (clazz) {
    clazz.putString.implementation = function (key, value) {
      // The value is deliberately not recorded: it frequently holds a token.
      emit('storage', 'SharedPreferences.Editor.putString', key, {
        key: String(key), value_length: value ? String(value).length : 0
      });
      return this.putString(key, value);
    };
  });
});
"""

CRYPTO_API = """
Java.perform(function () {
  safeHook('javax.crypto.Cipher', 'getInstance', function (clazz) {
    clazz.getInstance.overload('java.lang.String').implementation = function (transformation) {
      emit('crypto', 'Cipher.getInstance', transformation, {
        transformation: String(transformation)
      });
      return this.getInstance(transformation);
    };
  });

  safeHook('java.security.MessageDigest', 'getInstance', function (clazz) {
    clazz.getInstance.overload('java.lang.String').implementation = function (algorithm) {
      emit('crypto', 'MessageDigest.getInstance', algorithm, {algorithm: String(algorithm)});
      return this.getInstance(algorithm);
    };
  });

  safeHook('javax.crypto.spec.SecretKeySpec', '$init', function (clazz) {
    clazz.$init.overload('[B', 'java.lang.String').implementation = function (key, algorithm) {
      // Key material is never recorded; only its length and algorithm.
      emit('crypto', 'SecretKeySpec(byte[], String)', algorithm, {
        algorithm: String(algorithm), key_length_bytes: key ? key.length : 0
      });
      return this.$init(key, algorithm);
    };
  });
});
"""

NETWORK_API = """
Java.perform(function () {
  safeHook('java.net.URL', 'openConnection', function (clazz) {
    clazz.openConnection.overload().implementation = function () {
      const url = String(this.toString());
      emit('network', 'URL.openConnection', url, {
        url: url, cleartext: url.indexOf('http://') === 0
      });
      return this.openConnection();
    };
  });

  safeHook('okhttp3.Request$Builder', 'url', function (clazz) {
    clazz.url.overload('java.lang.String').implementation = function (url) {
      emit('network', 'okhttp3.Request.Builder.url', url, {
        url: String(url), cleartext: String(url).indexOf('http://') === 0
      });
      return this.url(url);
    };
  });
});
"""

PROCESS_AND_IPC = """
Java.perform(function () {
  safeHook('java.lang.Runtime', 'exec', function (clazz) {
    clazz.exec.overload('java.lang.String').implementation = function (command) {
      emit('process', 'Runtime.exec', command, {command: String(command), severity: 'high'});
      return this.exec(command);
    };
  });

  safeHook('android.content.ContextWrapper', 'startActivity', function (clazz) {
    clazz.startActivity.overload('android.content.Intent').implementation = function (intent) {
      emit('ipc', 'Context.startActivity', intent.toString(), {
        intent: String(intent.toString())
      });
      return this.startActivity(intent);
    };
  });
});
"""

METHOD_TRACE = """
Java.perform(function () {
  // Traces the application's own classes only, so the output is about the
  // application under test rather than the framework.
  const prefix = '__PACKAGE_PREFIX__';
  if (!prefix) { return; }
  let traced = 0;
  Java.enumerateLoadedClasses({
    onMatch: function (name) {
      if (traced >= 40 || name.indexOf(prefix) !== 0) { return; }
      try {
        const clazz = Java.use(name);
        const methods = clazz.class.getDeclaredMethods();
        for (let i = 0; i < methods.length && traced < 40; i++) {
          const methodName = methods[i].getName();
          if (!clazz[methodName] || methodName.indexOf('access$') === 0) { continue; }
          try {
            clazz[methodName].overloads.forEach(function (overload) {
              overload.implementation = function () {
                emit('method', name + '.' + methodName, 'invoked', {
                  class: name, method: methodName, argument_count: arguments.length
                });
                return overload.apply(this, arguments);
              };
            });
            traced++;
          } catch (e) { /* individual method not hookable */ }
        }
      } catch (e) { /* class not usable */ }
    },
    onComplete: function () {
      emit('instrumentation', 'method-trace', 'traced ' + traced + ' methods', {traced: traced});
    }
  });
});
"""


@dataclass(frozen=True, slots=True)
class InstrumentationModule:
    name: str
    description: str
    script: str
    requires_package_prefix: bool = False


MODULES: dict[str, InstrumentationModule] = {
    "file-access": InstrumentationModule(
        name="file-access",
        description="Records file reads and writes and SharedPreferences keys written.",
        script=FILE_ACCESS,
    ),
    "crypto-api": InstrumentationModule(
        name="crypto-api",
        description=(
            "Records cryptographic API usage: cipher transformations, digest "
            "algorithms and key algorithms. Key material is never captured."
        ),
        script=CRYPTO_API,
    ),
    "network-api": InstrumentationModule(
        name="network-api",
        description="Records URLs opened through java.net and OkHttp.",
        script=NETWORK_API,
    ),
    "process-ipc": InstrumentationModule(
        name="process-ipc",
        description="Records shell command execution and outgoing Intents.",
        script=PROCESS_AND_IPC,
    ),
    "method-trace": InstrumentationModule(
        name="method-trace",
        description=(
            "Traces up to 40 methods of the application's own classes. Verbose; "
            "intended for short sessions."
        ),
        script=METHOD_TRACE,
        requires_package_prefix=True,
    ),
}

DEFAULT_MODULES = ("file-access", "crypto-api", "network-api", "process-ipc")


def build_script(modules: list[str], *, package_name: str | None = None) -> str:
    """Compose the requested modules into a single Frida script."""
    selected = [MODULES[name] for name in modules if name in MODULES]
    parts = [COMMON_PRELUDE]
    for module in selected:
        script = module.script
        if module.requires_package_prefix:
            prefix = (package_name or "").strip()
            script = script.replace("__PACKAGE_PREFIX__", prefix)
        parts.append(f"// --- module: {module.name} ---\n{script}")
    return "\n".join(parts)


def describe_modules() -> list[dict[str, str]]:
    return [
        {"name": module.name, "description": module.description}
        for module in MODULES.values()
    ]
