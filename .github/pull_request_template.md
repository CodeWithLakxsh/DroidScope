## What this changes

<!-- What does it do, and why? -->

## Type

- [ ] Bug fix
- [ ] New detection rule
- [ ] New feature
- [ ] Documentation
- [ ] Refactoring

## If this adds or changes a detection rule

A rule needs to be proven in **both** directions — otherwise it is
indistinguishable from a keyword matcher.

- [ ] A test proves it fires on the vulnerable fixture
- [ ] A test proves it stays **silent** on the secure fixture
- [ ] `impact` says what an attacker gains, not that something "is insecure"
- [ ] `remediation` is specific enough to act on
- [ ] CWE and MASVS identifiers are real
- [ ] `limitations` states what the detection cannot tell you
- [ ] `droidscope rules validate` passes

**Code it fires on:**

```java
```

**Code it must not fire on:**

```java
```

## Checks

- [ ] `make check` passes
- [ ] Documentation updated if behaviour changed
- [ ] No APK, credential or real sample committed
- [ ] If an analyzer can now fail in a new way, that failure is recorded rather than swallowed

## Notes for the reviewer

<!-- Anything you are unsure about, or decisions worth a second opinion -->
