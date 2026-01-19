# WebSocket Events Reference

This document describes the real-time WebSocket events emitted by the monitoring backend. These events are delivered over a Socket.IO-compatible WebSocket connection and are intended to power live dashboards, alerts, and historical summaries.

---

## Transport & Framing

All application-level messages follow the Socket.IO event format and are prefixed with:

```
42
```

This indicates:

* `4` → Engine.IO message
* `2` → Socket.IO event

Each message is a JSON array of the form:

```
["eventName", ...payload]
```

Any messages not matching this pattern (e.g. bare numbers or acknowledgements) should be ignored by clients.

---

## Common Concepts

### monitorID

An integer identifier representing a monitored target (website, API, service, etc.). All metrics and events are scoped to a specific `monitorID`.

### status

Represents the health of a monitor at the time of the event:

* `1` → Up / Healthy
* `0` → Down / Unhealthy

### Time Format

All timestamps are emitted as server-side strings in the format:

```
YYYY-MM-DD HH:mm:ss.SSS
```

---

## Event: `heartbeat`

### Description

Represents a single health check execution for a monitor. This is the most frequent and fundamental event in the system.

### Payload Structure

```
["heartbeat", {
  monitorID: number,
  status: number,
  time: string,
  msg: string,
  ping: number,
  important: boolean,
  retries: number
}]
```

### Field Details

* **monitorID**
  ID of the monitor being checked.

* **status**
  Result of the check (`1` = success, `0` = failure).

* **time**
  Timestamp when the check completed.

* **msg**
  Human-readable result message (e.g. HTTP status or error reason).

* **ping**
  Response time in milliseconds for this specific check.

* **important**
  Indicates whether this heartbeat represents a state change or alert-worthy event.

  * `false` → Routine check
  * `true` → Status transition or critical condition

* **retries**
  Number of retries attempted before finalizing the result.

### Client Usage

* Update live status indicators
* Append to real-time latency charts
* Trigger alerts only when `important === true`

---

## Event: `avgPing`

### Description

Provides a rolling average response time for a monitor. This smooths out short-term spikes seen in raw heartbeats.

### Payload Structure

```
["avgPing", monitorID: number, averagePingMs: number]
```

### Field Details

* **monitorID**
  Target being summarized.

* **averagePingMs**
  Average latency in milliseconds.

### Client Usage

* Display average response time metrics
* Power summary dashboards

---

## Event: `uptime`

### Description

Reports uptime ratios for a monitor across multiple time windows.

### Payload Structure

```
["uptime", monitorID: number, period: number | string, uptimeRatio: number]
```

### Field Details

* **monitorID**
  Target being summarized.

* **period**
  Time window for the uptime calculation:

  * `24` → Last 24 hours
  * `720` → Last 720 hours (~30 days)
  * `"1y"` → Last year

* **uptimeRatio**
  Fraction between `0` and `1` representing uptime.

  * Example: `0.993` → 99.3% uptime

### Client Usage

* Convert ratio to percentage for display
* Power SLA and reliability views
* Avoid client-side recomputation

---

## Event: `certInfo`

### Description

Delivers a full TLS certificate inspection for the monitored host, including the complete trust chain.

This is a heavy, infrequently changing event and should be cached aggressively by clients.

### Payload Structure

```
["certInfo", monitorID: number, certInfoJson: string]
```

> **Note**: The certificate data is emitted as a **stringified JSON object**, not a raw object.

### Top-Level Certificate Fields

Inside the parsed JSON payload:

* **valid**
  Overall validity of the certificate (`true` / `false`).

* **certInfo**
  Detailed certificate information, including:

  * **subject / issuer** – Certificate ownership and signer
  * **subjectaltname** – DNS names covered
  * **valid_from / valid_to** – Certificate lifetime
  * **daysRemaining** – Days until expiry
  * **fingerprints** – Cryptographic identifiers
  * **pubkey / curve / bits** – Cryptographic strength
  * **issuerCertificate** – Nested intermediate and root CA chain
  * **certType** – `server`, `intermediate CA`, or `root CA`

### Client Usage

* Display certificate validity and expiry warnings
* Trigger alerts when `daysRemaining` crosses thresholds
* Show trust-chain details in advanced views
* Cache and refresh sparingly

---

## Event: `login`

### Description

Represents a client authentication attempt over the WebSocket connection. This event is sent from the client to the server to initiate login and obtain an authenticated session.

This event is used for **both** unsuccessful and successful authentication attempts. The outcome is determined by the server response.

### Payload Structure

```
["login", {
  username: string,
  password: string,
  token: string
}]
```

### Field Details

* **username**
  Account identifier used for authentication.

* **password**
  Plain-text password provided at login time. This is transmitted only for initial authentication and must be protected by TLS.

* **token**
  Optional authentication token. May be empty for first-time or password-based login flows.

### Client Usage

* Emit once per connection when authentication is required
* Do not retry blindly on failure; wait for server response
* Clear credentials from memory immediately after emission

---

## Event: `login` (successful response)

### Description

Represents a **successful authentication acknowledgment** from the server. This response confirms that the WebSocket connection is now authenticated.

Unlike failures, a successful login may reuse the `login` event name but is emitted with a different Socket.IO framing code, indicating success rather than an error condition.

### Example

```
421["login", {
  "username": "vaibhav",
  "password": "***",
  "token": ""
}]
```

### Semantics

* Indicates that credentials were accepted
* Marks the WebSocket session as authenticated
* No further login attempts should be sent on this connection

### Client Usage

* Transition application state to "authenticated"
* Enable privileged or monitor-scoped subscriptions
* Immediately discard any stored credential data

---

## Event: `authFailure` (server response)

---

## Event: `authFailure` (server response)

### Description

Represents a failed authentication response from the server. This event indicates that the login attempt was rejected.

This message is **not** emitted using the standard `42` Socket.IO event framing, but rather as a Socket.IO error/ack-style payload.

### Payload Structure

```
{
  ok: false,
  msg: string,
  msgi18n: boolean
}
```

### Field Details

* **ok**
  Always `false`, indicating authentication failure.

* **msg**
  Error code describing the failure reason (e.g. `authIncorrectCreds`).

* **msgi18n**
  Indicates whether the error message is intended to be internationalized on the client side.

### Client Usage

* Display a user-facing authentication error
* Map `msg` to localized copy if `msgi18n === true`
* Do not treat as a transport failure; the WebSocket connection itself may still be valid

---

## Non-Event Messages

Messages such as:

```
2 1
3 1
```

are transport-level acknowledgements or keep-alive traffic. They are **not application events** and should be ignored.

---

## Event Summary

| Event Name  | Purpose                                    |
| ----------- | ------------------------------------------ |
| `heartbeat` | Real-time health check result              |
| `avgPing`   | Rolling average latency                    |
| `uptime`    | Historical uptime ratios                   |
| `certInfo`  | TLS certificate and trust-chain inspection |

---

## Design Notes

* `heartbeat` reflects the present moment
* `avgPing` and `uptime` provide historical context
* `certInfo` enables proactive security and expiry monitoring

Together, these events form a complete real-time monitoring telemetry stream.
