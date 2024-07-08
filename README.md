# SQL Injection Patterns

This repository contains a comprehensive list of regular expression patterns designed to detect SQL injection attempts. SQL injection is a common web application vulnerability that can compromise the security of your database. This file provides various patterns that can help in identifying potentially malicious SQL queries.

## Table of Contents

- [Usage](#usage)
- [Patterns](#patterns)
- [Contributing](#contributing)
- [License](#license)

## Usage

To use these patterns, include the `SQL_Injection_Patterns.py` file in your project and integrate it with your query validation logic. Below is an example of how you can use these patterns in Python to check for SQL injection attempts.

### Example in Python

```python
from SQL_Injection_Patterns import check_for_sql_injection

query1 = "SELECT * FROM users WHERE username = 'admin' -- AND password = 'password'"
if check_for_sql_injection(query1):
    print("Potential SQL injection detected in query1!")
else:
    print("Query1 seems safe.")

query2 = "INSERT INTO logins (username, password) VALUES ('user', 'pass1234')"
if check_for_sql_injection(query2):
    print("Potential SQL injection detected in query2!")
else:
    print("Query2 seems safe.")

query3 = "UPDATE accounts SET balance = 10000 WHERE account_id = 1; DROP TABLE transactions;"
if check_for_sql_injection(query3):
    print("Potential SQL injection detected in query3!")
else:
    print("Query3 seems safe.")
```

### Example in JavaScript
```javascript
const userQuery = "SELECT * FROM users WHERE username='admin' OR 1=1 --' AND password='password'";
console.log(checkForSQLInjection(userQuery)); // true
```

### Example in TypeScript
```typescript
const userQuery: string = "SELECT * FROM users WHERE username='admin' OR 1=1 --' AND password='password'";
console.log(checkForSQLInjection(userQuery));  // true
```

### Example in Rust
```rust
fn main() {
    let user_query = "SELECT * FROM users WHERE username='admin' OR 1=1 --' AND password='password'";
    println!("{}", check_for_sql_injection(user_query));  // true
}
```

### Example in Go
```go
func main() {
    userQuery := "SELECT * FROM users WHERE username='admin' OR 1=1 --' AND password='password'"
    fmt.Println(checkForSQLInjection(userQuery))  // true
}
```


## Patterns

The `SQL_Injection_Patterns.py` file contains the following types of patterns:

- **Logical Operators**: Detects usage of `OR` and `AND` with potential malicious conditions.
- **Union/Select Statements**: Identifies suspicious `UNION` and `SELECT` statements.
- **Comments**: Looks for SQL comment sequences like `--` and `/*`.
- **DDL Commands**: Detects dangerous commands such as `DROP`, `INSERT`, `UPDATE`, `DELETE`, and `ALTER`.
- **Execution Commands**: Identifies execution commands like `exec`.
- **Delay Functions**: Detects usage of functions that introduce delays, such as `WAITFOR`, `DELAY`, and `SLEEP`.
- **Privilege Changes**: Detects commands related to privilege changes like `GRANT`.
- **Function Calls**: Identifies suspicious function calls like `char(`, `convert(`, and `cast(`.

## Contributing

We welcome contributions to enhance the detection capabilities of these patterns. To contribute:

1. Fork the repository.
2. Create a new branch: `git checkout -b feature-branch`.
3. Make your changes and commit them: `git commit -m 'Add new SQL injection pattern'`.
4. Push to the branch: `git push origin feature-branch`.
5. Submit a pull request.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

---

By using these patterns, you can enhance the security of your web applications and protect your databases from SQL injection attacks. Always ensure to keep your security measures up to date and regularly review your code for potential vulnerabilities.
