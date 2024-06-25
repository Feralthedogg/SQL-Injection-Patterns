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
import re

def check_for_sql_injection(query):
    with open('SQL_Injection_Patterns.txt', 'r') as file:
        sql_injection_patterns = [line.strip() for line in file.readlines()]
    
    compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in sql_injection_patterns]

    for pattern in compiled_patterns:
        if pattern.search(query):
            return True

    return False

# Example usage
query = "SELECT * FROM users WHERE username = 'admin' -- AND password = 'password'"
if check_for_sql_injection(query):
    print("Potential SQL injection detected!")
else:
    print("Query seems safe.")
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
