# dbms-project
# Smart ATM Simulator & Bank Management System

A database-driven web application simulating core banking functionalities, including ATM operations, user account management, deposit tracking, and loan handling. Built using **Flask**, **MySQL**, and **SQLAlchemy**, this project serves as a practical DBMS implementation with features like stored procedures, triggers, and nested queries.

## 🛠 Features

- User registration and login system
- ATM PIN creation and secure access
- Deposit and withdrawal operations
- Account and balance management
- Transaction logging
- Loan application and approval process
- Triggers for automated updates on deposit closure
- Stored procedures and nested aggregate queries for insights

##  Technologies Used

- **Backend**: Python, Flask
- **Database**: MySQL with SQLAlchemy ORM
- **Frontend**: HTML, CSS (with Bootstrap)
- **Security**: Password and ATM PIN encryption

##  Database Schema Overview

### Tables:
- `user_info`: Stores personal and login information
- `transactions`: Logs all financial transactions
- `deposit`: Handles fixed deposit-related data
- `loans`: Stores loan applications and statuses
- `accounts`: Consolidated view of savings and deposits

### Triggers:
- `after_deposit_close`: Automatically moves matured deposit amount to the user’s savings and logs a transaction

### Stored Procedure:
```sql
CREATE PROCEDURE get_account_summary(IN user_id_param INT)
BEGIN
    SELECT * FROM accounts WHERE user_id = user_id_param;
END;
