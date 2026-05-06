# Secure Task Management Web Application

## Overview
This project is a **Task Management Web Application** developed to demonstrate secure software design principles. The system is implemented in two versions:

- **Vulnerable Version** → Contains intentionally introduced security vulnerabilities for demonstration purposes  
- **Fixed Version** → Secure implementation with all vulnerabilities mitigated using best practices in secure coding

The goal of this project is to understand common web application security flaws, demonstrate how they can be exploited, and apply proper fixes to prevent them.

---

## ⚙️ Project Structure

vulnerable/ → Insecure version of the application (with vulnerabilities)  
fixed/ → Secure version of the application (with fixes applied)  
tests/ → Automated test scripts for verifying vulnerabilities and fixes

---

## Security Vulnerabilities Implemented

### 1. SQL Injection (Search Function)
- **Issue:** User input is directly used in database queries without proper sanitization
- **Impact:** Attackers can manipulate queries to access unauthorized data
- **Fix:** Implemented parameterized queries to prevent query manipulation

---

### 2. Cross-Site Scripting (XSS)
- **Issue:** User input is rendered directly in the task display without sanitization
- **Impact:** Malicious scripts can execute in the browser when viewing tasks
- **Fix:** Input sanitization and output encoding implemented to prevent script execution

---

### 3. Insecure Direct Object Reference (IDOR)
- **Issue:** No ownership validation when accessing or modifying tasks
- **Impact:** Users can access or modify tasks belonging to other users
- **Fix:** Added proper authorization checks to ensure users can only access their own data

---

## Automated Testing
The project includes automated test scripts that:
- Fail when executed against the **vulnerable version**
- Pass when executed against the **fixed version**

This ensures that all vulnerabilities are properly demonstrated and then successfully mitigated.

---


## Technologies Used
- Backend: Python / Flask 
- Frontend: HTML, CSS, JavaScript
- Security Concepts: OWASP Top 10
- Testing: Automated test scripts (Python / pytest)

---

## Learning Outcomes
- Understanding real-world web application vulnerabilities
- Hands-on experience with secure coding practices
- Implementation of authentication and authorization controls
- Writing automated security validation tests

---
