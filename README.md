# BuggedCart 🛒 — OWASP Top 10 Training App

BuggedCart is an intentionally vulnerable full-stack web application built with **Flask** and **SQLite** to support hands-on learning of web security and **ethical hacking**. Inspired by the learning style of vulnerable training labs (DVWA-like practice), the project provides a clean set of OWASP Top 10 scenarios in a controlled environment.

I designed BuggedCart as a problem-solving exercise from end to end: building a functional e-commerce workflow (routes, templates, data layer, and basic authentication) and then intentionally implementing common security mistakes to demonstrate *how attacks actually work*. Each lab includes a **patched vs unpatched** mode so learners can compare insecure behavior with the secure fix, understand root causes, and develop a defender mindset.

## How this project helps
- Practice OWASP Top 10 concepts with realistic web app flows (forms, sessions, database queries).
- Learn how attackers think by observing exploitation paths in **unpatched** mode.
- Learn remediation by switching to **patched** mode and reviewing the secure implementation.
- Ideal for building confidence in web security testing and secure coding in a safe, local lab.

> ⚠️ **Warning:** This project is intentionally insecure. Run only in an isolated environment for educational purposes.
