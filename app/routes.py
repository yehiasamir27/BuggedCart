import os
import sys
import base64
import pickle
import html
import re
import sqlite3
import xml.etree.ElementTree as ET
from flask import Blueprint, render_template, request, current_app, session, redirect, url_for
from . import db
from .models import Product

main = Blueprint('main', __name__)

@main.route('/')
def home():
    query = request.args.get('search')
    if query:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        sql = f"SELECT * FROM product WHERE name LIKE '%{query}%'"
        products = cursor.execute(sql).fetchall()
        conn.close()
    else:
        products = Product.query.all()
    return render_template('home.html', products=products, query=query)

@main.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        sql = f"SELECT * FROM user WHERE username = '{username}' AND password = '{password}'"
        user = cursor.execute(sql).fetchone()
        conn.close()

        if user:
            return f"Logged in as {user[1]}"
        else:
            error = "Invalid credentials"

    return render_template('login.html', error=error)

@main.route('/product/<int:product_id>', methods=['GET', 'POST'])
def product_detail(product_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    if request.method == 'POST':
        comment = request.form.get('comment')
        cursor.execute("INSERT INTO review (user_id, product_id, comment) VALUES (?, ?, ?)", (1, product_id, comment))
        conn.commit()

    product = cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,)).fetchone()
    reviews = cursor.execute("SELECT comment FROM review WHERE product_id = ?", (product_id,)).fetchall()
    conn.close()

    return render_template('product.html', product=product, reviews=reviews)

@main.route('/admin/delete/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    conn.commit()
    conn.close()
    return "Product deleted Successfully(no CSRF token used!)"

@main.route('/admin/contact', methods=['GET', 'POST'])
def contact_admin():
    output = None
    if request.method == 'POST':
        email = request.form.get('email')
        message = request.form.get('message')
        command = f"echo '{message}' | mail -s 'Feedback' {email}"
        output = os.popen(command).read()

    return render_template('contact.html', output=output)

@main.route('/products')
def products_page():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, price, description FROM product")
    products = cursor.fetchall()
    conn.close()
    return render_template('products.html', products=products)

@main.route("/vulns")
def vulns_page():
    return render_template("vuln_overview.html")


# ========== A1 - SQL INJECTION ==========
@main.route('/vuln/a1-injection', methods=['GET', 'POST'])
def vuln_a1():
    patched = request.args.get('patched', 'false') == 'true'
    q = request.args.get('q', '') if request.method == 'GET' else request.form.get('q', '')
    result = None
    injection_detected = False
    products = []
    
    if q:
        conn = sqlite3.connect('database.db')
        cur = conn.cursor()
        
        if patched:
            # PATCHED: Using parameterized queries
            try:
                cur.execute("SELECT id, name, price, description FROM product WHERE name LIKE ?", (f'%{q}%',))
                products = cur.fetchall()
                result = "Query executed safely with parameterized query."
            except Exception as e:
                result = f"Error: {e}"
        else:
            # VULNERABLE: Direct string concatenation
            injection_patterns = ["' OR", "' or", "OR '1'='1'", "or '1'='1'", "OR 1=1", "or 1=1",
                                "UNION", "union", "--", "#", "/*", "*/", "' OR '", "\" OR"]
            for pattern in injection_patterns:
                if pattern.lower() in q.lower():
                    injection_detected = True
                    break
            
            if injection_detected:
                products = [
                    (1, "iPhone 14 Pro", 999.99, "Latest smartphone"),
                    (2, "MacBook Pro", 1999.99, "Professional laptop"),
                    (3, "Samsung Galaxy S23", 799.99, "Android smartphone"),
                    (4, "iPad Air", 599.99, "Tablet device"),
                    (5, "AirPods Pro", 249.99, "Wireless earbuds"),
                    (6, "Secret Admin User", 0.00, "username: admin, password: admin123"),
                    (7, "Credit Card Data", 0.00, "4532-xxxx-xxxx-1234"),
                ]
                result = f"SQL Injection Successful! Query: SELECT * FROM product WHERE name LIKE '%{q}%'"
            else:
                sql = "SELECT id, name, price, description FROM product WHERE name LIKE '%" + q + "%'"
                try:
                    products = cur.execute(sql).fetchall()
                except Exception as e:
                    result = f"SQL Error: {e}"
        conn.close()
    
    return render_template('owasp_a1_injection.html', products=products, q=q, patched=patched,
                          injection_detected=injection_detected, result=result)

@main.route('/vuln/a1-sqli', methods=['GET', 'POST'])
def vuln_a1_sqli():
    return redirect(url_for('main.vuln_a1', **request.args))


# ========== A2 - BROKEN AUTHENTICATION ==========
@main.route('/vuln/a2-authentication', methods=['GET', 'POST'])
def vuln_a2():
    patched = request.args.get('patched', 'false') == 'true'
    error = None
    success = None
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        conn = sqlite3.connect('database.db')
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS user_vuln (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
        cur.execute("INSERT OR REPLACE INTO user_vuln (id, username, password) VALUES (1, 'admin', 'password123')")
        conn.commit()
        
        if patched:
            # PATCHED: Using parameterized queries and would normally hash passwords
            cur.execute("SELECT * FROM user_vuln WHERE username = ? AND password = ?", (username, password))
            user = cur.fetchone()
            if user:
                success = f"Logged in as {user[1]} (Secure login with parameterized query)"
            else:
                error = "Invalid credentials (Attack blocked - parameterized query used)"
        else:
            # VULNERABLE: SQL injection in login
            sql = f"SELECT * FROM user_vuln WHERE username='{username}' AND password='{password}'"
            try:
                user = cur.execute(sql).fetchone()
                if user:
                    success = f"Logged in as {user[1]} (Vulnerable login)"
                else:
                    error = "Invalid credentials"
            except Exception as e:
                error = f"SQL Error: {e}"
        conn.close()
    
    return render_template('owasp_a2_authentication.html', error=error, success=success, patched=patched)

@main.route('/vuln/a2-create-user', methods=['GET'])
def vuln_a2_create_user():
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS user_vuln (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    cur.execute("INSERT OR REPLACE INTO user_vuln (id, username, password) VALUES (1, 'admin', 'password123')")
    conn.commit()
    conn.close()
    return "Created demo user: admin / password123 (stored plaintext)"

@main.route('/vuln/a2-login', methods=['GET','POST'])
def vuln_a2_login():
    return redirect(url_for('main.vuln_a2'))


# ========== A3 - SENSITIVE DATA EXPOSURE ==========
@main.route('/vuln/a3-sensitive-data', methods=['GET', 'POST'])
def vuln_a3():
    patched = request.args.get('patched', 'false') == 'true'
    exposed_data = None
    
    if request.method == 'POST' or request.args.get('reveal') == 'true':
        if patched:
            exposed_data = {
                'db_path': '[REDACTED - Access Denied]',
                'secret_key': '[REDACTED - Access Denied]',
                'db_password': '[REDACTED - Access Denied]',
                'api_key': '[REDACTED - Access Denied]',
                'message': 'Sensitive data properly protected. Access logging enabled.'
            }
        else:
            exposed_data = {
                'db_path': os.path.abspath('database.db'),
                'secret_key': 'SECRET_KEY_EXPOSED_th1s_1s_v3ry_s3cr3t',
                'db_password': 'admin123_super_secret',
                'api_key': 'sk-proj-FAKE_API_KEY_12345abcdef',
                'message': 'All sensitive data exposed! This is dangerous!'
            }
    
    return render_template('owasp_a3_sensitive_data.html', exposed_data=exposed_data, patched=patched)

@main.route('/vuln/a3-config', methods=['GET'])
def vuln_a3_config():
    return redirect(url_for('main.vuln_a3', reveal='true'))


# ========== A4 - XXE ==========
@main.route('/vuln/a4-xxe', methods=['GET', 'POST'])
def vuln_a4():
    patched = request.args.get('patched', 'false') == 'true'
    result = None
    xxe_detected = False
    
    if request.method == 'POST':
        xml_data = request.form.get('xml', '')
        
        if patched:
            # PATCHED: Check for XXE patterns and block
            dangerous_patterns = ['<!ENTITY', '<!DOCTYPE', 'SYSTEM', 'file://', 'http://', 'https://']
            for pattern in dangerous_patterns:
                if pattern.lower() in xml_data.lower():
                    xxe_detected = True
                    result = f"XXE Attack Blocked! Dangerous pattern detected: {pattern}"
                    break
            
            if not xxe_detected:
                try:
                    root = ET.fromstring(xml_data)
                    result = f"XML parsed safely: {ET.tostring(root, encoding='unicode')[:500]}"
                except Exception as e:
                    result = f"Parse error: {e}"
        else:
            # VULNERABLE: Parse without checking
            xxe_patterns = ['<!ENTITY', '<!DOCTYPE', 'SYSTEM', 'file://']
            for pattern in xxe_patterns:
                if pattern in xml_data:
                    xxe_detected = True
                    if 'file://' in xml_data or '/etc/passwd' in xml_data:
                        result = "XXE Successful! File content: root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin\n..."
                    else:
                        result = f"XXE payload detected and executed (simulated): {xml_data[:200]}"
                    break
            
            if not xxe_detected:
                try:
                    root = ET.fromstring(xml_data)
                    result = ET.tostring(root, encoding='unicode')[:1000]
                except Exception as e:
                    result = f"Parse error: {e}"
    
    return render_template('owasp_a4_xml_external_entities.html', result=result, patched=patched, xxe_detected=xxe_detected)

@main.route('/vuln/a4-xml', methods=['GET','POST'])
def vuln_a4_xxe_legacy():
    return redirect(url_for('main.vuln_a4'))


# ========== A5 - BROKEN ACCESS CONTROL ==========
@main.route('/vuln/a5-access-control', methods=['GET', 'POST'])
def vuln_a5():
    patched = request.args.get('patched', 'false') == 'true'
    message = None
    items = []
    
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    items = cur.execute("SELECT id, name FROM product").fetchall()
    
    if request.method == 'POST':
        product_id = request.form.get('product_id')
        
        if patched:
            # PATCHED: Require authentication
            message = "Access Denied! You must be logged in as admin to delete products. (Protected)"
        else:
            # VULNERABLE: No authentication check
            cur.execute("DELETE FROM product WHERE id = ?", (product_id,))
            conn.commit()
            message = f"Product {product_id} deleted without authentication! (Vulnerable)"
            items = cur.execute("SELECT id, name FROM product").fetchall()
    
    conn.close()
    return render_template('owasp_a5_access_control.html', items=items, patched=patched, message=message)

@main.route('/vuln/a5-delete-demo')
def vuln_a5_demo():
    return redirect(url_for('main.vuln_a5'))


# ========== A6 - SECURITY MISCONFIGURATION ==========
@main.route('/vuln/a6-misconfig', methods=['GET', 'POST'])
def vuln_a6():
    patched = request.args.get('patched', 'false') == 'true'
    info = None
    
    if request.method == 'POST' or request.args.get('reveal') == 'true':
        if patched:
            info = {
                'python_version': '[Hidden for security]',
                'flask_debug': '[Hidden for security]',
                'server_info': '[Hidden for security]',
                'db_info': '[Hidden for security]',
                'message': 'Server information properly hidden in production.'
            }
        else:
            info = {
                'python_version': sys.version,
                'flask_debug': str(current_app.debug),
                'server_info': f"Flask {current_app.name}",
                'db_info': 'SQLite 3.x - database.db',
                'message': 'All server configuration exposed! Attackers can use this for reconnaissance.'
            }
    
    return render_template('owasp_a6_security_misconfig.html', info=info, patched=patched)

@main.route('/vuln/a6-misconfig-info', methods=['GET'])
def vuln_a6_misconfig():
    return redirect(url_for('main.vuln_a6', reveal='true'))


# ========== A7 - XSS ==========
@main.route('/vuln/a7-xss', methods=['GET', 'POST'])
def vuln_a7():
    patched = request.args.get('patched', 'false') == 'true'
    user_input = ''
    rendered_output = ''
    xss_detected = False
    
    if request.method == 'POST':
        user_input = request.form.get('input', '')
    else:
        user_input = request.args.get('input', '')
    
    if user_input:
        xss_patterns = ['<script', 'javascript:', 'onerror', 'onload', 'onclick', '<img', '<svg', 'alert(']
        for pattern in xss_patterns:
            if pattern.lower() in user_input.lower():
                xss_detected = True
                break
        
        if patched:
            # PATCHED: Escape all HTML
            rendered_output = html.escape(user_input)
            if xss_detected:
                rendered_output = f"[XSS Blocked] Sanitized output: {rendered_output}"
        else:
            # VULNERABLE: Render as-is
            rendered_output = user_input
            if xss_detected:
                rendered_output = f"XSS Payload Executed: {user_input}"
    
    return render_template('owasp_a7_xss.html', user_input=user_input, rendered_output=rendered_output,
                          patched=patched, xss_detected=xss_detected)


# ========== A8 - INSECURE DESERIALIZATION ==========
@main.route('/vuln/a8-deserialization', methods=['GET', 'POST'])
def vuln_a8():
    patched = request.args.get('patched', 'false') == 'true'
    output = None
    dangerous_detected = False
    
    if request.method == 'POST':
        b64_data = request.form.get('payload', '')
        
        if patched:
            # PATCHED: Reject pickle data, only allow JSON
            output = "Deserialization Blocked! Pickle is disabled for security. Use JSON instead."
            dangerous_detected = True
        else:
            # VULNERABLE: Unpickle user data
            try:
                raw = base64.b64decode(b64_data)
                # Check for dangerous patterns
                if b'cos\n' in raw or b'system' in raw or b'eval' in raw or b'exec' in raw:
                    dangerous_detected = True
                    output = f"Dangerous payload executed! (Simulated RCE)\nDecoded bytes contained: {raw[:100]}"
                else:
                    obj = pickle.loads(raw)
                    output = f"Object unpickled successfully!\nType: {type(obj)}\nValue: {obj}"
            except Exception as e:
                output = f"Deserialization error: {e}"
    
    return render_template('owasp_a8_deserialization.html', output=output, patched=patched,
                          dangerous_detected=dangerous_detected)

@main.route('/vuln/a8-deserialize', methods=['GET','POST'])
def vuln_a8_deserialize_legacy():
    return redirect(url_for('main.vuln_a8'))


# ========== A9 - VULNERABLE COMPONENTS ==========
@main.route('/vuln/a9-components', methods=['GET', 'POST'])
def vuln_a9():
    patched = request.args.get('patched', 'false') == 'true'
    
    vulnerable_deps = """# VULNERABLE DEPENDENCIES (OLD VERSIONS)
Flask==1.0.2           # CVE-2019-1010083 - DoS vulnerability
Jinja2==2.10           # CVE-2019-10906 - Sandbox escape
Werkzeug==0.15.0       # CVE-2019-14806 - Path traversal
SQLAlchemy==1.2.0      # Multiple SQL injection risks
requests==2.19.0       # CVE-2018-18074 - Information disclosure
urllib3==1.23          # CVE-2019-11324 - CRLF injection
cryptography==2.3      # Multiple CVEs - weak crypto
"""
    
    safe_deps = """# SECURE DEPENDENCIES (LATEST PATCHED VERSIONS)
Flask==3.1.1           # Latest stable, all CVEs patched
Jinja2==3.1.6          # Latest with security fixes
Werkzeug==3.1.3        # Latest secure version
SQLAlchemy==2.0.41     # Latest with security improvements
requests==2.31.0       # All known CVEs patched
urllib3==2.1.0         # Latest secure version
cryptography==41.0.0   # Modern crypto, CVEs addressed
"""
    
    if patched:
        reqs = safe_deps
        message = "Using latest patched versions - No known vulnerabilities!"
    else:
        reqs = vulnerable_deps
        message = "Using outdated vulnerable versions - Multiple CVEs present!"
    
    return render_template('owasp_a9_components.html', reqs=reqs, patched=patched, message=message)


# ========== A10 - LOGGING FAILURES ==========
@main.route('/vuln/a10-logging', methods=['GET', 'POST'])
def vuln_a10():
    patched = request.args.get('patched', 'false') == 'true'
    log_output = None
    log_entry = None
    
    if request.method == 'POST':
        user_data = request.form.get('data', '')
        
        if patched:
            # PATCHED: Redact sensitive info before logging
            redacted = re.sub(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', '[CARD REDACTED]', user_data)
            redacted = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL REDACTED]', redacted)
            redacted = re.sub(r'password["\']?\s*[:=]\s*["\']?[^"\'\s]+', 'password: [REDACTED]', redacted, flags=re.IGNORECASE)
            
            log_entry = f"[SECURED] User input (redacted): {redacted}"
            log_output = "Sensitive data redacted before logging. Security best practice applied!"
        else:
            # VULNERABLE: Log everything including sensitive data
            log_entry = f"[VULNERABLE] Raw user input logged: {user_data}"
            with open('app_debug.log', 'a') as f:
                f.write(f"{log_entry}\n")
            log_output = f"Logged raw data (including sensitive info!): {user_data}"
    
    return render_template('owasp_a10_logging_and_monitoring.html', log_output=log_output,
                          log_entry=log_entry, patched=patched)
