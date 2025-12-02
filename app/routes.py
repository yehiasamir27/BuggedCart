import os  
from flask import Blueprint, render_template, request, current_app
from . import db
from .models import Product
import sqlite3
import sys
import base64
import pickle

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
    """Vulnerability overview page (static)."""
    return render_template("vuln_overview.html")

# OWASP Top-10 teaching pages
@main.route('/vuln/a1-injection')
def vuln_a1():
    return render_template('owasp_a1_injection.html')

@main.route('/vuln/a1-sqli', methods=['GET', 'POST'])
def vuln_a1_sqli():
    q = request.args.get('q', '') if request.method == 'GET' else request.form.get('q', '')
    
    # Check for SQL injection patterns
    injection_detected = False
    injection_patterns = ["OR '1'='1'", "or '1'='1'", "OR 1=1", "or 1=1", 
                         "UNION", "union", "--", "#", "/*", "*/", "' OR", '" OR',
                         "' or", '" or', "OR '", "OR '", "or '", "or '"]
    
    for pattern in injection_patterns:
        if pattern.lower() in q.lower():
            injection_detected = True
            break
    
    if injection_detected:
        # Create fake products for demonstration
        fake_products = [
            (1, "iPhone 14 Pro", 999.99, "Latest smartphone from Apple"),
            (2, "MacBook Pro", 1999.99, "Professional laptop with M2 chip"),
            (3, "Samsung Galaxy S23", 799.99, "Android smartphone with triple camera"),
            (4, "iPad Air", 599.99, "Tablet for work and entertainment"),
            (5, "AirPods Pro", 249.99, "Wireless earbuds with noise cancellation"),
            (6, "Apple Watch Series 8", 399.99, "Smartwatch with health features"),
            (7, "Nike Air Max", 129.99, "Comfortable running shoes"),
            (8, "Adidas Hoodie", 69.99, "Warm cotton hoodie"),
            (9, "Sony WH-1000XM4", 349.99, "Wireless noise cancelling headphones"),
            (10, "Dell XPS 13", 1199.99, "Ultrabook laptop"),
            (11, "Banana", 0.99, "Fresh yellow fruit"),
            (12, "Apple", 1.29, "Crisp red fruit"),
            (13, "Orange", 1.19, "Citrus fruit rich in vitamin C"),
            (14, "Samsung TV 55\"", 699.99, "4K Smart TV"),
            (15, "Gaming Console", 499.99, "Next-gen gaming system")
        ]
        return render_template('owasp_a1_injection.html', products=fake_products, q=q, injection_detected=True)
    
    # Normal query execution
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    # VULNERABLE: direct string concatenation
    sql = "SELECT id, name, price, description FROM product WHERE name LIKE '%" + q + "%'"
    try:
        rows = cur.execute(sql).fetchall()
    except Exception as e:
        rows = []
    conn.close()
    return render_template('owasp_a1_injection.html', products=rows, q=q, injection_detected=False)

@main.route('/vuln/a2-authentication')
def vuln_a2():
    return render_template('owasp_a2_authentication.html')

@main.route('/vuln/a2-create-user', methods=['GET'])
def vuln_a2_create_user():
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    # create table if not exists (id, username, password plaintext)
    cur.execute("CREATE TABLE IF NOT EXISTS user_vuln (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    # insert / replace demo user (plaintext)
    cur.execute("INSERT OR REPLACE INTO user_vuln (id, username, password) VALUES (1, 'admin', 'password123')")
    conn.commit()
    conn.close()
    return "Created demo user: admin / password123 (stored plaintext)"

@main.route('/vuln/a2-login', methods=['GET','POST'])
def vuln_a2_login():
    err = None
    if request.method == 'POST':
        u = request.form.get('username', '')
        p = request.form.get('password', '')
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        user = c.execute(f"SELECT * FROM user_vuln WHERE username='{u}' AND password='{p}'").fetchone()
        conn.close()
        if user:
            return f"Logged in as {user[1]}"
        err = "Invalid"
    return render_template('owasp_a2_authentication.html', error=err)

@main.route('/vuln/a3-sensitive-data')
def vuln_a3():
    return render_template('owasp_a3_sensitive_data.html')

@main.route('/vuln/a3-config', methods=['GET'])
def vuln_a3_config():
    # Get the real database path
    import os
    db_path = os.path.abspath('database.db')
    # Also expose some fake sensitive environment variables for demonstration
    secret_key = "SECRET_KEY_EXPOSED"  # This simulates exposing sensitive config
    db_password = "admin123"  # This simulates exposing database credentials
    return render_template('owasp_a3_sensitive_data.html', 
                          db_path=db_path, 
                          secret_key=secret_key, 
                          db_password=db_password)

@main.route('/vuln/a4-xxe')
def vuln_a4():
    return render_template('owasp_a4_xml_external_entities.html')

import xml.etree.ElementTree as ET

@main.route('/vuln/a4-xml', methods=['GET','POST'])
def vuln_a4_xxe():
    result = None
    if request.method == 'POST':
        xm = request.form.get('xml', '')
        # VULNERABLE pattern: naive parse of user XML
        try:
            root = ET.fromstring(xm)
            result = ET.tostring(root, encoding='unicode')[:1000]
        except Exception as e:
            result = f"Parse error: {e}"
    return render_template('owasp_a4_xml_external_entities.html', result=result)

@main.route('/vuln/a5-access-control')
def vuln_a5():
    return render_template('owasp_a5_access_control.html')

@main.route('/vuln/a5-delete-demo')
def vuln_a5_demo():
    # lists delete links that any user can call
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    items = c.execute("SELECT id, name FROM product").fetchall()
    conn.close()
    return render_template('owasp_a5_access_control.html', items=items)

@main.route('/vuln/a6-misconfig')
def vuln_a6():
    return render_template('owasp_a6_security_misconfig.html')

@main.route('/vuln/a6-misconfig-info', methods=['GET'])
def vuln_a6_misconfig():
    pyver = sys.version
    flask_debug = current_app.debug
    return render_template('owasp_a6_security_misconfig.html', pyver=pyver, debug=flask_debug)

@main.route('/vuln/a7-xss')
def vuln_a7():
    user_input = request.args.get('input', '')
    return render_template('owasp_a7_xss.html', user_input=user_input)

@main.route('/vuln/a8-deserialization')
def vuln_a8():
    return render_template('owasp_a8_deserialization.html')

@main.route('/vuln/a8-deserialize', methods=['GET','POST'])
def vuln_a8_deserialize():
    out = None
    if request.method == 'POST':
        b64 = request.form.get('p', '')
        try:
            raw = base64.b64decode(b64)
            # VULNERABLE: insecure pickle.loads on user data
            obj = pickle.loads(raw)
            out = f"Loaded object type: {type(obj)}"
        except Exception as e:
            out = f"Error: {e}"
    return render_template('owasp_a8_deserialization.html', output=out)

@main.route('/vuln/a9-components')
def vuln_a9():
    try:
        with open('requirements.txt', 'r') as f:
            data = f.read()
    except:
        data = "requirements.txt missing"
    return render_template('owasp_a9_components.html', reqs=data)

@main.route('/vuln/a10-logging')
def vuln_a10():
    return render_template('owasp_a10_logging_and_monitoring.html')

@main.route('/vuln/a10-logging', methods=['GET','POST'])
def vuln_a10_logging():
    msg = None
    if request.method == 'POST':
        val = request.form.get('val', '')
        # VULNERABLE: logging sensitive data without redaction
        with open('app_debug.log', 'a') as fh:
            fh.write(f"USER_INPUT: {val}\n")
        msg = "Wrote to log"
    return render_template('owasp_a10_logging_and_monitoring.html', msg=msg)