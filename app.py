import streamlit as st
import sqlite3
import pandas as pd
import re
import json
import io
import smtplib, ssl
from email.message import EmailMessage
from datetime import datetime, date, timedelta
import hashlib, secrets, hmac

# ----------------- Config -----------------
st.set_page_config(page_title="LNMIIT Item Issue Form", page_icon="🎓", layout="wide")

ADMIN_EMAIL = st.secrets.get("admin", {}).get("email", "smaheshwari@lnmiit.ac.in")
ADMIN_INITIAL_PASSWORD = st.secrets.get("admin", {}).get("initial_password", "ChangeMe@123!")

SMTP_CONF = {
    "host": st.secrets.get("smtp", {}).get("host"),
    "port": st.secrets.get("smtp", {}).get("port", 587),
    "user": st.secrets.get("smtp", {}).get("user"),
    "password": st.secrets.get("smtp", {}).get("password"),
    "use_tls": st.secrets.get("smtp", {}).get("use_tls", True),
    "send_to": st.secrets.get("smtp", {}).get("send_to", ADMIN_EMAIL),
}

# --------------- Styling ------------------
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        padding: 1rem; border-radius: 10px; margin-bottom: 1rem; color: white;
    }
</style>
""", unsafe_allow_html=True)

# --------------- DB Helpers ----------------
def get_conn():
    return sqlite3.connect('lnmiit_forms.db', detect_types=sqlite3.PARSE_DECLTYPES)

def add_column_if_missing(conn, table, column, coldef):
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    cols = [r[1] for r in cur.fetchall()]
    if column not in cols:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coldef}")
        conn.commit()

def init_database():
    conn = get_conn()
    cur = conn.cursor()

    # Users table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            name TEXT,
            user_type TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # New cols
    add_column_if_missing(conn, "users", "password_hash", "TEXT")
    add_column_if_missing(conn, "users", "salt", "TEXT")
    add_column_if_missing(conn, "users", "is_admin", "INTEGER DEFAULT 0")
    add_column_if_missing(conn, "users", "reset_code", "TEXT")
    add_column_if_missing(conn, "users", "reset_expires", "TIMESTAMP")

    # Forms table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS form_submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT,
            name TEXT,
            user_type TEXT,
            user_id TEXT,
            department TEXT,
            instructor_name TEXT,
            mobile TEXT,
            issue_date TEXT,
            return_date TEXT,
            items TEXT,
            submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # Add workflow columns
    add_column_if_missing(conn, "form_submissions", "status", "TEXT DEFAULT 'pending'")
    add_column_if_missing(conn, "form_submissions", "admin_comment", "TEXT")
    add_column_if_missing(conn, "form_submissions", "reviewed_at", "TIMESTAMP")
    add_column_if_missing(conn, "form_submissions", "approved_by", "TEXT")

    # Inventory table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            quantity INTEGER DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()

    ensure_admin_user(conn)
    conn.close()

def ensure_admin_user(conn):
    cur = conn.cursor()
    cur.execute("SELECT id, password_hash, salt FROM users WHERE email = ?", (ADMIN_EMAIL,))
    row = cur.fetchone()
    if row is None or row[1] is None or row[2] is None:
        salt, pwd_hash = hash_password(ADMIN_INITIAL_PASSWORD)
        if row is None:
            cur.execute('''
                INSERT INTO users (email, name, user_type, password_hash, salt, is_admin)
                VALUES (?, ?, ?, ?, ?, 1)
            ''', (ADMIN_EMAIL, "Admin", "admin", pwd_hash, salt))
        else:
            cur.execute('''
                UPDATE users SET password_hash=?, salt=?, is_admin=1, user_type='admin', name='Admin'
                WHERE email=?
            ''', (pwd_hash, salt, ADMIN_EMAIL))
        conn.commit()

# --------------- Password Security ---------------
def hash_password(password: str, salt: str | None = None):
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt), 200_000)
    return salt, dk.hex()

def verify_password(password: str, salt: str, stored_hash_hex: str):
    calc = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt), 200_000).hex()
    return hmac.compare_digest(calc, stored_hash_hex)

# --------------- Email ----------------
def send_email(to_email, subject, body):
    if not SMTP_CONF["host"] or not SMTP_CONF["user"] or not SMTP_CONF["password"]:
        print("Email skipped (SMTP not configured):", subject)
        return False

    msg = EmailMessage()
    msg["From"] = SMTP_CONF["user"]
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        if SMTP_CONF["use_tls"]:
            context = ssl.create_default_context()
            with smtplib.SMTP(SMTP_CONF["host"], SMTP_CONF["port"]) as server:
                server.starttls(context=context)
                server.login(SMTP_CONF["user"], SMTP_CONF["password"])
                server.send_message(msg)
        else:
            with smtplib.SMTP_SSL(SMTP_CONF["host"], SMTP_CONF["port"]) as server:
                server.login(SMTP_CONF["user"], SMTP_CONF["password"])
                server.send_message(msg)
        return True
    except Exception as e:
        st.warning(f"Email send failed: {e}")
        return False

def notify_admin_submission(form_data):
    subject = f"New Item Issue Request: {form_data['name']} ({form_data['user_type']})"
    items_text = "\n".join([f"- {it['name']} x {it['quantity']}" for it in form_data['items']])
    body = f"""
A new form has been submitted.

Name: {form_data['name']}
Email: {form_data['email']}
User Type: {form_data['user_type']}
ID: {form_data['user_id']}
Department: {form_data['department']}
Instructor: {form_data['instructor_name'] or '-'}

Mobile: {form_data['mobile']}
Issue Date: {form_data['issue_date']}
Return Date: {form_data['return_date']}

Items:
{items_text}

Please log in to the admin panel to approve or reject.
Submitted at: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""
    send_email(SMTP_CONF["send_to"], subject, body)

def notify_user_decision(user_email, decision, comment, items):
    subject = f"Your Item Issue Request: {decision.capitalize()}"
    items_text = "\n".join([f"- {it['name']} x {it['quantity']}" for it in items])
    body = f"""
Your request has been {decision}.

Items:
{items_text}

Comment: {comment or '-'}

Regards,
LNMIIT Lab
"""
    send_email(user_email, subject, body)

# --------------- DB Ops (Users/Auth) ---------------
def validate_lnmiit_email(email):
    return re.match(r'^[a-zA-Z0-9._%+-]+@lnmiit\.ac\.in$', email or "") is not None

def get_user(email):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT email, name, user_type, password_hash, salt, is_admin FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "email": row[0], "name": row[1], "user_type": row[2],
        "password_hash": row[3], "salt": row[4], "is_admin": bool(row[5])
    }

def register_user(email, name, user_type, password):
    if not validate_lnmiit_email(email):
        raise ValueError("Only @lnmiit.ac.in email is allowed")
    if email.lower() == ADMIN_EMAIL.lower():
        raise ValueError("This email is reserved for Admin.")
    salt, pwd_hash = hash_password(password)
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO users (email, name, user_type, password_hash, salt, is_admin) VALUES (?, ?, ?, ?, ?, 0)",
                (email, name, user_type, pwd_hash, salt))
    conn.commit(); conn.close()

def authenticate(email, password):
    u = get_user(email)
    if not u or not u["password_hash"] or not u["salt"]:
        return False, None
    ok = verify_password(password, u["salt"], u["password_hash"])
    return (ok, u if ok else None)

def set_reset_code(email):
    code = f"{secrets.randbelow(1_000_000):06d}"
    expires = datetime.now() + timedelta(minutes=15)
    conn = get_conn(); cur = conn.cursor()
    cur.execute("UPDATE users SET reset_code=?, reset_expires=? WHERE email=?", (code, expires, email))
    conn.commit(); conn.close()
    return code

def reset_password(email, code, new_password):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT reset_code, reset_expires FROM users WHERE email=?", (email,))
    row = cur.fetchone()
    if not row or not row[0] or not row[1]:
        conn.close(); return False, "No reset request found."
    saved_code, expires = row
    try:
        exp_dt = pd.to_datetime(expires)
    except:
        exp_dt = datetime.now() - timedelta(seconds=1)
    if code != saved_code:
        conn.close(); return False, "Invalid code."
    if datetime.now() > exp_dt:
        conn.close(); return False, "Code expired."
    salt, pwd_hash = hash_password(new_password)
    cur.execute("UPDATE users SET password_hash=?, salt=?, reset_code=NULL, reset_expires=NULL WHERE email=?",
                (pwd_hash, salt, email))
    conn.commit(); conn.close()
    return True, "Password updated successfully."

# --------------- DB Ops (Forms & Inventory) ---------------
def save_form_submission(form_data):
    conn = get_conn(); cur = conn.cursor()
    items_json = json.dumps(form_data['items'])
    cur.execute('''
        INSERT INTO form_submissions 
        (user_email, name, user_type, user_id, department, instructor_name, mobile, issue_date, return_date, items, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
    ''', (form_data['email'], form_data['name'], form_data['user_type'], form_data['user_id'],
          form_data['department'], form_data['instructor_name'], form_data['mobile'],
          form_data['issue_date'], form_data['return_date'], items_json))
    conn.commit(); conn.close()

def get_all_submissions():
    conn = get_conn()
    df = pd.read_sql_query('SELECT * FROM form_submissions ORDER BY submitted_at DESC', conn)
    conn.close()
    return df

def get_submission(sid: int):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT * FROM form_submissions WHERE id=?", (sid,))
    row = cur.fetchone()
    cols = [d[0] for d in cur.description] if cur.description else []
    conn.close()
    if not row: return None
    rec = dict(zip(cols, row))
    try:
        rec['items'] = json.loads(rec['items']) if rec.get('items') else []
    except:
        rec['items'] = []
    return rec

def inv_get_all():
    conn = get_conn()
    df = pd.read_sql_query('SELECT id, name, quantity, updated_at FROM inventory ORDER BY name ASC', conn)
    conn.close()
    return df

def inv_get_qty(name: str) -> int:
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT quantity FROM inventory WHERE lower(name)=lower(?)", (name,))
    row = cur.fetchone()
    conn.close()
    return int(row[0]) if row else 0

def inv_upsert_set(name: str, qty: int):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT id FROM inventory WHERE lower(name)=lower(?)", (name,))
    row = cur.fetchone()
    if row:
        cur.execute("UPDATE inventory SET quantity=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", (qty, row[0]))
    else:
        cur.execute("INSERT INTO inventory (name, quantity) VALUES (?, ?)", (name, max(0, qty)))
    conn.commit(); conn.close()

def inv_adjust(name: str, delta: int):
    current = inv_get_qty(name)
    inv_upsert_set(name, max(0, current + delta))

def check_availability(items):
    # items: [{'name':..., 'quantity':...}]
    shortages = []
    for it in items:
        req = int(it.get('quantity', 0) or 0)
        if req <= 0: continue
        avail = inv_get_qty(it['name'])
        if avail < req:
            shortages.append({"name": it['name'], "requested": req, "available": avail})
    return len(shortages) == 0, shortages

def decrement_inventory(items):
    for it in items:
        qty = int(it.get('quantity', 0) or 0)
        if qty <= 0: continue
        inv_adjust(it['name'], -qty)

def mark_submission(sid: int, status: str, admin_email: str, comment: str = ""):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("""
        UPDATE form_submissions
        SET status=?, admin_comment=?, reviewed_at=CURRENT_TIMESTAMP, approved_by=?
        WHERE id=?
    """, (status, comment, admin_email, sid))
    conn.commit(); conn.close()

# --------------- Auth UI ---------------
def auth_ui():
    if "auth_mode" not in st.session_state:
        st.session_state.auth_mode = "login"
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False

    st.markdown('<div class="main-header">', unsafe_allow_html=True)
    st.markdown("## 🎓 The LNM Institute of Information Technology")
    st.markdown("### 🔐 Account Access")
    st.markdown('</div>', unsafe_allow_html=True)

    mode = st.session_state.auth_mode

    if mode == "login":
        with st.form("login_form"):
            email = st.text_input("Email", placeholder="username@lnmiit.ac.in")
            password = st.text_input("Password", type="password")
            c1, c2, c3 = st.columns(3)
            with c1:
                submitted = st.form_submit_button("Login", type="primary")
            with c2:
                if st.form_submit_button("Register"):
                    st.session_state.auth_mode = "register"; st.rerun()
            with c3:
                if st.form_submit_button("Forgot password"):
                    st.session_state.auth_mode = "forgot"; st.rerun()

            if submitted:
                ok, user = authenticate(email, password)
                if ok:
                    st.session_state.authenticated = True
                    st.session_state.user_email = user["email"]
                    st.session_state.user_name = user["name"]
                    st.session_state.user_type = user["user_type"]
                    st.session_state.is_admin = user["is_admin"]
                    st.success("Login successful!")
                    st.rerun()
                else:
                    st.error("Invalid email or password")

    elif mode == "register":
        with st.form("register_form"):
            st.info("Only @lnmiit.ac.in emails are allowed to register.")
            name = st.text_input("Full Name")
            email = st.text_input("LNMIIT Email", placeholder="username@lnmiit.ac.in")
            user_type = st.selectbox("User Type", ["student", "faculty", "staff"])
            pwd = st.text_input("Password", type="password")
            cpwd = st.text_input("Confirm Password", type="password")
            c1, c2 = st.columns(2)
            with c1:
                reg = st.form_submit_button("Create account", type="primary")
            with c2:
                back = st.form_submit_button("Back to login")

            if back:
                st.session_state.auth_mode = "login"; st.rerun()

            if reg:
                try:
                    if not name or not email or not pwd:
                        st.error("All fields are required.")
                    elif not validate_lnmiit_email(email):
                        st.error("Please use a valid LNMIIT email (@lnmiit.ac.in).")
                    elif pwd != cpwd:
                        st.error("Passwords do not match.")
                    elif len(pwd) < 8:
                        st.error("Password must be at least 8 characters.")
                    else:
                        register_user(email, name, user_type, pwd)
                        st.success("Account created! You can login now.")
                        st.session_state.auth_mode = "login"; st.rerun()
                except sqlite3.IntegrityError:
                    st.error("This email is already registered.")
                except Exception as e:
                    st.error(str(e))

    elif mode == "forgot":
        with st.form("forgot_form"):
            email = st.text_input("Enter your registered LNMIIT email")
            c1, c2 = st.columns(2)
            with c1:
                send = st.form_submit_button("Send reset code", type="primary")
            with c2:
                back = st.form_submit_button("Back to login")
            if back:
                st.session_state.auth_mode = "login"; st.rerun()
            if send:
                if not validate_lnmiit_email(email):
                    st.error("Please enter a valid LNMIIT email.")
                elif not get_user(email):
                    st.error("No account found with this email.")
                else:
                    code = set_reset_code(email)
                    send_email(email, "LNMIIT Account Password Reset Code",
                               f"Your reset code is: {code}\nIt will expire in 15 minutes.")
                    st.session_state.reset_email = email
                    st.session_state.auth_mode = "reset"
                    st.success("Reset code sent to your email (check inbox/spam).")
                    st.rerun()

    elif mode == "reset":
        with st.form("reset_form"):
            email = st.text_input("Email", value=st.session_state.get("reset_email", ""))
            code = st.text_input("Reset code", placeholder="6-digit code from email")
            new_pwd = st.text_input("New password", type="password")
            c1, c2 = st.columns(2)
            with c1:
                do = st.form_submit_button("Reset password", type="primary")
            with c2:
                back = st.form_submit_button("Back to login")
            if back:
                st.session_state.auth_mode = "login"; st.rerun()
            if do:
                ok, msg = reset_password(email, code, new_pwd)
                if ok:
                    st.success(msg)
                    st.session_state.auth_mode = "login"; st.rerun()
                else:
                    st.error(msg)

# --------------- App UI (User) ---------------
def show_main_form():
    st.markdown('<div class="main-header"><h3>LNMIIT Item Issue Form</h3></div>', unsafe_allow_html=True)
    st.write(f"Welcome, {st.session_state.user_name} ({st.session_state.user_email})")

    if st.button("Logout"):
        for k in list(st.session_state.keys()):
            del st.session_state[k]
        st.rerun()

    # Inventory-based items list
    inv_df = inv_get_all()
    available_items = inv_df['name'].tolist() if not inv_df.empty else [
        'Laptop','Projector','HDMI Cable','Extension Board','Webcam','Microphone',
        'Speakers','Arduino Board','Raspberry Pi','Breadboard','Multimeter','Oscilloscope'
    ]

    departments = [
        'Communication and Computer Engineering',
        'Computer Science and Engineering',
        'Electronics and Communication Engineering',
        'Mechanical-Mechatronics Engineering',
        'Physics', 'Mathematics', 'Humanities and Social Sciences', 'Others'
    ]

    default_return = date.today() + timedelta(days=1)

    with st.form("item_issue_form"):
        col1, col2, col3 = st.columns(3)
        with col1:
            user_type = st.selectbox("User Type", ["student","faculty","staff"],
                                     index=["student","faculty","staff"].index(st.session_state.get("user_type","student")))
        with col2:
            name = st.text_input("Name", value=st.session_state.user_name)
        with col3:
            user_id = st.text_input("Roll No" if user_type=="student" else "Employee No")

        col1, col2, col3 = st.columns(3)
        with col1:
            department = st.selectbox("Department", [""] + departments)
            if department == "Others":
                other = st.text_input("Please specify department")
                department = other if other else department
        with col2:
            mobile = st.text_input("Mobile No", placeholder="10-digit number")
        with col3:
            email = st.text_input("Email ID", value=st.session_state.user_email, disabled=True)

        instructor_name = st.text_input("Instructor Name") if user_type=="student" else ""

        c1, c2 = st.columns(2)
        with c1:
            issue_date = st.date_input("Issue Date", value=date.today())
        with c2:
            return_date = st.date_input("Return Date", value=default_return)

        st.markdown("### 📦 Items to Issue")
        if 'form_items' not in st.session_state:
            st.session_state.form_items = [{'name': '', 'quantity': 1}]

        remove_index = None
        for i, it in enumerate(st.session_state.form_items):
            cc1, cc2, cc3 = st.columns([2, 1, 1])
            with cc1:
                item_name = st.selectbox(f"Item {i+1}", [""] + available_items, key=f"item_name_{i}")
            with cc2:
                qty = st.number_input(f"Quantity {i+1}", min_value=1, value=int(it.get('quantity',1) or 1), key=f"quantity_{i}")
            with cc3:
                if len(st.session_state.form_items) > 1:
                    if st.form_submit_button(f"Remove {i+1}"):
                        remove_index = i
            st.session_state.form_items[i] = {'name': item_name, 'quantity': qty}

        if remove_index is not None:
            st.session_state.form_items.pop(remove_index)
            st.rerun()

        cadd, csub = st.columns([1,3])
        with cadd:
            add_clicked = st.form_submit_button("➕ Add Item")
        with csub:
            submitted = st.form_submit_button("Submit Form", type="primary")

        if add_clicked:
            st.session_state.form_items.append({'name':'','quantity':1})
            st.rerun()

        if submitted:
            errors = []
            if not name: errors.append("Name is required")
            if not user_id: errors.append("ID is required")
            if not department: errors.append("Department is required")
            if not mobile or not re.match(r'^\d{10}$', mobile): errors.append("Valid 10-digit mobile number is required")
            if user_type=="student" and not instructor_name: errors.append("Instructor name is required for students")
            if not return_date or return_date <= issue_date: errors.append("Return date must be after issue date")
            valid_items = [x for x in st.session_state.form_items if x['name']]
            if not valid_items: errors.append("At least one item is required")

            if errors:
                for e in errors: st.error(e)
            else:
                form_data = {
                    'email': email, 'name': name, 'user_type': user_type, 'user_id': user_id,
                    'department': department, 'instructor_name': instructor_name, 'mobile': mobile,
                    'issue_date': str(issue_date), 'return_date': str(return_date), 'items': valid_items
                }
                try:
                    save_form_submission(form_data)
                    st.success("✅ Form submitted! Your request is pending approval.")
                    notify_admin_submission(form_data)
                    st.session_state.form_items = [{'name':'','quantity':1}]
                    with st.expander("📋 Submitted Data"):
                        st.json(form_data)
                except Exception as e:
                    st.error(f"Error submitting form: {e}")

# --------------- Admin Panel ---------------
def show_admin_panel():
    st.markdown('<div class="main-header"><h3>Admin Panel - LNMIIT</h3></div>', unsafe_allow_html=True)
    st.write(f"Logged in as: {st.session_state.user_email}")

    if st.button("Logout"):
        for k in list(st.session_state.keys()):
            del st.session_state[k]
        st.rerun()

    tabs = st.tabs(["Approvals", "Inventory", "All Submissions", "Email Test"])

    # Approvals tab
    with tabs[0]:
        st.subheader("Pending Approvals")
        df = get_all_submissions()
        if df.empty:
            st.info("No submissions yet.")
        else:
            pending = df[(df['status'].isna()) | (df['status'].str.lower() == 'pending')]
            if pending.empty:
                st.success("No pending requests.")
            for _, row in pending.iterrows():
                try:
                    items_list = json.loads(row['items'])
                except:
                    items_list = []
                with st.expander(f"#{row['id']} • {row['name']} • {row['user_type']} • {row['user_email']}"):
                    st.write(f"Department: {row['department']}")
                    st.write(f"ID: {row['user_id']}")
                    st.write(f"Issue: {row['issue_date']} | Return: {row['return_date']}")
                    st.write("Items:")
                    for it in items_list:
                        st.write(f"- {it['name']} x {it['quantity']} (Available: {inv_get_qty(it['name'])})")

                    with st.form(f"review_form_{row['id']}"):
                        comment = st.text_area("Admin comment (optional)", "")
                        c1, c2 = st.columns(2)
                        with c1:
                            approve = st.form_submit_button("✅ Approve")
                        with c2:
                            reject = st.form_submit_button("❌ Reject")

                        if approve:
                            ok, shortages = check_availability(items_list)
                            if not ok:
                                st.error("Insufficient stock for:")
                                for sh in shortages:
                                    st.write(f"- {sh['name']}: requested {sh['requested']}, available {sh['available']}")
                            else:
                                decrement_inventory(items_list)
                                mark_submission(int(row['id']), "approved", st.session_state.user_email, comment)
                                notify_user_decision(row['user_email'], "approved", comment, items_list)
                                st.success("Approved and stock updated.")
                                st.rerun()

                        if reject:
                            mark_submission(int(row['id']), "rejected", st.session_state.user_email, comment)
                            notify_user_decision(row['user_email'], "rejected", comment, items_list)
                            st.warning("Rejected.")
                            st.rerun()

    # Inventory tab
    with tabs[1]:
        st.subheader("Inventory")
        inv = inv_get_all()
        if inv.empty:
            st.info("No items in inventory. Add some below.")
        else:
            st.dataframe(inv, use_container_width=True)

        st.markdown("##### Add or Set Quantity")
        with st.form("add_set_form"):
            iname = st.text_input("Item name")
            iqty = st.number_input("Set quantity to", min_value=0, value=0)
            setbtn = st.form_submit_button("Save")
            if setbtn:
                if not iname.strip():
                    st.error("Item name required.")
                else:
                    inv_upsert_set(iname.strip(), int(iqty))
                    st.success("Saved.")
                    st.rerun()

        st.markdown("##### Quick Adjust")
        names = inv['name'].tolist() if not inv.empty else []
        with st.form("adjust_form"):
            sel = st.selectbox("Select item", names)
            delta = st.number_input("Adjust by (+ add / - remove)", value=0, step=1)
            adj = st.form_submit_button("Apply")
            if adj:
                if not sel:
                    st.error("Select an item.")
                else:
                    inv_adjust(sel, int(delta))
                    st.success("Updated.")
                    st.rerun()

    # All submissions tab
    with tabs[2]:
        st.subheader("All Submissions")
        df = get_all_submissions()
        if df.empty:
            st.info("No data.")
        else:
            c1, c2, c3, c4 = st.columns(4)
            with c1:
                uf = st.selectbox("User Type", ["All"] + sorted(df['user_type'].dropna().unique().tolist()))
            with c2:
                deptf = st.selectbox("Department", ["All"] + sorted(df['department'].dropna().unique().tolist()))
            with c3:
                statusf = st.selectbox("Status", ["All"] + sorted(df['status'].dropna().unique().tolist()))
            with c4:
                datef = st.date_input("Date", value=None)

            filtered = df.copy()
            if uf != "All": filtered = filtered[filtered['user_type'] == uf]
            if deptf != "All": filtered = filtered[filtered['department'] == deptf]
            if statusf != "All": filtered = filtered[filtered['status'] == statusf]
            if datef:
                filtered['submitted_at'] = pd.to_datetime(filtered['submitted_at'])
                filtered = filtered[filtered['submitted_at'].dt.date == datef]

            disp = filtered.copy()
            def items_to_text(x):
                try:
                    arr = json.loads(x)
                    return ", ".join([f"{i['name']} ({i['quantity']})" for i in arr])
                except: return x
            disp['items'] = disp['items'].apply(items_to_text)

            st.dataframe(disp, use_container_width=True)

            c1, c2 = st.columns(2)
            with c1:
                csv = filtered.to_csv(index=False)
                st.download_button("📥 Download CSV", data=csv,
                    file_name=f"lnmiit_forms_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv")
            with c2:
                output = io.BytesIO()
                with pd.ExcelWriter(output, engine="openpyxl") as writer:
                    filtered.to_excel(writer, index=False)
                st.download_button("📊 Download Excel", data=output.getvalue(),
                    file_name=f"lnmiit_forms_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

    # Email Test tab
    with tabs[3]:
        st.subheader("Email diagnostics")
        st.write(f"SMTP host: {SMTP_CONF['host']}")
        st.write(f"SMTP user: {SMTP_CONF['user']}")
        if st.button("Send test email to admin"):
            ok = send_email(SMTP_CONF["send_to"], "Test mail", "This is a test from Streamlit.")
            st.success("Sent!") if ok else st.error("Failed to send.")

# --------------- Main ---------------
def main():
    init_database()

    if not st.session_state.get("authenticated", False):
        auth_ui()
        if not st.session_state.get("authenticated", False):
            return

    if st.session_state.get("is_admin", False) and st.session_state.get("user_email","").lower() == ADMIN_EMAIL.lower():
        show_admin_panel()
    else:
        show_main_form()

if __name__ == "__main__":
    main()