import streamlit as st
import sqlite3
import pandas as pd
import re
import json
import io
import os
from datetime import datetime, date, timedelta
import hashlib, secrets, hmac

# ----------------- Config -----------------
st.set_page_config(page_title="LNMIIT Item Issue Form", page_icon="🎓", layout="wide")

ADMIN_EMAIL = st.secrets.get("admin", {}).get("email", "smaheshwari@lnmiit.ac.in")
ADMIN_INITIAL_PASSWORD = st.secrets.get("admin", {}).get("initial_password", "ChangeMe@123!")
CSV_PATH = "items.csv"         # inventory CSV at repo root
FACULTY_CSV_PATH = "faculty.csv"  # faculty list CSV at repo root

# --------------- Styling ------------------
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        padding: 1rem; border-radius: 10px; margin-bottom: 1rem; color: white;
    }
    .profile-box {
        background: #f8fafc; border: 1px solid #e5e7eb; padding: 0.75rem 1rem; border-radius: 8px;
    }
    .overdue {
        color: #b91c1c; font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

# --------------- DB Helpers ----------------
def get_conn():
    return sqlite3.connect('lnmiit_forms.db', detect_types=sqlite3.PARSE_DECLTYPES)

def add_column_if_missing(conn, table, column, coldef, default_value=None):
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    cols = [r[1] for r in cur.fetchall()]
    if column in cols:
        return
    try:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coldef}")
        conn.commit()
    except sqlite3.OperationalError:
        try:
            cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} TEXT")
            conn.commit()
        except sqlite3.OperationalError as e2:
            print("Migration warning:", e2)
            return
    if default_value is not None:
        try:
            cur.execute(f"UPDATE {table} SET {column}=? WHERE {column} IS NULL", (default_value,))
            conn.commit()
        except Exception as e:
            print("Set default failed:", e)

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
    # Auth + profile columns
    add_column_if_missing(conn, "users", "password_hash", "TEXT")
    add_column_if_missing(conn, "users", "salt", "TEXT")
    add_column_if_missing(conn, "users", "is_admin", "INTEGER DEFAULT 0")
    add_column_if_missing(conn, "users", "reset_code", "TEXT")
    add_column_if_missing(conn, "users", "reset_expires", "TIMESTAMP")
    add_column_if_missing(conn, "users", "org_id", "TEXT")                # Roll/Emp No
    add_column_if_missing(conn, "users", "department", "TEXT")
    add_column_if_missing(conn, "users", "mobile", "TEXT")
    add_column_if_missing(conn, "users", "profile_completed", "INTEGER DEFAULT 0")

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
    # Workflow + tracking columns
    add_column_if_missing(conn, "form_submissions", "status", "TEXT DEFAULT 'pending'", default_value="pending")
    add_column_if_missing(conn, "form_submissions", "admin_comment", "TEXT")
    add_column_if_missing(conn, "form_submissions", "reviewed_at", "TIMESTAMP")
    add_column_if_missing(conn, "form_submissions", "approved_by", "TEXT")
    add_column_if_missing(conn, "form_submissions", "items_requested", "TEXT")
    add_column_if_missing(conn, "form_submissions", "items_remaining", "TEXT")
    add_column_if_missing(conn, "form_submissions", "items_approved", "TEXT")
    add_column_if_missing(conn, "form_submissions", "items_returned", "TEXT")
    add_column_if_missing(conn, "form_submissions", "return_updated_at", "TIMESTAMP")

    # Backfill defaults
    try:
        cur.execute("UPDATE form_submissions SET items_requested = COALESCE(items_requested, items)")
        cur.execute("UPDATE form_submissions SET items_remaining = COALESCE(items_remaining, items)")
        cur.execute("UPDATE form_submissions SET items_approved = COALESCE(items_approved, '[]')")
        cur.execute("UPDATE form_submissions SET items_returned = COALESCE(items_returned, '[]')")
        conn.commit()
    except Exception as e:
        print("Backfill warning:", e)

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
                INSERT INTO users (email, name, user_type, password_hash, salt, is_admin, profile_completed)
                VALUES (?, ?, ?, ?, ?, 1, 1)
            ''', (ADMIN_EMAIL, "Admin", "admin", pwd_hash, salt))
        else:
            cur.execute('''
                UPDATE users SET password_hash=?, salt=?, is_admin=1, user_type='admin', name='Admin', profile_completed=1
                WHERE email=?
            ''', (pwd_hash, salt, ADMIN_EMAIL))
        conn.commit()
    else:
        cur.execute("UPDATE users SET is_admin=1, user_type='admin', name=COALESCE(name,'Admin'), profile_completed=1 WHERE email=?", (ADMIN_EMAIL,))
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

# --------------- Notifications (TEMP DISABLED) ---------------
def notify_admin_submission(form_data):
    return  # notifications disabled

def notify_user_decision(user_email, decision, comment, items):
    return  # notifications disabled

# --------------- Helpers for items JSON ---------------
def load_items_json(s):
    try:
        if s is None or (isinstance(s, float) and pd.isna(s)) or s == "":
            return []
        return json.loads(s)
    except Exception:
        return []

def items_to_text(items):
    try:
        return ", ".join([f"{i['name']} ({i['quantity']})" for i in items]) if items else ""
    except Exception:
        return ""

def merge_items_add(base_list, add_list):
    agg = {}
    for it in base_list + add_list:
        if not it or 'name' not in it:
            continue
        name = str(it['name']).strip()
        qty = int(it.get('quantity', 0) or 0)
        agg[name] = agg.get(name, 0) + qty
    merged = [{"name": k, "quantity": max(0, v)} for k, v in agg.items()]
    merged.sort(key=lambda x: x["name"].lower())
    return merged

def subtract_items(a_list, b_list):
    # returns a - b by name, clipped at 0
    agg_a = {}
    for it in a_list:
        name = str(it.get('name',"")).strip()
        qty = int(it.get('quantity',0) or 0)
        if not name: continue
        agg_a[name] = agg_a.get(name, 0) + qty
    for it in b_list:
        name = str(it.get('name',"")).strip()
        qty = int(it.get('quantity',0) or 0)
        if not name: continue
        agg_a[name] = agg_a.get(name, 0) - qty
    out = []
    for name, qty in agg_a.items():
        if qty > 0:
            out.append({"name": name, "quantity": qty})
    out.sort(key=lambda x: x["name"].lower())
    return out

def sum_qty(items):
    return sum(int(i.get('quantity',0) or 0) for i in items)

# --------------- Faculty list ---------------
def load_faculty_names():
    if not os.path.exists(FACULTY_CSV_PATH):
        return []
    try:
        df = pd.read_csv(FACULTY_CSV_PATH)
        if df.empty:
            return []
        col = "Name" if "Name" in df.columns else df.columns[0]
        names = df[col].dropna().astype(str).str.strip()
        names = sorted({n for n in names if n})
        return names
    except Exception:
        return []

# --------------- DB Ops (Users/Auth/Profile) ---------------
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

def get_user_profile(email):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT name, user_type, org_id, department, mobile, profile_completed FROM users WHERE email=?", (email,))
    row = cur.fetchone(); conn.close()
    if not row:
        return {"name":"", "user_type":"student", "org_id":"", "department":"", "mobile":"", "profile_completed":0}
    return {"name": row[0] or "", "user_type": row[1] or "student", "org_id": row[2] or "", "department": row[3] or "", "mobile": row[4] or "", "profile_completed": int(row[5] or 0)}

def is_profile_completed(email):
    p = get_user_profile(email)
    return bool(p.get("profile_completed", 0))

def update_user_profile(email, name, user_type, org_id, department, mobile, completed=True):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("""
        UPDATE users
        SET name=?, user_type=?, org_id=?, department=?, mobile=?, profile_completed=?
        WHERE email=?
    """, (name, user_type, org_id, department, mobile, 1 if completed else 0, email))
    conn.commit(); conn.close()

def register_user(email, name, user_type, password):
    if not validate_lnmiit_email(email):
        raise ValueError("Only @lnmiit.ac.in email is allowed")
    if email.lower() == ADMIN_EMAIL.lower():
        raise ValueError("This email is reserved for Admin.")
    salt, pwd_hash = hash_password(password)
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO users (email, name, user_type, password_hash, salt, is_admin, profile_completed) VALUES (?, ?, ?, ?, ?, 0, 0)",
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

# --------------- CSV-backed Inventory ---------------
def _normalize_inventory_df(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [c.strip() for c in df.columns]
    if "name" not in df.columns:
        if "Name of Equipment" in df.columns:
            df = df.rename(columns={"Name of Equipment": "name"})
        elif "item" in df.columns:
            df = df.rename(columns={"item": "name"})
    if "quantity" not in df.columns:
        if "Quantity" in df.columns:
            df = df.rename(columns={"Quantity": "quantity"})
        elif "qty" in df.columns:
            df = df.rename(columns={"qty": "quantity"})
    if "name" not in df.columns or "quantity" not in df.columns:
        return pd.DataFrame(columns=["name", "quantity"])
    df["name"] = df["name"].astype(str).str.strip()
    df["quantity"] = pd.to_numeric(df["quantity"], errors="coerce").fillna(0).astype(int)
    df = df.groupby("name", as_index=False)["quantity"].sum()
    df["quantity"] = df["quantity"].clip(lower=0)
    return df[["name", "quantity"]]

def _read_inventory_csv() -> pd.DataFrame:
    if not os.path.exists(CSV_PATH):
        return pd.DataFrame(columns=["name", "quantity"])
    try:
        raw = pd.read_csv(CSV_PATH)
    except Exception:
        return pd.DataFrame(columns=["name", "quantity"])
    return _normalize_inventory_df(raw)

def _write_inventory_csv(df: pd.DataFrame):
    df = _normalize_inventory_df(df)
    out = df.rename(columns={"name": "Name of Equipment", "quantity": "Quantity"})
    out.to_csv(CSV_PATH, index=False, encoding="utf-8")

def inv_get_all() -> pd.DataFrame:
    return _read_inventory_csv()

def inv_get_qty(name: str) -> int:
    df = _read_inventory_csv()
    if df.empty:
        return 0
    mask = df["name"].str.lower() == (name or "").strip().lower()
    if not mask.any():
        return 0
    return int(df.loc[mask, "quantity"].iloc[0])

def inv_upsert_set(name: str, qty: int):
    name = (name or "").strip()
    if not name:
        return
    qty = int(qty or 0)
    df = _read_inventory_csv()
    if df.empty:
        df = pd.DataFrame([{"name": name, "quantity": max(0, qty)}])
    else:
        mask = df["name"].str.lower() == name.lower()
        if mask.any():
            df.loc[mask, "quantity"] = max(0, qty)
        else:
            df = pd.concat([df, pd.DataFrame([{"name": name, "quantity": max(0, qty)}])], ignore_index=True)
    _write_inventory_csv(df)

def inv_adjust(name: str, delta: int):
    name = (name or "").strip()
    if not name:
        return
    df = _read_inventory_csv()
    if df.empty:
        df = pd.DataFrame([{"name": name, "quantity": max(0, int(delta or 0))}])
    else:
        mask = df["name"].str.lower() == name.lower()
        if mask.any():
            new_qty = int(df.loc[mask, "quantity"].iloc[0]) + int(delta or 0)
            df.loc[mask, "quantity"] = max(0, new_qty)
        else:
            df = pd.concat(
                [df, pd.DataFrame([{"name": name, "quantity": max(0, int(delta or 0))}])],
                ignore_index=True
            )
    _write_inventory_csv(df)

def decrement_inventory(items):
    for it in items:
        qty = int(it.get('quantity', 0) or 0)
        if qty <= 0: continue
        inv_adjust(it['name'], -qty)

def increment_inventory(items):
    for it in items:
        qty = int(it.get('quantity', 0) or 0)
        if qty <= 0: continue
        inv_adjust(it['name'], +qty)

# --------------- DB Ops (Forms) ---------------
def save_form_submission(form_data):
    conn = get_conn(); cur = conn.cursor()
    items_json = json.dumps(form_data['items'])
    cur.execute('''
        INSERT INTO form_submissions 
        (user_email, name, user_type, user_id, department, instructor_name, mobile, issue_date, return_date, 
         items, items_requested, items_remaining, items_approved, items_returned, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
    ''', (form_data['email'], form_data['name'], form_data['user_type'], form_data['user_id'],
          form_data['department'], form_data['instructor_name'], form_data['mobile'],
          form_data['issue_date'], form_data['return_date'],
          items_json, items_json, items_json, json.dumps([]), json.dumps([])))
    conn.commit(); conn.close()

def get_all_submissions():
    conn = get_conn()
    df = pd.read_sql_query('SELECT * FROM form_submissions ORDER BY submitted_at DESC', conn)
    conn.close()
    return df

def update_submission_items(sid: int, items_list: list):
    conn = get_conn(); cur = conn.cursor()
    payload = json.dumps(items_list)
    cur.execute("UPDATE form_submissions SET items=?, items_remaining=? WHERE id=?", (payload, payload, sid))
    conn.commit(); conn.close()

def add_approved_to_submission(sid: int, approved_items: list):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT items_approved FROM form_submissions WHERE id=?", (sid,))
    row = cur.fetchone()
    existing = load_items_json(row[0]) if row else []
    merged = merge_items_add(existing, approved_items)
    cur.execute("UPDATE form_submissions SET items_approved=? WHERE id=?", (json.dumps(merged), sid))
    conn.commit(); conn.close()

def add_returned_to_submission(sid: int, returned_items: list):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT items_returned FROM form_submissions WHERE id=?", (sid,))
    row = cur.fetchone()
    existing = load_items_json(row[0]) if row else []
    merged = merge_items_add(existing, returned_items)
    cur.execute("UPDATE form_submissions SET items_returned=?, return_updated_at=CURRENT_TIMESTAMP WHERE id=?", (json.dumps(merged), sid))
    conn.commit(); conn.close()

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
                    if not is_profile_completed(user["email"]) and not user["is_admin"]:
                        st.session_state.force_profile_setup = True
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
                        # Auto-login and force profile setup
                        st.session_state.authenticated = True
                        st.session_state.user_email = email
                        st.session_state.user_name = name
                        st.session_state.user_type = user_type
                        st.session_state.is_admin = False
                        st.session_state.force_profile_setup = True
                        st.success("Account created! Please complete your profile.")
                        st.rerun()
                except sqlite3.IntegrityError:
                    st.error("This email is already registered.")
                except Exception as e:
                    st.error(str(e))

    elif mode == "forgot":
        with st.form("forgot_form"):
            email = st.text_input("Enter your registered LNMIIT email")
            c1, c2 = st.columns(2)
            with c1:
                send = st.form_submit_button("Generate reset code", type="primary")
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
                    st.info(f"Reset code (debug): {code}")  # email off
                    st.session_state.reset_email = email
                    st.session_state.auth_mode = "reset"
                    st.success("Reset code generated.")
                    st.rerun()

    elif mode == "reset":
        with st.form("reset_form"):
            email = st.text_input("Email", value=st.session_state.get("reset_email", ""))
            code = st.text_input("Reset code", placeholder="6-digit code")
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

# --------------- Profile UI ---------------
def departments_list():
    return [
        'Communication and Computer Engineering',
        'Computer Science and Engineering',
        'Electronics and Communication Engineering',
        'Mechanical-Mechatronics Engineering',
        'Physics', 'Mathematics', 'Humanities and Social Sciences', 'Others'
    ]

def show_profile_form(initial_setup=False):
    st.subheader("Profile")
    email = st.session_state.user_email
    prof = get_user_profile(email)

    with st.form("profile_form"):
        col1, col2, col3 = st.columns(3)
        with col1:
            user_type = st.selectbox("User Type", ["student","faculty","staff"],
                                     index=["student","faculty","staff"].index(prof.get("user_type","student")))
        with col2:
            name = st.text_input("Name", value=prof.get("name",""))
        with col3:
            org_id = st.text_input("Roll No" if user_type=="student" else "Employee No", value=prof.get("org_id",""))

        col4, col5 = st.columns(2)
        with col4:
            dlist = departments_list()
            opts = [""] + dlist
            sel_idx = 0
            if prof.get("department") in dlist:
                sel_idx = opts.index(prof.get("department"))
            dept = st.selectbox("Department", opts, index=sel_idx)
            if dept == "Others":
                dept_other = st.text_input("Please specify department")
                if dept_other.strip():
                    dept = dept_other.strip()
        with col5:
            mobile = st.text_input("Mobile No", value=prof.get("mobile",""), placeholder="10-digit number")

        st.text_input("Email", value=email, disabled=True)

        c1, c2 = st.columns(2)
        with c1:
            submit = st.form_submit_button("Save Profile", type="primary")
        with c2:
            cancel = st.form_submit_button("Cancel")

        if submit:
            errors = []
            if not name: errors.append("Name is required")
            if not org_id: errors.append("Roll/Employee No is required")
            if not dept: errors.append("Department is required")
            if not mobile or not re.match(r'^\d{10}$', mobile): errors.append("Valid 10-digit mobile is required")
            if errors:
                for e in errors: st.error(e)
            else:
                update_user_profile(email, name, user_type, org_id, dept, mobile, completed=True)
                st.session_state.user_name = name
                st.session_state.user_type = user_type
                if "force_profile_setup" in st.session_state:
                    del st.session_state["force_profile_setup"]
                st.success("Profile saved!")
                st.rerun()

        if cancel and initial_setup:
            st.warning("Profile setup required to continue.")

# --------------- App UI (User) ---------------
def show_main_form():
    st.markdown('<div class="main-header"><h3>LNMIIT Item Issue Form</h3></div>', unsafe_allow_html=True)
    st.write(f"Welcome, {st.session_state.user_name} ({st.session_state.user_email})")

    if st.button("Logout"):
        for k in list(st.session_state.keys()):
            del st.session_state[k]
        st.rerun()

    # If profile incomplete, force setup
    if st.session_state.get("force_profile_setup") or not is_profile_completed(st.session_state.user_email):
        st.info("Please complete your profile to continue.")
        show_profile_form(initial_setup=True)
        return

    tabs = st.tabs(["New Request", "My Requests", "Profile"])

    # New Request tab
    with tabs[0]:
        prof = get_user_profile(st.session_state.user_email)
        st.markdown("##### Your Profile")
        st.markdown(f"""
<div class="profile-box">
<b>User Type:</b> {prof['user_type'].title()}<br>
<b>{'Roll No' if prof['user_type']=='student' else 'Employee No'}:</b> {prof['org_id']}<br>
<b>Name:</b> {prof['name']}<br>
<b>Department:</b> {prof['department']}<br>
<b>Mobile:</b> {prof['mobile']}<br>
<b>Email:</b> {st.session_state.user_email}
</div>
""", unsafe_allow_html=True)
        st.caption("Need changes? Go to the Profile tab to update.")

        inv_df = inv_get_all()
        available_items = inv_df['name'].tolist()

        default_return = date.today() + timedelta(days=1)

        with st.form("item_issue_form"):
            # Instructor for students only (from faculty.csv)
            if prof["user_type"] == "student":
                fac_names = load_faculty_names()
                st.markdown("##### Instructor")
                if fac_names:
                    choice = st.selectbox("Instructor Name", [""] + fac_names + ["Other"])
                    if choice == "Other":
                        instructor_name = st.text_input("Enter Instructor Name")
                    else:
                        instructor_name = choice
                else:
                    instructor_name = st.text_input("Instructor Name")
            else:
                instructor_name = ""

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
                submitted = st.form_submit_button("Submit Request", type="primary")

            if add_clicked:
                st.session_state.form_items.append({'name':'','quantity':1})
                st.rerun()

            if submitted:
                errors = []
                if prof["user_type"] == "student" and not instructor_name:
                    errors.append("Instructor name is required for students")
                if not return_date or return_date <= issue_date:
                    errors.append("Return date must be after issue date")
                valid_items = [x for x in st.session_state.form_items if x['name']]
                if not valid_items:
                    errors.append("At least one item is required")

                if errors:
                    for e in errors: st.error(e)
                else:
                    form_data = {
                        'email': st.session_state.user_email,
                        'name': prof['name'],
                        'user_type': prof['user_type'],
                        'user_id': prof['org_id'],
                        'department': prof['department'],
                        'instructor_name': instructor_name,
                        'mobile': prof['mobile'],
                        'issue_date': str(issue_date),
                        'return_date': str(return_date),
                        'items': valid_items
                    }
                    try:
                        save_form_submission(form_data)
                        st.success("✅ Request submitted! Your request is pending approval.")
                        notify_admin_submission(form_data)  # no-op
                        st.session_state.form_items = [{'name':'','quantity':1}]
                        with st.expander("📋 Submitted Data"):
                            st.json(form_data)
                    except Exception as e:
                        st.error(f"Error submitting form: {e}")

    # My Requests tab
    with tabs[1]:
        st.subheader("My Requests")
        df_all = get_all_submissions()
        if df_all.empty:
            st.info("No submissions yet.")
        else:
            mydf = df_all[df_all['user_email'] == st.session_state.user_email].copy()
            if mydf.empty:
                st.info("You have no submissions yet.")
            else:
                req_list, app_list, ret_list, out_list = [], [], [], []
                for _, r in mydf.iterrows():
                    items_req = load_items_json(r.get('items_requested') if 'items_requested' in mydf.columns else r.get('items'))
                    items_app = load_items_json(r.get('items_approved')) if 'items_approved' in mydf.columns else []
                    items_ret = load_items_json(r.get('items_returned')) if 'items_returned' in mydf.columns else []
                    items_out = subtract_items(items_app, items_ret)
                    req_list.append(items_to_text(items_req))
                    app_list.append(items_to_text(items_app))
                    ret_list.append(items_to_text(items_ret))
                    out_list.append(items_to_text(items_out))
                mydf['Requested'] = req_list
                mydf['Approved'] = app_list
                mydf['Returned'] = ret_list
                mydf['Outstanding'] = out_list
                cols = ['id','submitted_at','status','admin_comment','issue_date','return_date','Requested','Approved','Returned','Outstanding']
                cols = [c for c in cols if c in mydf.columns]
                st.dataframe(mydf[cols].sort_values(by='submitted_at', ascending=False), use_container_width=True)

                c1, c2 = st.columns(2)
                with c1:
                    csv = mydf.to_csv(index=False)
                    st.download_button("📥 Download my submissions (CSV)", data=csv,
                        file_name=f"my_requests_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv")
                with c2:
                    output = io.BytesIO()
                    with pd.ExcelWriter(output, engine="openpyxl") as writer:
                        mydf.to_excel(writer, index=False)
                    st.download_button("📊 Download my submissions (Excel)", data=output.getvalue(),
                        file_name=f"my_requests_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

    # Profile tab
    with tabs[2]:
        show_profile_form(initial_setup=False)

# --------------- Admin Panel ---------------
def show_admin_panel():
    st.markdown('<div class="main-header"><h3>Admin Panel - LNMIIT</h3></div>', unsafe_allow_html=True)
    st.write(f"Logged in as: {st.session_state.user_email}")

    if st.button("Logout"):
        for k in list(st.session_state.keys()):
            del st.session_state[k]
        st.rerun()

    tabs = st.tabs(["Approvals", "Returns", "Inventory", "All Submissions"])

    # Approvals tab (pending approvals)
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
                items_list = load_items_json(row.get('items_remaining') if 'items_remaining' in pending.columns else row.get('items'))

                with st.expander(f"#{row['id']} • {row['name']} • {row['user_type']} • {row['user_email']}"):
                    st.write(f"Department: {row['department']}")
                    st.write(f"ID: {row['user_id']}")
                    st.write(f"Issue: {row['issue_date']} | Return: {row['return_date']}")

                    with st.form(f"review_form_{row['id']}"):
                        st.markdown("##### Items (tick to approve and set qty)")
                        approved_quantities = {}
                        for i, it in enumerate(items_list):
                            name = it.get('name', '')
                            req_qty = int(it.get('quantity', 0) or 0)
                            avail = inv_get_qty(name)
                            max_approve = min(req_qty, avail) if avail is not None else 0

                            c1, c2, c3 = st.columns([3, 1, 1])
                            with c1:
                                sel = st.checkbox(
                                    f"{name} • requested: {req_qty} • available: {avail}",
                                    key=f"sel_{row['id']}_{i}",
                                    value=False
                                )
                            with c2:
                                qty_to_approve = st.number_input(
                                    "Approve qty",
                                    min_value=0,
                                    max_value=int(max_approve),
                                    value=0,
                                    step=1,
                                    key=f"appqty_{row['id']}_{i}"
                                )
                            with c3:
                                st.write("")

                            if sel and qty_to_approve > 0:
                                approved_quantities[i] = int(qty_to_approve)

                        comment = st.text_area("Admin comment (optional)", "", key=f"comment_{row['id']}")
                        cA, cR = st.columns(2)
                        with cA:
                            approve_selected = st.form_submit_button("✅ Approve selected")
                        with cR:
                            reject_all = st.form_submit_button("❌ Reject all")

                        if approve_selected:
                            if not approved_quantities:
                                st.error("Select at least one item and approve qty > 0.")
                            else:
                                # validate availability again
                                shortages = []
                                for idx, qty in approved_quantities.items():
                                    it = items_list[idx]
                                    avail_now = inv_get_qty(it['name'])
                                    if qty > avail_now:
                                        shortages.append(f"- {it['name']}: approve {qty}, available {avail_now}")
                                if shortages:
                                    st.error("Insufficient stock for:")
                                    for s in shortages: st.write(s)
                                else:
                                    # Decrement inventory, update DB
                                    to_decrement = [{'name': items_list[idx]['name'], 'quantity': qty}
                                                    for idx, qty in approved_quantities.items()]
                                    decrement_inventory(to_decrement)
                                    add_approved_to_submission(int(row['id']), to_decrement)

                                    remaining = []
                                    for idx, it in enumerate(items_list):
                                        approved_q = int(approved_quantities.get(idx, 0))
                                        rem = int(it.get('quantity', 0)) - approved_q
                                        if rem > 0:
                                            remaining.append({'name': it['name'], 'quantity': rem})

                                    if remaining:
                                        update_submission_items(int(row['id']), remaining)
                                        mark_submission(int(row['id']), "pending",
                                                        st.session_state.user_email,
                                                        (comment or "") + " | Approved some items")
                                        st.success("Approved selected items. Remaining kept pending.")
                                    else:
                                        update_submission_items(int(row['id']), [])
                                        mark_submission(int(row['id']), "approved",
                                                        st.session_state.user_email,
                                                        (comment or "") + " | Approved all items")
                                        st.success("Approved and completed.")
                                    st.rerun()

                        if reject_all:
                            update_submission_items(int(row['id']), [])
                            mark_submission(int(row['id']), "rejected",
                                            st.session_state.user_email, comment or "")
                            st.warning("Rejected all items.")
                            st.rerun()

    # Returns tab (mark physical returns + overdue view)
    with tabs[1]:
        st.subheader("Mark Returns")
        df = get_all_submissions()
        if df.empty:
            st.info("No submissions found.")
        else:
            # Build records with approved/returned/outstanding
            def build_row_info(r):
                items_app = load_items_json(r.get('items_approved'))
                items_ret = load_items_json(r.get('items_returned'))
                outstanding = subtract_items(items_app, items_ret)
                total_out = sum_qty(outstanding)
                due = False
                try:
                    rt = pd.to_datetime(r.get('return_date')).date()
                    due = (date.today() > rt) and (total_out > 0)
                except Exception:
                    due = False
                return items_app, items_ret, outstanding, total_out, due

            # Overdue list summary
            overdue_rows = []
            for _, r in df.iterrows():
                items_app, items_ret, outstanding, total_out, due = build_row_info(r)
                if due:
                    overdue_rows.append({"id": r['id'], "user": r['name'], "email": r['user_email'],
                                         "outstanding": items_to_text(outstanding),
                                         "return_date": r['return_date']})
            if overdue_rows:
                st.markdown("##### Overdue Returns")
                for od in overdue_rows:
                    st.markdown(f"- <span class='overdue'>#{od['id']} • {od['user']} • {od['email']} • due: {od['return_date']} • outstanding: {od['outstanding']}</span>", unsafe_allow_html=True)
            else:
                st.info("No overdue returns. ✅")

            st.markdown("##### Pending Returns (Outstanding items)")
            # Show only those with outstanding > 0
            pending_returns = []
            for _, r in df.iterrows():
                items_app, items_ret, outstanding, total_out, due = build_row_info(r)
                if total_out > 0:
                    pending_returns.append((r, items_app, items_ret, outstanding, total_out, due))

            if not pending_returns:
                st.success("No pending returns.")
            else:
                for r, items_app, items_ret, outstanding, total_out, due in pending_returns:
                    header = f"#{r['id']} • {r['name']} • {r['user_type']} • {r['user_email']}"
                    if due:
                        header += " • OVERDUE"
                    with st.expander(header):
                        st.write(f"Department: {r['department']}")
                        st.write(f"ID: {r['user_id']}")
                        st.write(f"Issue: {r['issue_date']} | Return (due): {r['return_date']}")
                        st.write(f"Approved: {items_to_text(items_app)}")
                        st.write(f"Returned so far: {items_to_text(items_ret)}")
                        st.write(f"Outstanding: {items_to_text(outstanding)}")

                        with st.form(f"return_form_{r['id']}"):
                            st.markdown("Tick items and set return qty")
                            to_return = {}
                            for i, it in enumerate(outstanding):
                                name = it['name']
                                out_qty = int(it['quantity'])
                                c1, c2, c3 = st.columns([3, 1, 1])
                                with c1:
                                    sel = st.checkbox(f"{name} • outstanding: {out_qty}", key=f"ret_sel_{r['id']}_{i}")
                                with c2:
                                    qty_r = st.number_input("Return qty", min_value=0, max_value=out_qty, value=0, step=1,
                                                            key=f"ret_qty_{r['id']}_{i}")
                                with c3:
                                    st.write("")
                                if sel and qty_r > 0:
                                    to_return[i] = qty_r

                            comment = st.text_area("Admin comment (optional)", "", key=f"ret_comment_{r['id']}")
                            rt_btn = st.form_submit_button("✅ Mark returned")

                            if rt_btn:
                                if not to_return:
                                    st.error("Select at least one item and return qty > 0.")
                                else:
                                    # Build return items
                                    returned_now = [{'name': outstanding[idx]['name'], 'quantity': int(qty)}
                                                    for idx, qty in to_return.items()]
                                    # Increase inventory
                                    increment_inventory(returned_now)
                                    # Update DB cumulative returned
                                    add_returned_to_submission(int(r['id']), returned_now)

                                    # If now fully returned, update status
                                    after_df = get_all_submissions()
                                    ar = after_df[after_df['id'] == r['id']].iloc[0]
                                    items_app2 = load_items_json(ar.get('items_approved'))
                                    items_ret2 = load_items_json(ar.get('items_returned'))
                                    new_outstanding = subtract_items(items_app2, items_ret2)
                                    if sum_qty(new_outstanding) == 0:
                                        mark_submission(int(r['id']), "returned", st.session_state.user_email,
                                                        (comment or "") + " | All items returned")
                                        st.success("All items returned. Status set to 'returned'.")
                                    else:
                                        mark_submission(int(r['id']), ar.get('status', 'approved') or 'approved',
                                                        st.session_state.user_email,
                                                        (comment or "") + " | Partial return")
                                        st.info("Partial return recorded.")
                                    st.rerun()

    # Inventory
    with tabs[2]:
        st.subheader("Inventory")
        inv = inv_get_all()
        if inv.empty:
            st.info("No items in inventory. Add or import CSV below.")
        else:
            st.dataframe(inv.rename(columns={"name":"Name of Equipment","quantity":"Quantity"}), use_container_width=True)

        # CSV Import / Download
        st.markdown("##### CSV Inventory (items.csv at repo root)")
        col_imp, col_exp = st.columns(2)
        with col_imp:
            with st.form("import_csv_form"):
                uploaded = st.file_uploader("Upload items.csv (Name of Equipment, Quantity)", type=["csv"])
                imp = st.form_submit_button("Import CSV")
                if imp:
                    if uploaded is None:
                        st.error("Please choose a CSV file.")
                    else:
                        try:
                            tmp = pd.read_csv(uploaded)
                            tmp = _normalize_inventory_df(tmp)
                            if tmp.empty:
                                st.error("CSV must have columns: Name of Equipment, Quantity")
                            else:
                                _write_inventory_csv(tmp)
                                st.success("Inventory imported from CSV.")
                                st.rerun()
                        except Exception as e:
                            st.error(f"Failed to import CSV: {e}")
        with col_exp:
            cur_df = inv_get_all()
            if cur_df.empty:
                st.info("No inventory yet to download.")
            else:
                download_df = cur_df.rename(columns={"name":"Name of Equipment","quantity":"Quantity"})
                st.download_button(
                    "⬇️ Download current items.csv",
                    data=download_df.to_csv(index=False).encode("utf-8"),
                    file_name="items.csv",
                    mime="text/csv"
                )

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