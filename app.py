import streamlit as st
import sqlite3
import pandas as pd
import re
from datetime import datetime, date
import gspread
from google.oauth2.service_account import Credentials
import json

# Page configuration
st.set_page_config(
    page_title="LNMIIT Item Issue Form",
    page_icon="🎓",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        margin-bottom: 2rem;
    }
    .form-container {
        background: white;
        padding: 2rem;
        border-radius: 10px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    .success-message {
        background: #d4edda;
        color: #155724;
        padding: 1rem;
        border-radius: 5px;
        border-left: 4px solid #28a745;
    }
    .error-message {
        background: #f8d7da;
        color: #721c24;
        padding: 1rem;
        border-radius: 5px;
        border-left: 4px solid #dc3545;
    }
</style>
""", unsafe_allow_html=True)

# Database initialization
def init_database():
    conn = sqlite3.connect('lnmiit_forms.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            name TEXT,
            user_type TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Forms table
    cursor.execute('''
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
            submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_email) REFERENCES users (email)
        )
    ''')
    
    # Admin users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert default admin
    cursor.execute('''
        INSERT OR IGNORE INTO admin_users (email) 
        VALUES ('admin@lnmiit.ac.in')
    ''')
    
    conn.commit()
    conn.close()

# Email validation
def validate_lnmiit_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@lnmiit\.ac\.in$'
    return re.match(pattern, email) is not None

# Check if user is admin
def is_admin(email):
    conn = sqlite3.connect('lnmiit_forms.db')
    cursor = conn.cursor()
    cursor.execute('SELECT email FROM admin_users WHERE email = ?', (email,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

# Save user to database
def save_user(email, name, user_type):
    conn = sqlite3.connect('lnmiit_forms.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO users (email, name, user_type)
        VALUES (?, ?, ?)
    ''', (email, name, user_type))
    conn.commit()
    conn.close()

# Save form submission
def save_form_submission(form_data):
    conn = sqlite3.connect('lnmiit_forms.db')
    cursor = conn.cursor()
    
    items_json = json.dumps(form_data['items'])
    
    cursor.execute('''
        INSERT INTO form_submissions 
        (user_email, name, user_type, user_id, department, instructor_name, 
         mobile, issue_date, return_date, items)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        form_data['email'], form_data['name'], form_data['user_type'],
        form_data['user_id'], form_data['department'], form_data['instructor_name'],
        form_data['mobile'], form_data['issue_date'], form_data['return_date'],
        items_json
    ))
    
    conn.commit()
    conn.close()

# Get all submissions (for admin)
def get_all_submissions():
    conn = sqlite3.connect('lnmiit_forms.db')
    df = pd.read_sql_query('''
        SELECT * FROM form_submissions 
        ORDER BY submitted_at DESC
    ''', conn)
    conn.close()
    return df

# Authentication function
def authenticate_user():
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    
    if not st.session_state.authenticated:
        st.markdown('<div class="main-header">', unsafe_allow_html=True)
        st.markdown("# 🎓 LNMIIT Item Issue Form")
        st.markdown("## The LNM Institute of Information Technology")
        st.markdown('</div>', unsafe_allow_html=True)
        
        st.markdown("### 🔐 Login with LNMIIT Email")
        
        with st.form("login_form"):
            email = st.text_input("Email Address", placeholder="username@lnmiit.ac.in")
            name = st.text_input("Full Name")
            user_type = st.selectbox("User Type", ["student", "faculty", "staff"])
            
            submitted = st.form_submit_button("Login")
            
            if submitted:
                if not email or not name:
                    st.error("Please fill all fields")
                elif not validate_lnmiit_email(email):
                    st.error("Please use a valid LNMIIT email address (@lnmiit.ac.in)")
                else:
                    # Save user and authenticate
                    save_user(email, name, user_type)
                    st.session_state.authenticated = True
                    st.session_state.user_email = email
                    st.session_state.user_name = name
                    st.session_state.user_type = user_type
                    st.success("Login successful!")
                    st.rerun()
        
        return False
    
    return True

# Main form
def show_main_form():
    st.markdown('<div class="main-header">', unsafe_allow_html=True)
    col1, col2 = st.columns([3, 1])
    with col1:
        st.markdown("# 🎓 LNMIIT Item Issue Form")
        st.markdown("## The LNM Institute of Information Technology")
    with col2:
        if st.button("Logout"):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Welcome message
    st.markdown(f"### Welcome, {st.session_state.user_name}!")
    
    # Departments list
    departments = [
        'Communication and Computer Engineering',
        'Computer Science and Engineering',
        'Electronics and Communication Engineering',
        'Mechanical-Mechatronics Engineering',
        'Physics',
        'Mathematics',
        'Humanities and Social Sciences',
        'Others'
    ]
    
    # Available items (you can modify this list)
    available_items = [
        'Laptop', 'Projector', 'HDMI Cable', 'Extension Board',
        'Webcam', 'Microphone', 'Speakers', 'Arduino Board',
        'Raspberry Pi', 'Breadboard', 'Multimeter', 'Oscilloscope'
    ]
    
    with st.form("item_issue_form"):
        st.markdown("### 📝 Form Details")
        
        # Basic Information
        col1, col2, col3 = st.columns(3)
        
        with col1:
            user_type = st.selectbox("User Type", ["student", "faculty", "staff"], 
                                   index=["student", "faculty", "staff"].index(st.session_state.user_type))
            
        with col2:
            name = st.text_input("Name", value=st.session_state.user_name)
            
        with col3:
            user_id = st.text_input("Roll No" if user_type == "student" else "Employee No")
        
        # Department and Contact
        col1, col2, col3 = st.columns(3)
        
        with col1:
            department = st.selectbox("Department", [""] + departments)
            if department == "Others":
                other_department = st.text_input("Please specify department")
                department = other_department if other_department else department
                
        with col2:
            mobile = st.text_input("Mobile No", placeholder="10-digit number")
            
        with col3:
            email = st.text_input("Email ID", value=st.session_state.user_email, disabled=True)
        
        # Instructor name for students
        if user_type == "student":
            instructor_name = st.text_input("Instructor Name")
        else:
            instructor_name = ""
        
        # Dates
        col1, col2 = st.columns(2)
        with col1:
            issue_date = st.date_input("Issue Date", value=date.today())
        with col2:
            return_date = st.date_input("Return Date")
        
        # Items section
        st.markdown("### 📦 Items to Issue")
        
        # Initialize items in session state
        if 'form_items' not in st.session_state:
            st.session_state.form_items = [{'name': '', 'quantity': 1}]
        
        # Display items
        for i, item in enumerate(st.session_state.form_items):
            col1, col2, col3 = st.columns([2, 1, 1])
            
            with col1:
                item_name = st.selectbox(f"Item {i+1}", 
                                       [""] + available_items + ["Other"], 
                                       key=f"item_name_{i}")
                if item_name == "Other":
                    custom_item = st.text_input(f"Custom Item {i+1}", key=f"custom_item_{i}")
                    item_name = custom_item if custom_item else item_name
                
            with col2:
                quantity = st.number_input(f"Quantity {i+1}", min_value=1, value=1, key=f"quantity_{i}")
                
            with col3:
                if len(st.session_state.form_items) > 1:
                    if st.button(f"Remove {i+1}", key=f"remove_{i}"):
                        st.session_state.form_items.pop(i)
                        st.rerun()
            
            # Update session state
            st.session_state.form_items[i] = {'name': item_name, 'quantity': quantity}
        
        # Add item button
        if st.button("+ Add Item"):
            st.session_state.form_items.append({'name': '', 'quantity': 1})
            st.rerun()
        
        # Form submission
        submitted = st.form_submit_button("Submit Form", type="primary")
        
        if submitted:
            # Validation
            errors = []
            
            if not name:
                errors.append("Name is required")
            if not user_id:
                errors.append("ID is required")
            if not department:
                errors.append("Department is required")
            if not mobile or not re.match(r'^\d{10}$', mobile):
                errors.append("Valid 10-digit mobile number is required")
            if user_type == "student" and not instructor_name:
                errors.append("Instructor name is required for students")
            if not return_date or return_date <= issue_date:
                errors.append("Return date must be after issue date")
            
            # Check items
            valid_items = [item for item in st.session_state.form_items 
                          if item['name'] and item['name'] != '']
            if not valid_items:
                errors.append("At least one item is required")
            
            if errors:
                for error in errors:
                    st.error(error)
            else:
                # Save form data
                form_data = {
                    'email': email,
                    'name': name,
                    'user_type': user_type,
                    'user_id': user_id,
                    'department': department,
                    'instructor_name': instructor_name,
                    'mobile': mobile,
                    'issue_date': str(issue_date),
                    'return_date': str(return_date),
                    'items': valid_items
                }
                
                try:
                    save_form_submission(form_data)
                    st.success("✅ Form submitted successfully!")
                    
                    # Clear form items
                    st.session_state.form_items = [{'name': '', 'quantity': 1}]
                    
                    # Show submitted data
                    with st.expander("📋 View Submitted Data"):
                        st.json(form_data)
                        
                except Exception as e:
                    st.error(f"Error submitting form: {str(e)}")

# Admin panel
def show_admin_panel():
    st.markdown('<div class="main-header">', unsafe_allow_html=True)
    st.markdown("# 👨‍💼 Admin Panel - LNMIIT Form Submissions")
    st.markdown('</div>', unsafe_allow_html=True)
    
    if st.button("Logout"):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()
    
    # Get all submissions
    df = get_all_submissions()
    
    if df.empty:
        st.info("No form submissions yet.")
    else:
        st.markdown(f"### 📊 Total Submissions: {len(df)}")
        
        # Filters
        col1, col2, col3 = st.columns(3)
        
        with col1:
            user_type_filter = st.selectbox("Filter by User Type", 
                                          ["All"] + list(df['user_type'].unique()))
        
        with col2:
            department_filter = st.selectbox("Filter by Department", 
                                           ["All"] + list(df['department'].unique()))
        
        with col3:
            date_filter = st.date_input("Filter by Date")
        
        # Apply filters
        filtered_df = df.copy()
        
        if user_type_filter != "All":
            filtered_df = filtered_df[filtered_df['user_type'] == user_type_filter]
        
        if department_filter != "All":
            filtered_df = filtered_df[filtered_df['department'] == department_filter]
        
        # Display data
        st.markdown("### 📋 Form Submissions")
        
        # Format items column for better display
        display_df = filtered_df.copy()
        display_df['items'] = display_df['items'].apply(
            lambda x: ', '.join([f"{item['name']} ({item['quantity']})" 
                               for item in json.loads(x)]) if x else ""
        )
        
        st.dataframe(display_df, use_container_width=True)
        
        # Download options
        col1, col2 = st.columns(2)
        
        with col1:
            csv = filtered_df.to_csv(index=False)
            st.download_button(
                label="📥 Download CSV",
                data=csv,
                file_name=f"lnmiit_forms_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
        
        with col2:
            # Excel download
            excel_data = filtered_df.to_excel(index=False, engine='openpyxl')
            st.download_button(
                label="📊 Download Excel",
                data=excel_data,
                file_name=f"lnmiit_forms_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )

# Main application
def main():
    init_database()
    
    if not authenticate_user():
        return
    
    # Check if user is admin
    if is_admin(st.session_state.user_email):
        show_admin_panel()
    else:
        show_main_form()

if __name__ == "__main__":
    main()