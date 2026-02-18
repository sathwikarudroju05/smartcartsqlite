
from flask import Flask, render_template, request, redirect, session, flash,url_for
from flask_mail import Mail, Message
import bcrypt
import random
import config
import os
from werkzeug.utils import secure_filename
import razorpay
from flask import make_response, render_template
from utils.pdf_generator import generate_pdf
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

def verify_user_password(entered_password, stored_password):
    """
    Handles BOTH bcrypt and werkzeug hashed passwords.
    This does NOT change your logic — only makes login compatible
    with already stored database values.
    """

    if stored_password is None:
        return False

    # If stored as bytes (bcrypt format)
    if isinstance(stored_password, bytes):
        return bcrypt.check_password_hash(stored_password, entered_password)

    # If stored as string (sometimes SQLite gives str for bcrypt)
    if isinstance(stored_password, str) and stored_password.startswith("$2"):
        return bcrypt.check_password_hash(stored_password.encode('utf-8'), entered_password)

    # Otherwise assume werkzeug hash
    try:
        from werkzeug.security import check_password_hash
        return check_password_hash(stored_password, entered_password)
    except:
        return False


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "smartcart.db")







razorpay_client = razorpay.Client(
    auth=(config.RAZORPAY_KEY_ID, config.RAZORPAY_KEY_SECRET)
)

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
# ==========================================================
# DEFAULT ROUTE (OPEN SITE → GO TO USER LOGIN)
# ==========================================================
@app.route('/')
def default_home():

    # If user already logged in → go to products page
    if 'user_id' in session:
        return redirect('/user/products')

    # If admin logged in → go to admin dashboard
    if 'admin_id' in session:
        return redirect('/admin/item-list')

    # Otherwise → show user login page
    return redirect('/user-login')





ADMIN_UPLOAD_FOLDER = 'static/uploads/admin_profiles'
app.config['ADMIN_UPLOAD_FOLDER'] = ADMIN_UPLOAD_FOLDER

app.config['USER_UPLOAD_FOLDER'] = 'static/uploads/user_profiles'






# ---------------- EMAIL CONFIGURATION ----------------
app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD

mail = Mail(app)



# ---------------- DB CONNECTION FUNCTION --------------
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)   # ✅ Use absolute path
    conn.row_factory = sqlite3.Row
    return conn



# ---------------------------------------------------------
# ROUTE 1: ADMIN SIGNUP (SEND OTP)
# ---------------------------------------------------------
@app.route('/admin-signup', methods=['GET', 'POST'])
def admin_signup():

    # Show form
    if request.method == "GET":
        return render_template("admin/admin_signup.html")

    # POST → Process signup
    name = request.form['name']
    email = request.form['email']

    # 1️⃣ Check if admin email already exists
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT admin_id FROM admin WHERE email=?", (email,))
    existing_admin = cursor.fetchone()
    cursor.close()
    conn.close()

    if existing_admin:
        flash("This email is already registered. Please login instead.", "danger")
        return redirect('/admin-signup')

    # 2️⃣ Save user input temporarily in session
    session['signup_name'] = name
    session['signup_email'] = email

    # 3️⃣ Generate OTP and store in session
    otp = random.randint(100000, 999999)
    session['otp'] = otp

    # 4️⃣ Send OTP Email
    message = Message(
        subject="SmartCart Admin OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    message.body = f"Your OTP for SmartCart Admin Registration is: {otp}"
    mail.send(message)

    flash("OTP sent to your email!", "success")
    return redirect('/verify-otp')



# ---------------------------------------------------------
# ROUTE 2: DISPLAY OTP PAGE
# ---------------------------------------------------------
@app.route('/verify-otp', methods=['GET'])
def verify_otp_get():
    return render_template("admin/verify_otp.html")



# ---------------------------------------------------------
# ROUTE 3: VERIFY OTP + SAVE ADMIN
# ---------------------------------------------------------
@app.route('/verify-otp', methods=['POST'])
def verify_otp_post():
    
    # User submitted OTP + Password
    user_otp = request.form['otp']
    password = request.form['password']

    # Compare OTP
    if str(session.get('otp')) != str(user_otp):
        flash("Invalid OTP. Try again!", "danger")
        return redirect('/verify-otp')

    # Hash password using bcrypt
    # hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode('utf-8')
    hashed_password = bcrypt.hashpw(
    password.encode('utf-8'),
    bcrypt.gensalt()
).decode('utf-8')




    # Insert admin into database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO admin (name, email, password) VALUES (?,?,?)",
        (session['signup_name'], session['signup_email'], hashed_password)
    )
    conn.commit()
    cursor.close()
    conn.close()

    # Clear temporary session data
    session.pop('otp', None)
    session.pop('signup_name', None)
    session.pop('signup_email', None)

    flash("Admin Registered Successfully!", "success")
    return redirect('/admin-login')


# =================================================================
# ROUTE 4: ADMIN LOGIN PAGE (GET + POST)
# =================================================================
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():

    # Show login page
    if request.method == 'GET':
        return render_template("admin/admin_login.html")

    # POST → Validate login
    email = request.form['email']
    password = request.form['password']

    # Step 1: Check if admin email exists
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM admin WHERE email=?", (email,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    if admin is None:
        flash("Email not found! Please register first.", "danger")
        return redirect('/admin-login')

    # Step 2: Verify password (Supports BOTH werkzeug + bcrypt)
    stored_password = admin['password']

    password_valid = False

    try:
        # Try Werkzeug hash (new/reset passwords)
        if check_password_hash(stored_password, password):
            password_valid = True
    except:
        pass

    if not password_valid:
        try:
            # Try bcrypt (old passwords)
            import bcrypt
            if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                password_valid = True
        except:
            pass

    if not password_valid:
        flash("Incorrect password!", "danger")
        return redirect('/admin-login')

    # Step 3: If login success → Create admin session
    session['admin_id'] = admin['admin_id']
    session['admin_name'] = admin['name']
    session['admin_email'] = admin['email']

    flash("Login Successful!", "success")
    return redirect('/admin/item-list')



# =================================================================
# ROUTE 5: ADMIN DASHBOARD (PROTECTED ROUTE)
# =================================================================
@app.route('/admin-dashboard')
def admin_dashboard():

    # Protect dashboard → Only logged-in admin can access
    if 'admin_id' not in session:
        flash("Please login to access dashboard!", "danger")
        return redirect('/admin-login')

    # Send admin name to dashboard UI
    return render_template("admin/dashboard.html", admin_name=session['admin_name'])



# =================================================================
# ROUTE 6: ADMIN LOGOUT
# =================================================================
@app.route('/admin-logout')
def admin_logout():

    # Clear admin session
    session.pop('admin_id', None)
    session.pop('admin_name', None)
    session.pop('admin_email', None)

    flash("Logged out successfully.", "success")
    return redirect('/admin-login')




# ------------------- IMAGE UPLOAD PATH -------------------
UPLOAD_FOLDER = 'static/uploads/product_images'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# =================================================================
# ROUTE 7: SHOW ADD PRODUCT PAGE (Protected Route)
# =================================================================
@app.route('/admin/add-item', methods=['GET'])
def add_item_page():

    # Only logged-in admin can access
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    return render_template("admin/add_item.html")



# =================================================================
# ROUTE 8: ADD PRODUCT INTO DATABASE
# =================================================================
@app.route('/admin/add-item', methods=['POST'])
def add_item():

    # Check admin session
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    # 1️⃣ Get form data
    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']
    image_file = request.files['image']

    # 2️⃣ Validate image upload
    if image_file.filename == "":
        flash("Please upload a product image!", "danger")
        return redirect('/admin/add-item')

    # 3️⃣ Secure the file name
    filename = secure_filename(image_file.filename)

    # 4️⃣ Create full path
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # 5️⃣ Save image into folder
    image_file.save(image_path)

    # 6️⃣ Insert product into database
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO products (name, description, category, price, image) VALUES (?, ?,?, ?, ?)",
        (name, description, category, price, filename)
    )

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product added successfully!", "success")
    return redirect('/admin/add-item')


# =================================================================
# ROUTE 9: DISPLAY ALL PRODUCTS (Admin)
# =================================================================
@app.route('/admin/item-list')
def item_list():

    # Check admin session
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    # 1️⃣ Fetch category list for dropdown
    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    # 2️⃣ Build dynamic query based on filters
    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE ?"
        params.append(f"%{search}%") 

    if category_filter:
        query += " AND category = ?"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "admin/item_list.html",
        products=products,
        categories=categories
    )




#=================================================================
# ROUTE 10: VIEW SINGLE PRODUCT DETAILS
# =================================================================
@app.route('/admin/view-item/<int:item_id>')
def view_item(item_id):

    # Check admin session
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM products WHERE product_id = ?", (item_id,))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/view_item.html", product=product)


# =================================================================
# ROUTE 11: SHOW UPDATE FORM WITH EXISTING DATA
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['GET'])
def update_item_page(item_id):

    # Check login
    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    # Fetch product data
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM products WHERE product_id = ?", (item_id,))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/update_item.html", product=product)


# =================================================================
# ROUTE 12: UPDATE PRODUCT + OPTIONAL IMAGE REPLACE
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['POST'])
def update_item(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    # 1️⃣ Get updated form data
    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']

    new_image = request.files['image']

    # 2️⃣ Fetch old product data
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE product_id = ?", (item_id,))
    product = cursor.fetchone()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    old_image_name = product['image']

    # 3️⃣ If admin uploaded a new image → replace it
    if new_image and new_image.filename != "":
        
        # Secure filename
        from werkzeug.utils import secure_filename
        new_filename = secure_filename(new_image.filename)

        # Save new image
        new_image_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        new_image.save(new_image_path)

        # Delete old image file
        old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], old_image_name)
        if os.path.exists(old_image_path):
            os.remove(old_image_path)

        final_image_name = new_filename

    else:
        # No new image uploaded → keep old one
        final_image_name = old_image_name

    # 4️⃣ Update product in the database
    cursor.execute("""
        UPDATE products
        SET name=?, description=?, category=?, price=?, image=?
        WHERE product_id=?
    """, (name, description, category, price, final_image_name, item_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product updated successfully!", "success")
    return redirect('/admin/item-list')





# =================================================================
# ROUTE 13:DELETE PRODUCT (DELETE DB ROW + DELETE IMAGE FILE)
# =================================================================
@app.route('/admin/delete-item/<int:item_id>')
def delete_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    # 1️⃣ Fetch product to get image name
    cursor.execute("SELECT image FROM products WHERE product_id=?", (item_id,))
    product = cursor.fetchone()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    image_name = product['image']

    # Delete image from folder
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_name)
    if os.path.exists(image_path):
        os.remove(image_path)

    # 2️⃣ Delete product from DB
    cursor.execute("DELETE FROM products WHERE product_id=?", (item_id,))
    conn.commit()

    cursor.close()
    conn.close()

    flash("Product deleted successfully!", "success")
    return redirect('/admin/item-list')







# =================================================================
# ROUTE 14: SHOW ADMIN PROFILE DATA
# =================================================================
@app.route('/admin/profile', methods=['GET'])
def admin_profile():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (admin_id,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template("admin/admin_profile.html", admin=admin)





# =================================================================
# ROUTE 15: UPDATE ADMIN PROFILE (NAME, EMAIL, PASSWORD, IMAGE)
# =================================================================
@app.route('/admin/profile', methods=['POST'])
def admin_profile_update():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    # 1️⃣ Get form data
    name = request.form['name']
    email = request.form['email']
    new_password = request.form['password']
    new_image = request.files['profile_image']

    conn = get_db_connection()
    cursor = conn.cursor()

    # 2️⃣ Fetch old admin data
    cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (admin_id,))
    admin = cursor.fetchone()

    old_image_name = admin['profile_image']

    # 3️⃣ Update password only if entered
    if new_password:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    else:
        hashed_password = admin['password']  # keep old password

    # 4️⃣ Process new profile image if uploaded
    if new_image and new_image.filename != "":
        
        from werkzeug.utils import secure_filename
        new_filename = secure_filename(new_image.filename)

        # Save new image
        image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], new_filename)
        new_image.save(image_path)

        # Delete old image
        if old_image_name:
            old_image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_image_path):
                os.remove(old_image_path)

        final_image_name = new_filename
    else:
        final_image_name = old_image_name

    # 5️⃣ Update database
    cursor.execute("""
        UPDATE admin
        SET name=?, email=?, password=?, profile_image=?
        WHERE admin_id=?
    """, (name, email, hashed_password, final_image_name, admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    # Update session name for UI consistency
    session['admin_name'] = name  
    session['admin_email'] = email

    flash("Profile updated successfully!", "success")
    return redirect('/admin/profile')









# =================================================================
# ROUTE 16: USER REGISTRATION
# =================================================================
@app.route('/user-register', methods=['GET', 'POST'])
def user_register():

    if request.method == 'GET':
        return render_template("user/user_register.html")

    name = request.form['name']
    email = request.form['email']
    password = request.form['password']

    # Check if user already exists
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    existing_user = cursor.fetchone()

    if existing_user:
        flash("Email already registered! Please login.", "danger")
        return redirect('/user-register')

    # Hash password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Insert new user
    cursor.execute(
        "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
        (name, email, hashed_password)
    )
    conn.commit()

    cursor.close()
    conn.close()

    flash("Registration successful! Please login.", "success")
    return redirect('/user-login')

# =================================================================
# ROUTE 17: USER LOGIN
# =================================================================
# =================================================================
# ROUTE 17: USER LOGIN (FINAL FIX — Handles Old + New Passwords)
# =================================================================
@app.route('/user-login', methods=['GET', 'POST'])
def user_login():

    if request.method == 'GET':
        return render_template("user/user_login.html")

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()
        flash("Email not found! Please register.", "danger")
        return redirect('/user-login')

    stored_password = user['password']

    # ---------------------------------------------------
    # STEP 1: Detect Password Type Automatically
    # ---------------------------------------------------
    password_verified = False

    try:
        # If it's Werkzeug hash → starts with 'pbkdf2:' or 'scrypt:'
        if stored_password.startswith('pbkdf2:') or stored_password.startswith('scrypt:'):
            password_verified = check_password_hash(stored_password, password)

        else:
            # Otherwise assume OLD bcrypt hash
            import bcrypt
            password_verified = bcrypt.checkpw(
                password.encode('utf-8'),
                stored_password.encode('utf-8')
            )

            # ---------------------------------------------------
            # STEP 2: Auto-Upgrade bcrypt → Werkzeug (One-time migration)
            # ---------------------------------------------------
            if password_verified:
                new_hash = generate_password_hash(password)

                cursor.execute(
                    "UPDATE users SET password=? WHERE user_id=?",
                    (new_hash, user['user_id'])
                )
                conn.commit()

    except Exception as e:
        cursor.close()
        conn.close()
        flash("Invalid password format. Contact admin.", "danger")
        return redirect('/user-login')

    if not password_verified:
        cursor.close()
        conn.close()
        flash("Incorrect password!", "danger")
        return redirect('/user-login')

    cursor.close()
    conn.close()

    # ---------------------------------------------------
    # STEP 3: Create Session
    # ---------------------------------------------------
    session['user_id'] = user['user_id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']

    flash("Login successful!", "success")
    return redirect("/user/products")




# =================================================================
# ROUTE 18: USER DASHBOARD
# =================================================================
@app.route('/user-dashboard')
def user_dashboard():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    return render_template("user/user_home.html", user_name=session['user_name'])


# =================================================================
# ROUTE 19: USER LOGOUT
# =================================================================
@app.route('/user-logout')
def user_logout():
    
    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('user_email', None)

    flash("Logged out successfully!", "success")
    return redirect('/user-login')







# =================================================================
# ROUTE 20: USER PRODUCT LISTING (SEARCH + FILTER)
# =================================================================
@app.route('/user/products')
def user_products():

    # Optional: restrict only logged-in users
    if 'user_id' not in session:
        flash("Please login to view products!", "danger")
        return redirect('/user-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch categories for filter dropdown
    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    # Build dynamic SQL
    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE ?"
        params.append(f"%{search}%") 

    if category_filter:
        query += " AND category = ?"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "user/user_products.html",
        products=products,
        categories=categories
    )
# =================================================================
# ROUTE 21: USER PRODUCT DETAILS PAGE
# =================================================================
@app.route('/user/product/<int:product_id>')
def user_product_details(product_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM products WHERE product_id = ?", (product_id,))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/user/products')

    return render_template("user/product_details.html", product=product)



# =================================================================
#  ROUTE 22:ADD ITEM TO CART
# =================================================================
@app.route('/user/add-to-cart/<int:product_id>')
def add_to_cart(product_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    # Create cart if doesn't exist
    if 'cart' not in session:
        session['cart'] = {}

    cart = session['cart']

    # Get product
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE product_id=?", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found.", "danger")
        return redirect(request.referrer)

    pid = str(product_id)

    # If exists → increase quantity
    if pid in cart:
        cart[pid]['quantity'] += 1
    else:
        cart[pid] = {
            'name': product['name'],
            'price': float(product['price']),
            'image': product['image'],
            'quantity': 1
        }

    session['cart'] = cart

    flash("Item added to cart!", "success")

    return redirect(request.referrer)   # ⭐ Return to same page



# =================================================================
#  ROUTE 23: VIEW CART PAGE
# =================================================================
@app.route('/user/cart')
def view_cart():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})

    # Calculate total
    grand_total = sum(item['price'] * item['quantity'] for item in cart.values())

    return render_template("user/cart.html", cart=cart, grand_total=grand_total)



# =================================================================
#  ROUTE 24:INCREASE QUANTITY
# =================================================================
@app.route('/user/cart/increase/<pid>')
def increase_quantity(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart[pid]['quantity'] += 1

    session['cart'] = cart
    return redirect('/user/cart')



# =================================================================
#  ROUTE 25:DECREASE QUANTITY
# =================================================================
@app.route('/user/cart/decrease/<pid>')
def decrease_quantity(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart[pid]['quantity'] -= 1

        # If quantity becomes 0 → remove item
        if cart[pid]['quantity'] <= 0:
            cart.pop(pid)

    session['cart'] = cart
    return redirect('/user/cart')



# =================================================================
# ROUTE 26:REMOVE ITEM
# =================================================================
@app.route('/user/cart/remove/<pid>')
def remove_from_cart(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart.pop(pid)

    session['cart'] = cart

    flash("Item removed!", "success")
    return redirect('/user/cart')

#=================================================================
# ROUTE 27:USER PROFILE
# =================================================================
@app.route('/user/profile', methods=['GET'])
def user_profile():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template("user/user_profile.html", user=user)
#=================================================================
# ROUTE 28: UPDATE USER PROFILE
# =================================================================

@app.route('/user/profile', methods=['POST'])
def user_profile_update():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/login')

    user_id = session['user_id']

    name = request.form['name']
    email = request.form['email']
    new_password = request.form['password']
    new_image = request.files['profile_image']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
    user = cursor.fetchone()

    old_image_name = user['profile_image']

    if new_password:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    else:
        hashed_password = user['password']

    if new_image and new_image.filename != "":
        new_filename = secure_filename(new_image.filename)

        image_path = os.path.join(app.config['USER_UPLOAD_FOLDER'], new_filename)
        new_image.save(image_path)

        if old_image_name:
            old_image_path = os.path.join(app.config['USER_UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_image_path):
                os.remove(old_image_path)

        final_image_name = new_filename
    else:
        final_image_name = old_image_name

    cursor.execute("""
        UPDATE users
        SET name=?, email=?, password=?, profile_image=?
        WHERE user_id=?
    """, (name, email, hashed_password, final_image_name, user_id))

    conn.commit()
    cursor.close()
    conn.close()

    session['user_name'] = name
    session['user_email'] = email

    flash("Profile updated successfully!", "success")
    return redirect('/user/profile')



# =================================================================
# ROUTE 29: CREATE RAZORPAY ORDER
# =================================================================
@app.route('/user/pay')
def user_pay():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})

    if not cart:
        flash("Your cart is empty!", "danger")
        return redirect('/user/products')

    # Calculate total amount
    total_amount = sum(item['price'] * item['quantity'] for item in cart.values())
    razorpay_amount = int(total_amount * 100)  # convert to paise

    # Create Razorpay order
    razorpay_order = razorpay_client.order.create({
        "amount": razorpay_amount,
        "currency": "INR",
        "payment_capture": "1"
    })

    session['razorpay_order_id'] = razorpay_order['id']

    return render_template(
        "user/payment.html",
        amount=total_amount,
        key_id=config.RAZORPAY_KEY_ID,
        order_id=razorpay_order['id']
    )


# =================================================================
# TEMP SUCCESS PAGE (Verification in Day 13)
# =================================================================
@app.route('/payment-success')
def payment_success():

    payment_id = request.args.get('payment_id')
    order_id = request.args.get('order_id')

    if not payment_id:
        flash("Payment failed!", "danger")
        return redirect('/user/cart')

    return render_template(
        "user/payment_success.html",
        payment_id=payment_id,
        order_id=order_id
    )






# DAY 13: Verify Razorpay Payment & Store Order + Order Items

from flask import request, jsonify, render_template
import razorpay
import traceback

# Ensure razorpay_client is initialized (from Day 12)
# razorpay_client = razorpay.Client(auth=(config.RAZORPAY_KEY_ID, config.RAZORPAY_KEY_SECRET))

# ------------------------------
# Route: Verify Payment and Store Order
# ------------------------------
@app.route('/verify-payment', methods=['POST'])
def verify_payment():
    if 'user_id' not in session:
        flash("Please login to complete the payment.", "danger")
        return redirect('/user-login')

    # Read values posted from frontend
    razorpay_payment_id = request.form.get('razorpay_payment_id')
    razorpay_order_id = request.form.get('razorpay_order_id')
    razorpay_signature = request.form.get('razorpay_signature')

    if not (razorpay_payment_id and razorpay_order_id and razorpay_signature):
        flash("Payment verification failed (missing data).", "danger")
        return redirect('/user/cart')

    # Build verification payload required by Razorpay client.utility
    payload = {
        'razorpay_order_id': razorpay_order_id,
        'razorpay_payment_id': razorpay_payment_id,
        'razorpay_signature': razorpay_signature
    }

    try:
        # This will raise an error if signature invalid
        razorpay_client.utility.verify_payment_signature(payload)

    except Exception as e:
        # Verification failed
        app.logger.error("Razorpay signature verification failed: %s", str(e))
        flash("Payment verification failed. Please contact support.", "danger")
        return redirect('/user/cart')

    # Signature verified — now store order and items into DB
    user_id = session['user_id']
    cart = session.get('cart', {})
    address_id = session.get('selected_address_id')


    if not cart:
        flash("Cart is empty. Cannot create order.", "danger")
        return redirect('/user/products')

    # Calculate total amount (ensure same as earlier)
    total_amount = sum(item['price'] * item['quantity'] for item in cart.values())

    # DB insert: orders and order_items
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Insert into orders table
        cursor.execute("""
INSERT INTO orders (user_id, razorpay_order_id, razorpay_payment_id, amount, payment_status, address_id)
VALUES (?, ?, ?, ?, ?, ?)
""", (user_id, razorpay_order_id, razorpay_payment_id, total_amount, 'paid', address_id))


        order_db_id = cursor.lastrowid  # newly created order's primary key

        # Insert all items
        for pid_str, item in cart.items():
            product_id = int(pid_str)
            cursor.execute("""
                INSERT INTO order_items (order_id, product_id, product_name, quantity, price)
                VALUES (?, ?, ?, ?, ?)
            """, (order_db_id, product_id, item['name'], item['quantity'], item['price']))

        # Commit transaction
        conn.commit()

        # Clear cart and temporary razorpay order id
        session.pop('cart', None)
        session.pop('razorpay_order_id', None)
        session.pop('selected_address_id', None)

        # flash("Payment successful and order placed!", "success")
        return redirect(f"/user/order-success/{order_db_id}")

    except Exception as e:
        # Rollback and log error
        conn.rollback()
        app.logger.error("Order storage failed: %s\n%s", str(e), traceback.format_exc())
        flash("There was an error saving your order. Contact support.", "danger")
        return redirect('/user/cart')

    finally:
        cursor.close()
        conn.close()



@app.route('/user/order-success/<int:order_db_id>')
def order_success(order_db_id):

    if 'user_id' not in session:
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Get order details
    cursor.execute("""
        SELECT * FROM orders
        WHERE order_id=? AND user_id=?
    """, (order_db_id, session['user_id']))
    order = cursor.fetchone()

    # Get ordered items
    cursor.execute("""
        SELECT * FROM order_items
        WHERE order_id=?
    """, (order_db_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    # VERY IMPORTANT — this return was missing
    return render_template("user/order_success.html", order=order, items=items)




@app.route('/user/my-orders')
def my_orders():
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC", (session['user_id'],))
    orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("user/my_orders.html", orders=orders)



# ----------------------------
# GENERATE INVOICE PDF
# ----------------------------
@app.route("/user/download-invoice/<int:order_id>")
def download_invoice(order_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    # Fetch order
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM orders WHERE order_id=? AND user_id=?",
                   (order_id, session['user_id']))
    order = cursor.fetchone()

    cursor.execute("SELECT * FROM order_items WHERE order_id=?", (order_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/my-orders')

    # Render invoice HTML
    html = render_template("user/invoice.html", order=order, items=items)

    pdf = generate_pdf(html)
    if not pdf:
        flash("Error generating PDF", "danger")
        return redirect('/user/my-orders')

    # Prepare response
    response = make_response(pdf.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f"attachment; filename=invoice_{order_id}.pdf"

    return response



@app.route('/user/select-address')
def select_address():
    if 'user_id' not in session:
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM user_addresses WHERE user_id=? ORDER BY is_default DESC",
                   (session['user_id'],))
    addresses = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("user/select_address.html", addresses=addresses)
@app.route('/user/use-address/<int:address_id>')
def use_address(address_id):

    if 'user_id' not in session:
        return redirect('/user-login')

    # store selected address
    session['selected_address_id'] = address_id

    # go to Razorpay order creation
    return redirect('/user/pay')   # ✅ correct route




@app.route('/user/add-address', methods=['GET', 'POST'])
def add_address():

    if request.method == 'POST':
        data = (
            session['user_id'],
            request.form['full_name'],
            request.form['phone'],
            request.form['address'],
            request.form['city'],
            request.form['state'],
            request.form['pincode']
        )

        conn = get_db_connection()
        cursor = conn.cursor()

        # if first address → make default
        cursor.execute("SELECT COUNT(*) FROM user_addresses WHERE user_id=?", (session['user_id'],))
        count = cursor.fetchone()[0]

        is_default = (count == 0)

        cursor.execute("""
            INSERT INTO user_addresses
            (user_id, full_name, phone, address_line, city, state, pincode, is_default)
            VALUES (?,?,?,?,?,?,?,?)
        """, (*data, is_default))

        conn.commit()
        cursor.close()
        conn.close()

        return redirect('/user/select-address')

    return render_template("user/add_address.html")



# -------------------- USER FORGOT PASSWORD --------------------
@app.route('/user-forgot', methods=['GET', 'POST'])
def user_forgot():
    if request.method == 'POST':
        email = request.form['email']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if not user:
            flash("Email not registered.", "danger")
            return redirect('/user-forgot')

        # Create random token (NO serializer used)
        token = str(uuid.uuid4())

        # Save in session temporarily
        session['reset_token'] = token
        session['reset_email'] = email

        reset_link = url_for('user_reset', token=token, _external=True)

        msg = Message(
            "Reset Your Password",
            sender=app.config['MAIL_USERNAME'],
            recipients=[email]
        )

        msg.body = f"""
Hello,

Click the link below to reset your password:

{reset_link}

If you did not request this, ignore this email.
"""

        mail.send(msg)

        flash("Reset link sent to your email.", "success")
        return redirect('/user-login')

    return render_template('user/forgot_password.html')


# -------------------- USER RESET PASSWORD --------------------
@app.route('/user-reset/<token>', methods=['GET', 'POST'])
def user_reset(token):

    # Validate 🔐 token by comparing session value
    if token != session.get('reset_token'):
        flash("Invalid or expired reset link.", "danger")
        return redirect('/user-forgot')

    if request.method == 'POST':
        password = request.form['password']
        confirm = request.form['confirm_password']

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(request.url)

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("UPDATE users SET password=? WHERE email=?",
                       (hashed_password, session.get('reset_email')))

        conn.commit()
        cursor.close()
        conn.close()

        # Clear session reset data
        session.pop('reset_token', None)
        session.pop('reset_email', None)

        flash("Password reset successful. Please login.", "success")
        return redirect('/user-login')

    return render_template('user/reset_password.html')


# -------------------- ADMIN FORGOT PASSWORD --------------------
@app.route('/admin-forgot', methods=['GET', 'POST'])
def admin_forgot():
    if request.method == 'POST':
        email = request.form['email']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM admin WHERE email=?", (email,))
        admin = cursor.fetchone()
        cursor.close()
        conn.close()

        if not admin:
            flash("Email not registered.", "danger")
            return redirect('/admin-forgot')

        # SAME token generation as user
        token = str(uuid.uuid4())

        # SAME session logic as user (just admin names)
        session['admin_reset_token'] = token
        session['admin_reset_email'] = email

        # SAME link generation as user
        reset_link = url_for('admin_reset', token=token, _external=True)

        msg = Message(
            "Reset Your Admin Password",
            sender=app.config['MAIL_USERNAME'],
            recipients=[email]
        )

        msg.body = f"""
Hello Admin,

Click the link below to reset your password:

{reset_link}

If you did not request this, ignore this email.
"""

        mail.send(msg)

        flash("Reset link sent to your email.", "success")
        return redirect('/admin-login')

    return render_template('admin/admin_forgot.html')


# -------------------- ADMIN RESET PASSWORD --------------------
@app.route('/admin-reset/<token>', methods=['GET', 'POST'])
def admin_reset(token):

    # SAME validation logic as user_reset
    if token != session.get('admin_reset_token'):
        flash("Invalid or expired reset link.", "danger")
        return redirect('/admin-forgot')

    if request.method == 'POST':
        password = request.form['password']
        confirm = request.form['confirm_password']

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(request.url)

        # SAME hashing — no change
        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE admin SET password=? WHERE email=?",
            (hashed_password, session.get('admin_reset_email'))
        )
        conn.commit()
        cursor.close()
        conn.close()

        # SAME cleanup as user
        session.pop('admin_reset_token', None)
        session.pop('admin_reset_email', None)

        flash("Password reset successful. Please login.", "success")
        return redirect('/admin-login')

    return render_template('admin/admin_reset.html')





# ------------------------- RUN APP ------------------------
if __name__ == '__main__':
    app.run(debug=True)
