# config.py
# ------------------------------------
# This file holds all configurations
# like Secret Key, Database connection
# details, Email settings, Razorpay keys etc.
# ------------------------------------

SECRET_KEY = "abc123"   # used for sessions

# MySQL Database Configuration
DB_HOST = "localhost"
DB_USER = "root"
DB_PASSWORD = "root"  # keep empty if no password
DB_NAME = "smartcart_db"


# Email SMTP Settings
MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = 'rudrojusathwika@gmail.com'
MAIL_PASSWORD = 'ehuh kuvv ipqr xlky'   # Gmail App Password


RAZORPAY_KEY_ID = "rzp_test_SFjrX4MaDmecbl"
RAZORPAY_KEY_SECRET = "3h08M3PpwL7TzpgCmm7c4PTf"


MAIL_SERVER = "smtp.gmail.com"
MAIL_PORT = 587
MAIL_USE_TLS = True

MAIL_USERNAME = "rudrojusathwika@gmail.com"   # your gmail
MAIL_PASSWORD = "nlpf xhhz jsxd uzlh"         # ← paste 16-digit app password here
