import os
import re
import json
import requests
import cohere
import razorpay
import random
from markdown import markdown
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, Blueprint
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from datetime import datetime, timedelta
from functools import wraps
from flask_mail import Mail, Message

# --- Flask App Initialization ---
app = Flask(__name__)
app.jinja_env.filters['markdown'] = markdown
app.config['SECRET_KEY'] = 'a_very_secret_key_that_should_be_changed'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Email Configuration for OTP ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = ''
app.config['MAIL_PASSWORD'] = ''
app.config['MAIL_DEFAULT_SENDER'] = 'codemistry359@gmail.com'


# --- Extensions Initialization ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# --- API Key Rotation System ---
class ApiKeyManager:
    def __init__(self, keys):
        self.keys = [key for key in keys if key and not key.startswith("YOUR_")]
        self.current_index = 0

    def get_key(self):
        if not self.keys:
            return None
        return self.keys[self.current_index]

    def rotate_key(self):
        if not self.keys:
            return
        self.current_index = (self.current_index + 1) % len(self.keys)
        print(f"Rotated API key to index: {self.current_index}")

# ⚠️ IMPORTANT: Add your unique API keys to these lists
FMP_API_KEYS = [ "" ]
COHERE_API_KEYS = [ "" ]

fmp_key_manager = ApiKeyManager(FMP_API_KEYS)
cohere_key_manager = ApiKeyManager(COHERE_API_KEYS)

# --- Razorpay Client ---
RAZORPAY_KEY_ID = ""
RAZORPAY_KEY_SECRET = ""
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))


# --- Database Models ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    coins = db.Column(db.Integer, default=10)
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    is_blocked = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    analyses = db.relationship('AnalysisHistory', backref='author', lazy=True)
    orders = db.relationship('Order', backref='customer', lazy=True)
    activities = db.relationship('UserActivity', backref='user', lazy=True)
    # FEAT: Added relationship to notifications
    notifications = db.relationship('Notification', backref='recipient', lazy=True, cascade="all, delete-orphan")

class AnalysisHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(10), nullable=False)
    recommendation = db.Column(db.String(50), nullable=False)
    full_analysis = db.Column(db.Text, nullable=True)
    price_at_analysis = db.Column(db.Float, nullable=False)
    rec_color = db.Column(db.String(10), nullable=False)
    date_analyzed = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.String(40), unique=True, nullable=False)
    payment_id = db.Column(db.String(40))
    amount = db.Column(db.Integer, nullable=False)
    coins_purchased = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='created')
    date_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Coupon(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    discount = db.Column(db.Integer, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    expiry_date = db.Column(db.DateTime)

class UserActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# FEAT: New model for user notifications
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --- Decorators ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# --- Helper & Data Fetching Functions ---
def log_activity(action):
    if current_user.is_authenticated:
        activity = UserActivity(action=action, user_id=current_user.id)
        db.session.add(activity)
        db.session.commit()

# FEAT: Helper to create notifications
def create_notification(user_id, message):
    notification = Notification(user_id=user_id, message=message)
    db.session.add(notification)
    # The session will be committed in the calling route

def send_otp_email(email, otp):
    try:
        msg = Message('Your OTP for AI Stock Analyzer', recipients=[email])
        msg.body = f'Your One-Time Password (OTP) is: {otp}. It is valid for 10 minutes.'
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def safe_fetch(url, params=None):
    if not fmp_key_manager.keys:
        print("Error: No FMP API keys provided.")
        return None
        
    for _ in range(len(fmp_key_manager.keys)):
        api_key = fmp_key_manager.get_key()
        try:
            current_params = params or {}
            current_params['apikey'] = api_key
            response = requests.get(url, params=current_params, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429: # Too Many Requests
                print(f"FMP API key at index {fmp_key_manager.current_index} is rate-limited. Rotating.")
                fmp_key_manager.rotate_key()
            else:
                print(f"HTTP error for {url} with key index {fmp_key_manager.current_index}: {e}")
                fmp_key_manager.rotate_key()
        except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
            print(f"Request failed for {url} with key index {fmp_key_manager.current_index}: {e}")
            fmp_key_manager.rotate_key()
    
    print("All FMP API keys failed.")
    return None

def clean_stock_data(data):
    if 'profile' not in data: data['profile'] = {}
    if 'quote' not in data: data['quote'] = {}
    data['profile'].setdefault('image', 'https://placehold.co/64x64/0D1117/C9D1D9?text=N/A')
    data['profile'].setdefault('companyName', 'N/A')
    data['profile'].setdefault('exchangeShortName', 'N/A')
    data['profile'].setdefault('mktCap', 0)
    data['quote'].setdefault('price', 0.0)
    data['quote'].setdefault('change', 0.0)
    data['quote'].setdefault('changesPercentage', 0.0)
    data['quote'].setdefault('pe', 0.0)
    data['quote'].setdefault('volume', 0)
    return data

def parse_ai_recommendation(analysis_text):
    """More robustly parses the AI recommendation."""
    match = re.search(r"\*\*([^\*]+)\*\*", analysis_text)
    if match:
        recommendation = match.group(1).strip()
    else:
        search_area = analysis_text[:250].lower()
        keywords = ["strong buy", "buy", "strong sell", "sell", "hold", "wait", "avoid"]
        found_keyword = next((key for key in keywords if key in search_area), None)
        recommendation = found_keyword.title() if found_keyword else "N/A"

    rec_lower = recommendation.lower()
    if "buy" in rec_lower: return recommendation, "green"
    if "sell" in rec_lower or "avoid" in rec_lower: return recommendation, "red"
    if "hold" in rec_lower or "wait" in rec_lower: return recommendation, "yellow"
    return recommendation, "gray"

def get_market_movers():
    # This API endpoint requires a paid FMP plan.
    # Returning empty lists to avoid errors on the free plan.
    print("Skipping get_market_movers() - requires paid FMP plan.")
    return [], []
    # base_url = "https://financialmodelingprep.com/stable"
    # gainers = safe_fetch(f"{base_url}/biggest-gainers") or []
    # losers = safe_fetch(f"{base_url}/biggest-losers") or []
    # return gainers[:8], losers[:8]

def get_stocks_by_market_cap_range(min_cap, max_cap, limit=4):
    # This API endpoint requires a paid FMP plan.
    # Returning empty lists to avoid errors on the free plan.
    print("Skipping get_stocks_by_market_cap_range() - requires paid FMP plan.")
    return []
    # screener_url = "https://financialmodelingprep.com/stable/company-screener"
    # params = {'marketCapMoreThan': min_cap, 'marketCapLowerThan': max_cap, 'limit': limit}
    # return safe_fetch(screener_url, params) or []

def get_stocks_by_industry(industry, limit=4):
    # This API endpoint requires a paid FMP plan.
    # Returning empty lists to avoid errors on the free plan.
    print("Skipping get_stocks_by_industry() - requires paid FMP plan.")
    return []
    # screener_url = "https://financialmodelingprep.com/stable/company-screener"
    # params = {'industry': industry, 'limit': limit}
    # return safe_fetch(screener_url, params) or []

def get_stock_data(symbol):
    base_url = "https://financialmodelingprep.com/stable"  # <-- Use stable
    symbol = symbol.upper()
    profile_data = safe_fetch(f"{base_url}/profile?symbol={symbol}")  # <-- Add ?symbol=
    quote_data = safe_fetch(f"{base_url}/quote?symbol={symbol}")      # <-- Add ?symbol=
    
    # Check if API returned an error (e.g., payment required)
    if not profile_data or not quote_data or 'error' in profile_data or 'error' in quote_data:
        # Check for free plan "payment required" error specifically
        if profile_data and 'Error Message' in profile_data[0]:
             raise ValueError(f"Could not retrieve data for symbol: {symbol}. Your FMP plan does not include this data.")
        raise ValueError(f"Could not retrieve data for symbol: {symbol}. The API may be rate-limited or the symbol is invalid.")

    return {'profile': profile_data[0], 'quote': quote_data[0]}

def analyze_with_ai(stock_data, symbol, chat_history=None, question=None):
    if not cohere_key_manager.keys:
        return "### Error\nNo Cohere API keys provided."

    for _ in range(len(cohere_key_manager.keys)):
        api_key = cohere_key_manager.get_key()
        try:
            co = cohere.Client(api_key)
            if not question:
                profile = stock_data.get('profile', {})
                quote = stock_data.get('quote', {})
                def safe_format(value, prefix="", suffix="", default_val="N/A"):
                    if isinstance(value, (int, float)): return f"{prefix}{value:,.2f}{suffix}"
                    return default_val
                prompt = f"""
Act as a decisive, expert stock market analyst. Your primary goal is to provide a clear, actionable recommendation. You must choose a direction. Based on the data, is this stock more likely to go up or down from here?
Avoid conservative 'Hold' or 'Wait' recommendations unless the signals are in perfect, undeniable conflict.

**Company Profile:**
- Name: {profile.get('companyName', 'N/A')}
- Sector: {profile.get('sector', 'N/A')}
- Industry: {profile.get('industry', 'N/A')}

**Current Market Data:**
- Current Price: {safe_format(quote.get('price'), '$')}
- Day's Change: {safe_format(quote.get('change', 0), '$')} ({safe_format(quote.get('changesPercentage', 0), suffix='%')})
- Market Cap: {safe_format(profile.get('mktCap'), '$')}
- P/E Ratio: {safe_format(quote.get('pe'), default_val='N/A')}

**Analysis Request:**
Provide a detailed analysis structured exactly as follows.

### 📈 AI Recommendation Summary
- **For Potential Buyers:** [State your final verdict as **Strong Buy**, **Buy**, **Sell**, or **Strong Sell**. Only use **Hold/Wait** if absolutely necessary. Justify your reasoning in 1-2 sentences.]
- **For Existing Shareholders:** [Provide a clear recommendation: **Hold**, **Add to Position**, **Trim Position**, **Sell**. Justify your reasoning in 1-2 sentences.]
---
### 💡 Key Insights & Rationale
[Explain the core reasons for your recommendation. What is the single most important factor driving your decision? (e.g., strong earnings, overvaluation, technical breakout, etc.)]
---
### ⚠️ Key Risks
[Identify the two most significant risks associated with this stock.]
"""
                response = co.chat(model="command-r-plus-08-2024", message=prompt, temperature=0.3)
            else:
                response = co.chat(model="command-r-plus-08-2024", message=question, chat_history=chat_history, temperature=0.3)
            return response.text
        except Exception as e:
            print(f"Cohere API error with key index {cohere_key_manager.current_index}: {e}")
            cohere_key_manager.rotate_key()

    return "### Error\nAll AI analysis API keys failed. Please contact support."


# --- Flask Routes ---
@app.route("/")
def home():
    # --- MODIFIED ---
    # We no longer call the FMP APIs here, as they require a paid plan.
    # We will pass empty lists to the template and build the homepage
    # with static content instead.
    gainers, losers = [], []
    large_cap, mid_cap, small_cap, tech_industry = [], [], [], []
    # --- END MODIFICATION ---
    
    return render_template("index.html", 
                           gainers=gainers, 
                           losers=losers,
                           large_cap=large_cap,
                           mid_cap=mid_cap,
                           small_cap=small_cap,
                           tech_industry=tech_industry)

@app.route("/about")
def about():
    return render_template('about.html', title='About Us')

@app.route("/contact")
def contact():
    return render_template('contact.html', title='Contact Us')

@app.route("/history")
@login_required
def history():
    user_history = AnalysisHistory.query.filter_by(user_id=current_user.id)\
                                        .order_by(AnalysisHistory.date_analyzed.desc()).all()
    return render_template('history.html', title='Analysis History', history=user_history)

@app.route("/get_live_price/<symbol>")
@login_required
def get_live_price(symbol):
    try:
        base_url = "https://financialmodelingprep.com/stable"  # <-- Use stable
        quote_data = safe_fetch(f"{base_url}/quote?symbol={symbol.upper()}") # <-- Add ?symbol=
        
        if not quote_data or 'error' in quote_data or (isinstance(quote_data, list) and not quote_data):
            if quote_data and 'Error Message' in quote_data[0]:
                 return jsonify({'error': 'Cannot fetch live price. API plan does not support this symbol.'}), 402
            return jsonify({'error': 'Could not fetch live price.'}), 404

        if isinstance(quote_data, list):
            quote_data = quote_data[0]

        return jsonify({
            'price': quote_data.get('price', 0.0),
            'change': quote_data.get('change', 0.0),
            'changesPercentage': quote_data.get('changesPercentage', 0.0)
        })
    except Exception as e:
        print(f"Error fetching live price for {symbol}: {e}")
        return jsonify({'error': 'Server error fetching live price.'}), 500

# --- User Auth Routes ---
@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if User.query.filter_by(email=email).first():
            flash('Email address is already registered.', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Username is already taken.', 'danger')
            return redirect(url_for('register'))

        otp = random.randint(100000, 999999)
        session['otp'] = otp
        session['otp_expiry'] = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
        session['registration_data'] = {'username': username, 'email': email, 'password': password}

        if send_otp_email(email, otp):
            flash('An OTP has been sent to your email. Please verify to complete registration.', 'info')
            return redirect(url_for('verify_otp'))
        else:
            flash('Failed to send OTP. Please check your email settings and try again later.', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html', title='Register')

@app.route("/verify_otp", methods=['GET', 'POST'])
def verify_otp():
    if 'registration_data' not in session:
        return redirect(url_for('register'))

    if request.method == 'POST':
        user_otp = request.form.get('otp')
        try:
            user_otp = int(user_otp)
        except (ValueError, TypeError):
            flash('Invalid OTP format. Please enter numbers only.', 'danger')
            return render_template('verify_otp.html', title='Verify OTP')

        if 'otp' in session and session['otp'] == user_otp:
            expiry_time = datetime.fromisoformat(session['otp_expiry'])
            if datetime.utcnow() > expiry_time:
                flash('OTP has expired. Please register again.', 'danger')
                session.pop('otp', None)
                session.pop('registration_data', None)
                return redirect(url_for('register'))

            reg_data = session['registration_data']
            hashed_password = bcrypt.generate_password_hash(reg_data['password']).decode('utf-8')
            user = User(username=reg_data['username'], email=reg_data['email'], password=hashed_password, is_verified=True)
            db.session.add(user)
            db.session.commit()

            session.pop('otp', None)
            session.pop('registration_data', None)

            flash('Your account has been created and verified! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')

    return render_template('verify_otp.html', title='Verify OTP')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            if not user.is_verified:
                flash('Your account is not verified. Please check your email for the verification link or register again.', 'warning')
                return redirect(url_for('login'))
            if user.is_blocked:
                flash('Your account has been blocked by an administrator.', 'danger')
                return redirect(url_for('login'))

            login_user(user, remember=True)
            log_activity('User logged in')
            
            if user.is_admin:
                next_page = url_for('admin.dashboard')
            else:
                next_page = request.args.get('next') or url_for('home')

            flash('Login Successful!', 'success')
            return redirect(next_page)
        else:
            flash('Login Unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', title='Login')


@app.route("/logout")
@login_required
def logout():
    log_activity('User logged out')
    logout_user()
    return redirect(url_for('home'))

# --- Account & Payment Routes ---
@app.route("/account")
@login_required
def account():
    return render_template('account.html', title='My Account', RAZORPAY_KEY_ID=RAZORPAY_KEY_ID)

@app.route('/create_order', methods=['POST'])
@login_required
def create_order():
    data = request.get_json()
    amount_in_inr = data.get('amount')
    coins = data.get('coins')
    if not amount_in_inr or not coins:
        return jsonify({'error': 'Missing amount or coin data'}), 400

    amount_in_paise = int(float(amount_in_inr) * 100)

    order_data = {
        'amount': amount_in_paise,
        'currency': 'INR',
        'receipt': f'order_rcptid_{current_user.id}_{int(datetime.now().timestamp())}',
        'notes': {
            'user_id': current_user.id,
            'coins': coins
        }
    }
    try:
        order = razorpay_client.order.create(data=order_data)
        new_order = Order(
            order_id=order['id'],
            amount=amount_in_inr,
            coins_purchased=coins,
            customer=current_user
        )
        db.session.add(new_order)
        db.session.commit()
        return jsonify(order)
    except Exception as e:
        print(f"Razorpay order creation failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/verify_payment', methods=['POST'])
@login_required
def verify_payment():
    data = request.get_json()
    razorpay_order_id = data['razorpay_order_id']
    razorpay_payment_id = data['razorpay_payment_id']
    razorpay_signature = data['razorpay_signature']

    order = Order.query.filter_by(order_id=razorpay_order_id).first()
    if not order:
        return jsonify({'redirect_url': url_for('payment_failure')})

    params_dict = {
        'razorpay_order_id': razorpay_order_id,
        'razorpay_payment_id': razorpay_payment_id,
        'razorpay_signature': razorpay_signature
    }
    try:
        razorpay_client.utility.verify_payment_signature(params_dict)

        order.status = 'successful'
        order.payment_id = razorpay_payment_id
        current_user.coins += order.coins_purchased
        log_activity(f'Purchased {order.coins_purchased} coins')
        create_notification(current_user.id, f"Successfully purchased {order.coins_purchased} coins.")
        db.session.commit()

        flash(f'{order.coins_purchased} coins have been successfully added to your account!', 'success')
        return jsonify({'redirect_url': url_for('payment_success')})

    except razorpay.errors.SignatureVerificationError:
        order.status = 'failed'
        db.session.commit()
        return jsonify({'redirect_url': url_for('payment_failure')})

@app.route('/payment_success')
@login_required
def payment_success():
    return render_template('payment_success.html')

@app.route('/payment_failure')
@login_required
def payment_failure():
    return render_template('payment_failure.html')


# --- Analysis Routes ---
@app.route("/loading/<symbol>")
@login_required
def loading(symbol):
    if current_user.coins < 1:
        flash('You do not have enough coins for an analysis. Please get more coins from your account page.', 'danger')
        return redirect(url_for('account'))
    return render_template("loading.html", symbol=symbol)

@app.route("/analyze")
@login_required
def analyze():
    if current_user.coins < 1:
        flash('You do not have enough coins for an analysis.', 'danger')
        return redirect(url_for('account'))

    symbol = request.args.get("symbol", "").strip().upper()
    if not symbol:
        return render_template("error.html", error="Stock symbol cannot be empty.")
    try:
        stock_data = get_stock_data(symbol)
        stock_data = clean_stock_data(stock_data)
        ai_analysis_text = analyze_with_ai(stock_data, symbol)
        
        if "### Error" in ai_analysis_text:
             return render_template("error.html", error=ai_analysis_text.replace("### Error\n", ""))

        recommendation, rec_color = parse_ai_recommendation(ai_analysis_text)

        history_entry = AnalysisHistory(
            symbol=symbol,
            recommendation=recommendation,
            full_analysis=ai_analysis_text,
            price_at_analysis=stock_data['quote'].get('price', 0.0),
            rec_color=rec_color,
            author=current_user
        )
        db.session.add(history_entry)

        current_user.coins -= 1
        log_activity(f'Analyzed stock: {symbol}')
        # FEAT: Create notification instead of flashing a message
        create_notification(current_user.id, f"1 coin was deducted for analyzing {symbol}.")
        
        db.session.commit()

        return render_template("result.html",
                               symbol=symbol,
                               data=stock_data,
                               analysis=ai_analysis_text,
                               recommendation=recommendation,
                               rec_color=rec_color,
                               history_id=history_entry.id)
    except ValueError as e:
        return render_template("error.html", error=str(e))
    except Exception as e:
        print(f"An unexpected error occurred during template rendering: {e}")
        return render_template("error.html", error="An unexpected server error occurred while trying to display the results.")


@app.route("/ask_ai", methods=['POST'])
@login_required
def ask_ai():
    if current_user.coins < 1:
        return jsonify({'error': 'Insufficient coins for a follow-up question.'}), 403

    data = request.get_json()
    question = data.get('question')
    history_id = data.get('history_id')
    # FEAT: Get chat history from the request for context
    chat_history = data.get('chat_history', [])

    if not question or not history_id:
        return jsonify({'error': 'Missing question or history ID.'}), 400

    analysis_entry = AnalysisHistory.query.get(history_id)
    if not analysis_entry or analysis_entry.author.id != current_user.id:
        return jsonify({'error': 'Analysis not found or you do not have permission.'}), 404
    
    ai_response = analyze_with_ai(stock_data=None, symbol=None, chat_history=chat_history, question=question)

    if "### Error" in ai_response:
        return jsonify({'error': ai_response.replace("### Error\n", "")})

    current_user.coins -= 1
    log_activity(f'Asked follow-up on {analysis_entry.symbol}: "{question}"')
    # FEAT: Create notification for the follow-up question
    create_notification(current_user.id, f"1 coin was deducted for a follow-up question on {analysis_entry.symbol}.")
    db.session.commit()

    return jsonify({
        'answer': markdown(ai_response),
        'coins_remaining': current_user.coins
    })

# FEAT: Routes for notification system
@app.route('/get_notifications')
@login_required
def get_notifications():
    notifications = Notification.query.filter_by(user_id=current_user.id)\
                                      .order_by(Notification.timestamp.desc()).limit(10).all()
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    
    return jsonify({
        'notifications': [{'id': n.id, 'message': n.message, 'timestamp': n.timestamp.isoformat(), 'is_read': n.is_read} for n in notifications],
        'unread_count': unread_count
    })

@app.route('/mark_notifications_read', methods=['POST'])
@login_required
def mark_notifications_read():
    try:
        Notification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        print(f"Error marking notifications as read: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# --- Admin Panel ---
admin = Blueprint('admin', __name__, url_prefix='/admin', template_folder='templates/admin')

@admin.route('/')
@admin_required
def dashboard():
    total_users = User.query.count()
    total_analyses = AnalysisHistory.query.count()
    total_transactions = Order.query.filter_by(status='successful').count()
    recent_users = User.query.order_by(User.id.desc()).limit(5).all()
    return render_template('dashboard.html', total_users=total_users, total_analyses=total_analyses, total_transactions=total_transactions, recent_users=recent_users)

@admin.route('/users')
@admin_required
def manage_users():
    users = User.query.all()
    return render_template('users.html', users=users)

@admin.route('/user/<int:user_id>')
@admin_required
def user_detail(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('user_detail.html', user=user)

@admin.route('/user/give_coins/<int:user_id>', methods=['POST'])
@admin_required
def give_coins(user_id):
    user = User.query.get_or_404(user_id)
    try:
        coins = int(request.form.get('coins'))
        user.coins += coins
        log_activity(f'Admin gave {coins} coins to user {user.username}')
        create_notification(user.id, f"An admin has granted you {coins} coins.")
        db.session.commit()
        flash(f'Successfully gave {coins} coins to {user.username}.', 'success')
    except (ValueError, TypeError):
        flash('Invalid number of coins.', 'danger')
    return redirect(url_for('admin.user_detail', user_id=user.id))

@admin.route('/user/block/<int:user_id>')
@admin_required
def block_user(user_id):
    user = User.query.get_or_404(user_id)
    if not user.is_admin:
        user.is_blocked = True
        db.session.commit()
        log_activity(f'Admin blocked user {user.username}')
        flash(f'User {user.username} has been blocked.', 'success')
    else:
        flash('Cannot block an admin account.', 'danger')
    return redirect(url_for('admin.manage_users'))

@admin.route('/user/unblock/<int:user_id>')
@admin_required
def unblock_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_blocked = False
    db.session.commit()
    log_activity(f'Admin unblocked user {user.username}')
    flash(f'User {user.username} has been unblocked.', 'success')
    return redirect(url_for('admin.manage_users'))

@admin.route('/activity')
@admin_required
def activity_log():
    activities = UserActivity.query.order_by(UserActivity.timestamp.desc()).all()
    return render_template('activity_log.html', activities=activities)

app.register_blueprint(admin)

# --- Main Execution ---
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(is_admin=True).first():
            hashed_password = bcrypt.generate_password_hash('adminpassword').decode('utf-8')
            admin_user = User(username='admin', email='admin@aistockanalyzer.demo', password=hashed_password, is_admin=True, is_verified=True)
            db.session.add(admin_user)
            db.session.commit()
            print("Default admin user created with username 'admin' and password 'adminpassword'")
        if not Coupon.query.first():
            coupon1 = Coupon(code='SAVE20', discount=20, is_active=True)
            coupon2 = Coupon(code='NEWUSER', discount=50, is_active=True, expiry_date=datetime.utcnow() + timedelta(days=30))
            db.session.add(coupon1)
            db.session.add(coupon2)
            db.session.commit()
            print("Sample coupons created.")
    app.run(host='0.0.0.0', port=5000, debug=True)
