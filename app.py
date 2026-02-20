import eventlet
eventlet.monkey_patch()

import os
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, abort, flash, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from sqlalchemy import or_, and_, func, case, Index
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, EmailField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, Email, Regexp
from flask_socketio import SocketIO, emit, join_room
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# --- تنظیمات اولیه ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_key_change_in_prod')

# تنظیم دیتابیس
database_url = os.getenv("DATABASE_URL")
if not database_url:
    basedir = os.path.abspath(os.path.dirname(__file__))
    database_url = 'sqlite:///' + os.path.join(basedir, 'app.db')
else:
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_pre_ping": True,
    "pool_recycle": 300,
}

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
limiter = Limiter(key_func=get_remote_address, app=app, storage_uri="memory://")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# --- مدیریت وضعیت آنلاین‌ها ---
ONLINE_USERS_MEMORY = set()

class StateManager:
    @staticmethod
    def set_online(user_id):
        ONLINE_USERS_MEMORY.add(user_id)

    @staticmethod
    def set_offline(user_id):
        if user_id in ONLINE_USERS_MEMORY:
            ONLINE_USERS_MEMORY.remove(user_id)

    @staticmethod
    def is_online(user_id):
        return user_id in ONLINE_USERS_MEMORY

# --- مدل‌های دیتابیس ---
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True) # جدید
    major = db.Column(db.String(100))
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, server_default=func.now())

class Message(db.Model):
    __tablename__ = 'message'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=func.now(), index=True)
    read_at = db.Column(db.DateTime, nullable=True)

    __table_args__ = (
        Index('idx_sender_receiver_timestamp', 'sender_id', 'receiver_id', 'timestamp'),
    )

# --- سرویس‌ها ---
class AuthService:
    @staticmethod
    def register_user(name, email, major, password):
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(name=name, email=email, major=major, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return new_user

    @staticmethod
    def authenticate_user(username, password):
        user = User.query.filter(
            or_(User.name == username, User.email == username) # ورود با نام کاربری یا ایمیل
        ).first()
        if user and check_password_hash(user.password_hash, password):
            return user
        return None

class ChatService:
    @staticmethod
    def get_inbox_conversations(user_id):
        other_user_id = case(
            (Message.sender_id == user_id, Message.receiver_id),
            else_=Message.sender_id
        ).label("other_user_id")

        subquery = db.session.query(
            func.max(Message.id).label("last_message_id")
        ).filter(
            or_(Message.sender_id == user_id, Message.receiver_id == user_id)
        ).group_by(other_user_id).subquery()

        results = db.session.query(Message, User, 
            func.sum(case((and_(Message.receiver_id == user_id, Message.read_at.is_(None)), 1), else_=0)).label("unread_count")
        ).join(
            subquery, Message.id == subquery.c.last_message_id
        ).join(
            User, User.id == other_user_id
        ).group_by(Message.id, User.id).order_by(Message.timestamp.desc()).all()

        conversations = []
        for msg, other_user, unread in results:
            conversations.append({
                'other_user_id': other_user.id,
                'other_user_name': other_user.name,
                'last_message_content': msg.content,
                'last_message_timestamp': msg.timestamp,
                'has_unread': unread > 0,
                'is_online': StateManager.is_online(other_user.id) 
            })
        return conversations

    @staticmethod
    def get_chat_history(current_user_id, other_user_id, limit=50):
        Message.query.filter(
            and_(Message.sender_id == other_user_id, 
                 Message.receiver_id == current_user_id, 
                 Message.read_at.is_(None))
        ).update({Message.read_at: func.now()}, synchronize_session=False)
        db.session.commit()

        messages = Message.query.filter(
            or_(
                and_(Message.sender_id == current_user_id, Message.receiver_id == other_user_id),
                and_(Message.sender_id == other_user_id, Message.receiver_id == current_user_id)
            )
        ).order_by(Message.timestamp.desc()).limit(limit).all()
        
        return messages[::-1]

    @staticmethod
    def save_message(sender_id, receiver_id, content):
        msg = Message(sender_id=sender_id, receiver_id=receiver_id, content=content)
        db.session.add(msg)
        db.session.commit()
        return msg

# --- فرم‌ها ---
MAJOR_CHOICES = [('', 'رشته خود را انتخاب کنید'), ('مهندسی کامپیوتر', 'مهندسی کامپیوتر'), ('علوم کامپیوتر', 'علوم کامپیوتر')]

class RegistrationForm(FlaskForm):
    name = StringField('نام کاربری', validators=[DataRequired(), Length(min=4, max=100), Regexp('^[A-Za-z0-9_.]+$', message="فقط حروف انگلیسی، اعداد و _ و . مجاز است")])
    email = EmailField('ایمیل', validators=[DataRequired(), Email(message="فرمت ایمیل نامعتبر است")])
    major = SelectField('رشته تحصیلی', choices=MAJOR_CHOICES, validators=[DataRequired()])
    password = PasswordField('رمز عبور', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('تکرار رمز عبور', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('ثبت‌نام')
    
    def validate_name(self, field):
        if User.query.filter_by(name=field.data).first():
            raise ValidationError('این نام کاربری قبلاً استفاده شده است.')
            
    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('این ایمیل قبلاً ثبت شده است.')

class LoginForm(FlaskForm):
    username = StringField('نام کاربری یا ایمیل', validators=[DataRequired()])
    password = PasswordField('رمز عبور', validators=[DataRequired()])
    submit = SubmitField('ورود')

class UpdateProfileForm(FlaskForm):
    name = StringField('نام کاربری', validators=[DataRequired(), Length(min=4, max=100), Regexp('^[A-Za-z0-9_.]+$')])
    email = EmailField('ایمیل', validators=[DataRequired(), Email()])
    major = SelectField('رشته تحصیلی', choices=MAJOR_CHOICES)
    submit = SubmitField('بروزرسانی پروفایل')
    
    def __init__(self, original_username, original_email, *args, **kwargs):
        super(UpdateProfileForm, self).__init__(*args, **kwargs)
        self.original_username = original_username
        self.original_email = original_email
        
    def validate_name(self, field):
        if field.data != self.original_username:
            if User.query.filter_by(name=field.data).first():
                raise ValidationError('نام کاربری جدید تکراری است.')
                
    def validate_email(self, field):
        if field.data != self.original_email:
            if User.query.filter_by(email=field.data).first():
                raise ValidationError('ایمیل جدید تکراری است.')

class UpdatePasswordForm(FlaskForm):
    current_password = PasswordField('رمز عبور فعلی', validators=[DataRequired()])
    new_password = PasswordField('رمز عبور جدید', validators=[DataRequired(), Length(min=6)])
    confirm_new_password = PasswordField('تکرار رمز عبور جدید', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('تغییر رمز عبور')

class DeleteAccountForm(FlaskForm):
    submit = SubmitField('حذف حساب کاربری')

# --- دکوراتورها ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'current_user_id' not in session:
            flash('برای دسترسی به این صفحه باید وارد شوید.', 'info')
            return redirect(url_for('show_auth_page'))
        return f(*args, **kwargs)
    return decorated_function

# --- Context Processors (بهینه‌سازی شده) ---
@app.context_processor
def inject_user():
    # استفاده از سشن برای جلوگیری از کوئری دیتابیس در هر درخواست
    user_id = session.get('current_user_id')
    user_name = session.get('current_user_name')
    
    if user_id and user_name:
        return dict(current_user={'id': user_id, 'name': user_name}, current_user_id=user_id)
    return dict(current_user=None, current_user_id=None)

# --- روت‌ها ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/auth')
def show_auth_page():
    if session.get('current_user_id'):
        return redirect(url_for('match'))
    return render_template('register.html', form=RegistrationForm(), login_form=LoginForm())

@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = AuthService.register_user(form.name.data, form.email.data, form.major.data, form.password.data)
        session['current_user_id'] = user.id
        session['current_user_name'] = user.name # ذخیره نام در سشن
        flash('ثبت‌نام موفقیت‌آمیز بود.', 'success')
        return redirect(url_for('match'))
    return render_template('register.html', form=form, login_form=LoginForm())

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user = AuthService.authenticate_user(login_form.username.data, login_form.password.data)
        if user:
            session['current_user_id'] = user.id
            session['current_user_name'] = user.name # ذخیره نام در سشن
            flash('خوش آمدید.', 'success')
            return redirect(url_for('match'))
        else:
            flash('نام کاربری/ایمیل یا رمز عبور اشتباه است.', 'error')
    return render_template('register.html', form=RegistrationForm(), login_form=login_form)

@app.route('/logout')
@login_required
def logout():
    StateManager.set_offline(session.get('current_user_id'))
    session.clear() # پاکسازی کامل سشن
    flash('خروج موفقیت‌آمیز.', 'info')
    return redirect(url_for('show_auth_page'))

@app.route('/match')
@login_required
def match():
    current_user_id = session['current_user_id']
    q = request.args.get('q', '')
    query = User.query.filter(User.id != current_user_id)
    if q:
        users = query.filter((User.major.contains(q)) | (User.name.contains(q))).all()
    else:
        users = query.all()
    return render_template('match.html', users=users)

@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    current_user_id = session['current_user_id']
    user = db.session.get(User, user_id) # متد جدید SQLAlchemy 2.0
    if not user:
        abort(404)
        
    can_edit = (current_user_id == user_id)
    
    forms = {
        'update_profile': UpdateProfileForm(obj=user, original_username=user.name, original_email=user.email) if can_edit else None,
        'update_password': UpdatePasswordForm() if can_edit else None,
        'delete_account': DeleteAccountForm() if can_edit else None
    }
    
    return render_template('profile.html', user=user, can_edit=can_edit, 
                           update_profile_form=forms['update_profile'],
                           update_password_form=forms['update_password'],
                           delete_account_form=forms['delete_account'])

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    user_id = session['current_user_id']
    user = db.session.get(User, user_id)
    if not user: abort(404)
    
    form = UpdateProfileForm(obj=user, original_username=user.name, original_email=user.email)
    if form.validate_on_submit():
        user.name = form.name.data
        user.email = form.email.data # آپدیت ایمیل
        user.major = form.major.data
        db.session.commit()
        
        # آپدیت سشن
        session['current_user_name'] = user.name
        
        flash('پروفایل بروزرسانی شد.', 'success')
    return redirect(url_for('profile', user_id=user_id))

@app.route('/update_password', methods=['POST'])
@login_required
def update_password():
    user_id = session['current_user_id']
    user = db.session.get(User, user_id)
    if not user: abort(404)
    
    form = UpdatePasswordForm()
    if form.validate_on_submit():
        if check_password_hash(user.password_hash, form.current_password.data):
            user.password_hash = generate_password_hash(form.new_password.data, method='pbkdf2:sha256')
            db.session.commit()
            flash('رمز عبور تغییر کرد.', 'success')
        else:
            flash('رمز عبور فعلی اشتباه است.', 'error')
    return redirect(url_for('profile', user_id=user_id))

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user_id = session['current_user_id']
    user = db.session.get(User, user_id)
    if user:
        StateManager.set_offline(user_id)
        db.session.delete(user)
        db.session.commit()
    session.clear()
    flash('حساب کاربری حذف شد.', 'info')
    return redirect(url_for('show_auth_page'))

@app.route('/chat/<int:other_user_id>')
@login_required
def chat(other_user_id):
    current_user_id = session['current_user_id']
    if current_user_id == other_user_id:
        return redirect(url_for('inbox'))
    
    other_user = db.session.get(User, other_user_id)
    if not other_user: abort(404)
        
    messages = ChatService.get_chat_history(current_user_id, other_user_id)
    return render_template('chat.html', other_user=other_user, messages=messages)

@app.route('/inbox')
@login_required
def inbox():
    current_user_id = session['current_user_id']
    conversations = ChatService.get_inbox_conversations(current_user_id)
    return render_template('inbox.html', conversations=conversations, user_id=current_user_id)

@app.route('/api/user_status/<int:user_id>')
def check_user_online(user_id):
    return jsonify({'online': StateManager.is_online(user_id)})

# --- سوکت هندلرها ---
@socketio.on('connect')
def handle_connect():
    current_user_id = session.get('current_user_id')
    if current_user_id:
        StateManager.set_online(current_user_id)

@socketio.on('disconnect')
def handle_disconnect():
    current_user_id = session.get('current_user_id')
    if current_user_id:
        StateManager.set_offline(current_user_id)

@socketio.on('join_chat')
def handle_join_chat(data):
    current_user_id = session.get('current_user_id')
    if not current_user_id: return
    other_user_id = data['other_user_id']
    room_id = f"chat-{min(current_user_id, other_user_id)}-{max(current_user_id, other_user_id)}"
    join_room(room_id)
    user_name = session.get('current_user_name', 'کاربر') # استفاده از سشن
    emit('status_message', {'msg': f"{user_name} متصل شد.", 'type': 'join'}, room=room_id, include_self=False)

@socketio.on('send_message')
def handle_send_message(data):
    current_user_id = session.get('current_user_id')
    if not current_user_id: return
    other_user_id = data.get('other_user_id')
    content = data.get('content')
    if not other_user_id or not content: return

    msg = ChatService.save_message(current_user_id, other_user_id, content)
    room_id = f"chat-{min(current_user_id, other_user_id)}-{max(current_user_id, other_user_id)}"
    
    user_name = session.get('current_user_name', 'کاربر')
    emit('new_message', {
        'sender_name': user_name,
        'content': content,
        'timestamp': msg.timestamp.strftime('%H:%M'),
        'sender_id': current_user_id,
        'message_id': msg.id
    }, room=room_id, include_self=False)

@socketio.on('typing')
def handle_typing(data):
    current_user_id = session.get('current_user_id')
    if current_user_id and data.get('room'):
        emit('typing', {'user_id': current_user_id}, room=data['room'], include_self=False)

@socketio.on('stop_typing')
def handle_stop_typing(data):
    current_user_id = session.get('current_user_id')
    if current_user_id and data.get('room'):
        emit('stop_typing', {'user_id': current_user_id}, room=data['room'], include_self=False)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port)