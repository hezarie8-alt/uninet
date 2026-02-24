import eventlet
eventlet.monkey_patch()

import os
import jdatetime
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, abort, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from sqlalchemy import or_, and_, func, case, Index
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, SelectField, HiddenField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask_socketio import SocketIO, emit, join_room
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# --- تنظیمات ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_key_change_in_prod')
UPLOAD_FOLDER = 'static/uploads/profile_pics'
CHAT_UPLOAD_FOLDER = 'static/uploads/chat_files'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'docx', 'zip'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['CHAT_UPLOAD_FOLDER'] = CHAT_UPLOAD_FOLDER

# ایجاد پوشه‌ها
for folder in [UPLOAD_FOLDER, CHAT_UPLOAD_FOLDER]:
    if not os.path.exists(folder):
        os.makedirs(folder)

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
    "pool_size": 5,
    "max_overflow": 10
}
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

try:
    import psycogreen.psycopg2
    psycogreen.psycopg2.patch()
except ImportError:
    pass

db = SQLAlchemy(app)
migrate = Migrate(app, db)
limiter = Limiter(key_func=get_remote_address, app=app, storage_uri="memory://")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')
csrf = CSRFProtect(app)

# --- مدیریت آنلاین و تنظیمات سیستم ---
ONLINE_USERS_MEMORY = set()
class StateManager:
    @staticmethod
    def set_online(user_id): ONLINE_USERS_MEMORY.add(user_id)
    @staticmethod
    def set_offline(user_id):
        if user_id in ONLINE_USERS_MEMORY: ONLINE_USERS_MEMORY.remove(user_id)
    @staticmethod
    def is_online(user_id): return user_id in ONLINE_USERS_MEMORY

# --- مدل‌ها ---
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    student_id = db.Column(db.String(20), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    major = db.Column(db.String(100))
    profile_pic = db.Column(db.String(255), default='default.jpg')
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, server_default=func.now())

class Message(db.Model):
    __tablename__ = 'message'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    file_path = db.Column(db.String(255), nullable=True) # New
    timestamp = db.Column(db.DateTime, server_default=func.now(), index=True)
    read_at = db.Column(db.DateTime, nullable=True)
    __table_args__ = (Index('idx_sender_receiver_timestamp', 'sender_id', 'receiver_id', 'timestamp'),)

class ClassSchedule(db.Model):
    __tablename__ = 'schedule'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    day = db.Column(db.String(10), nullable=False)
    time_slot = db.Column(db.String(20), nullable=False)
    course_name = db.Column(db.String(100))
    class_location = db.Column(db.String(100))
    professor_name = db.Column(db.String(100), nullable=True) # New
    week_type = db.Column(db.String(10), default='all') # New: 'all', 'even', 'odd'

class MasterSchedule(db.Model):
    """برنامه کلاس‌های خالی که ادمین تعریف می‌کند"""
    __tablename__ = 'master_schedule'
    id = db.Column(db.Integer, primary_key=True)
    day = db.Column(db.String(10), nullable=False)
    time_slot = db.Column(db.String(20), nullable=False)
    rooms = db.Column(db.Text, nullable=False) # کاما جدا شده: 101,102

class Reservation(db.Model):
    """درخواست‌های رزرو"""
    __tablename__ = 'reservation'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    master_slot_id = db.Column(db.Integer, db.ForeignKey('master_schedule.id'), nullable=False)
    room_name = db.Column(db.String(50), nullable=False) # کلاس خاصی که رزرو شده
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending') # pending, approved, rejected
    created_at = db.Column(db.DateTime, server_default=func.now())

class CancelledClass(db.Model):
    """کلاس‌های لغو شده"""
    __tablename__ = 'cancelled_class'
    id = db.Column(db.Integer, primary_key=True)
    professor_name = db.Column(db.String(100), nullable=True)
    course_name = db.Column(db.String(100), nullable=True)
    cancel_date = db.Column(db.Date, nullable=True) # تاریخ دقیق لغو
    start_date = db.Column(db.Date, nullable=True) # شروع بازه لغو
    end_date = db.Column(db.Date, nullable=True) # پایان بازه لغو
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, server_default=func.now())

class GroupMessage(db.Model):
    """پیام‌های گروه عمومی"""
    __tablename__ = 'group_message'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=True)
    file_path = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, server_default=func.now())

class ChannelMessage(db.Model):
    """پیام‌های کانال (فقط ادمین)"""
    __tablename__ = 'channel_message'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    file_path = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, server_default=func.now())

class Notification(db.Model):
    """اطلاعیه‌های سیستمی برای کاربر"""
    __tablename__ = 'notification'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, server_default=func.now())

class SystemSetting(db.Model):
    """تنظیمات سیستم مثل آخرین بروزرسانی هفته"""
    __tablename__ = 'system_setting'
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.String(100), nullable=True)

# --- سرویس‌ها و فرم‌ها ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class AuthService:
    @staticmethod
    def register_user(full_name, student_id, major, password):
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        is_admin = (student_id == 'admin')
        new_user = User(full_name=full_name, student_id=student_id, major=major, password_hash=hashed_password, is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()
        return new_user

    @staticmethod
    def authenticate_user(student_id, password):
        user = User.query.filter_by(student_id=student_id).first()
        if user and check_password_hash(user.password_hash, password): return user
        return None

class ChatService:
    @staticmethod
    def get_inbox_conversations(user_id):
        other_user_id = case((Message.sender_id == user_id, Message.receiver_id), else_=Message.sender_id).label("other_user_id")
        subquery = db.session.query(func.max(Message.id).label("last_message_id")).filter(or_(Message.sender_id == user_id, Message.receiver_id == user_id)).group_by(other_user_id).subquery()
        results = db.session.query(Message, User, func.sum(case((and_(Message.receiver_id == user_id, Message.read_at.is_(None)), 1), else_=0)).label("unread_count")).join(subquery, Message.id == subquery.c.last_message_id).join(User, User.id == other_user_id).group_by(Message.id, User.id).order_by(Message.timestamp.desc()).all()
        conversations = []
        for msg, other_user, unread in results:
            conversations.append({'other_user_id': other_user.id, 'other_user_name': other_user.full_name, 'other_user_pic': other_user.profile_pic, 'last_message_content': msg.content, 'last_message_timestamp': msg.timestamp, 'has_unread': unread > 0, 'is_online': StateManager.is_online(other_user.id)})
        return conversations

    @staticmethod
    def get_chat_history(current_user_id, other_user_id, limit=50):
        Message.query.filter(and_(Message.sender_id == other_user_id, Message.receiver_id == current_user_id, Message.read_at.is_(None))).update({Message.read_at: func.now()}, synchronize_session=False)
        db.session.commit()
        messages = Message.query.filter(or_(and_(Message.sender_id == current_user_id, Message.receiver_id == other_user_id), and_(Message.sender_id == other_user_id, Message.receiver_id == current_user_id))).order_by(Message.timestamp.desc()).limit(limit).all()
        return messages[::-1]

    @staticmethod
    def save_message(sender_id, receiver_id, content, file_path=None):
        msg = Message(sender_id=sender_id, receiver_id=receiver_id, content=content, file_path=file_path)
        db.session.add(msg)
        db.session.commit()
        return msg

MAJOR_CHOICES = [('', 'انتخاب کنید'), ('مهندسی کامپیوتر', 'مهندسی کامپیوتر'), ('علوم کامپیوتر', 'علوم کامپیوتر')]
class RegistrationForm(FlaskForm):
    full_name = StringField('نام', validators=[DataRequired()])
    student_id = StringField('شماره دانشجویی', validators=[DataRequired(), Length(min=10, max=10)])
    major = SelectField('رشته', choices=MAJOR_CHOICES, validators=[DataRequired()])
    password = PasswordField('کد ملی', validators=[DataRequired(), Length(min=10, max=10)])
    confirm_password = PasswordField('تکرار', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('ثبت‌نام')
    def validate_student_id(self, field):
        if User.query.filter_by(student_id=field.data).first(): raise ValidationError('قبلاً استفاده شده است.')

class LoginForm(FlaskForm):
    student_id = StringField('شماره دانشجویی', validators=[DataRequired()])
    password = PasswordField('رمز', validators=[DataRequired()])
    submit = SubmitField('ورود')

class UpdateProfileForm(FlaskForm):
    full_name = StringField('نام', validators=[DataRequired()])
    major = SelectField('رشته', choices=MAJOR_CHOICES)
    submit = SubmitField('بروزرسانی')

class UpdatePasswordForm(FlaskForm):
    current_password = PasswordField('رمز فعلی', validators=[DataRequired()])
    new_password = PasswordField('رمز جدید', validators=[DataRequired()])
    confirm_new_password = PasswordField('تکرار', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('تغییر رمز')

class DeleteAccountForm(FlaskForm):
    submit = SubmitField('حذف حساب')

# --- دکوراتورها ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'current_user_id' not in session:
            flash('لطفا وارد شوید.', 'info')
            return redirect(url_for('show_auth_page'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            flash('دسترسی غیرمجاز.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# --- Context ---
@app.context_processor
def inject_user():
    user_id = session.get('current_user_id')
    user_name = session.get('current_user_name')
    user_pic = session.get('current_user_pic')
    is_admin = session.get('is_admin', False)
    if user_id and user_name:
        return dict(current_user={'id': user_id, 'name': user_name, 'pic': user_pic}, current_user_id=user_id, is_admin=is_admin)
    return dict(current_user=None, current_user_id=None, is_admin=False)

# --- منطق ریست هفتگی ---
def get_week_number():
    # محاسبه شماره هفته در ترم یا سال
    today = jdatetime.date.today()
    return today.week # 0-51 aprox

def check_weekly_reset():
    """چک میکند اگر هفته تغییر کرده، رزروها را پاک میکند"""
    setting = SystemSetting.query.get('last_reset_week')
    current_week = str(get_week_number())
    
    if not setting:
        setting = SystemSetting(key='last_reset_week', value=current_week)
        db.session.add(setting)
        db.session.commit()
        return
    
    if setting.value != current_week:
        # هفته جدید رسیده -> ریست
        Reservation.query.delete() # تمام رزروهای موقت حذف میشوند
        setting.value = current_week
        db.session.commit()

# --- روت‌های اصلی ---
@app.route('/')
def index():
    check_weekly_reset() # چک کردن ریست در هر بار لود
    return render_template('index.html')

@app.route('/about')
def about(): return render_template('about.html')

@app.route('/auth')
def show_auth_page():
    if session.get('current_user_id'): return redirect(url_for('dashboard'))
    return render_template('register.html', form=RegistrationForm(), login_form=LoginForm())

@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = AuthService.register_user(form.full_name.data, form.student_id.data, form.major.data, form.password.data)
        session['current_user_id'] = user.id
        session['current_user_name'] = user.full_name
        session['current_user_pic'] = user.profile_pic
        session['is_admin'] = user.is_admin
        flash('ثبت‌نام موفق.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('register.html', form=form, login_form=LoginForm())

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user = AuthService.authenticate_user(login_form.student_id.data, login_form.password.data)
        if user:
            session['current_user_id'] = user.id
            session['current_user_name'] = user.full_name
            session['current_user_pic'] = user.profile_pic
            session['is_admin'] = user.is_admin
            flash('خوش آمدید.', 'success')
            return redirect(url_for('dashboard'))
        else: flash('اطلاعات اشتباه است.', 'error')
    return render_template('register.html', form=RegistrationForm(), login_form=login_form)

@app.route('/logout')
@login_required
def logout():
    StateManager.set_offline(session.get('current_user_id'))
    session.clear()
    flash('خروج موفق.', 'info')
    return redirect(url_for('index'))

# --- داشبورد ---
@app.route('/dashboard')
@login_required
def dashboard():
    check_weekly_reset()
    current_user_id = session['current_user_id']
    my_schedules = ClassSchedule.query.filter_by(user_id=current_user_id).all()
    
    # داده‌های تاریخ شمسی
    today_j = jdatetime.date.today()
    weekday_name = ['شنبه', 'یکشنبه', 'دوشنبه', 'سه شنبه', 'چهارشنبه', 'پنجشنبه', 'جمعه'][today_j.weekday()]
    
    # کلاس‌های لغو شده
    cancelled = CancelledClass.query.filter(
        or_(
            CancelledClass.cancel_date == today_j.togregorian(),
            and_(CancelledClass.start_date <= today_j.togregorian(), CancelledClass.end_date >= today_j.togregorian())
        )
    ).all()
    
    # اطلاعیه‌های من
    notifications = Notification.query.filter_by(user_id=current_user_id, is_read=False).order_by(Notification.created_at.desc()).limit(5).all()

    return render_template('dashboard.html', 
                           schedules=my_schedules, 
                           today_j=today_j, 
                           weekday_name=weekday_name,
                           cancelled_classes=cancelled,
                           notifications=notifications)

@app.route('/update_schedule', methods=['POST'])
@csrf.exempt
@login_required
def update_schedule():
    data = request.json
    user_id = session['current_user_id']
    
    # حذف قبلی
    ClassSchedule.query.filter_by(user_id=user_id, day=data['day'], time_slot=data['time_slot']).delete()
    
    if data.get('course_name'):
        new_schedule = ClassSchedule(
            user_id=user_id, 
            day=data['day'], 
            time_slot=data['time_slot'], 
            course_name=data['course_name'], 
            class_location=data.get('class_location', ''),
            professor_name=data.get('professor_name', ''),
            week_type=data.get('week_type', 'all')
        )
        db.session.add(new_schedule)
    db.session.commit()
    return jsonify({'status': 'success'})

# --- رزرو کلاس (کاربر) ---
@app.route('/api/master_schedule')
@login_required
def get_master_schedule():
    slots = MasterSchedule.query.all()
    reservations = Reservation.query.filter_by(status='approved').all()
    
    # ساخت مپ برای دسترسی سریع به رزروهای تایید شده
    reserved_map = {}
    for r in reservations:
        key = f"{r.master_slot_id}_{r.room_name}"
        reserved_map[key] = True

    output = []
    for s in slots:
        rooms_list = [r.strip() for r in s.rooms.split(',')]
        available_rooms = []
        for room in rooms_list:
            key = f"{s.id}_{room}"
            if key not in reserved_map:
                available_rooms.append(room)
        
        output.append({
            'id': s.id, 
            'day': s.day, 
            'time_slot': s.time_slot, 
            'available_rooms': available_rooms,
            'all_rooms': rooms_list
        })
    return jsonify(output)

@app.route('/submit_reservation/<int:slot_id>/<room_name>', methods=['POST'])
@login_required
def submit_reservation(slot_id, room_name):
    reason = request.form.get('reason')
    
    # بررسی تکراری نبودن
    exists = Reservation.query.filter_by(master_slot_id=slot_id, room_name=room_name, status='approved').first()
    if exists:
        flash('این کلاس قبلاً رزرو شده است.', 'error')
        return redirect(url_for('dashboard'))

    new_req = Reservation(user_id=session['current_user_id'], master_slot_id=slot_id, room_name=room_name, reason=reason)
    db.session.add(new_req)
    db.session.commit()
    flash('درخواست رزرو ثبت شد.', 'success')
    return redirect(url_for('dashboard'))

# --- پنل ادمین ---
@app.route('/admin')
@admin_required
def admin_dashboard():
    # کلاس‌های لغو شده
    cancelled = CancelledClass.query.order_by(CancelledClass.created_at.desc()).limit(10).all()
    
    # درخواست‌های رزرو
    pending_requests = Reservation.query.filter_by(status='pending').all()
    
    # برنامه مستر
    master_slots = MasterSchedule.query.all()
    
    return render_template('admin_dashboard.html', slots=master_slots, requests=pending_requests, cancelled_classes=cancelled)

@app.route('/admin/save_master_schedule', methods=['POST'])
@admin_required
def save_master_schedule():
    data = request.json
    # data format: list of {day, time_slot, rooms}
    
    # حذف قبلی
    MasterSchedule.query.delete()
    
    for item in data:
        if item['rooms']:
            slot = MasterSchedule(day=item['day'], time_slot=item['time_slot'], rooms=item['rooms'])
            db.session.add(slot)
    
    db.session.commit()
    return jsonify({'status': 'success'})

@app.route('/admin/handle_reservation/<int:req_id>/<string:action>')
@admin_required
def handle_reservation(req_id, action):
    req = Reservation.query.get_or_404(req_id)
    
    if action == 'approve':
        req.status = 'approved'
        
        # ارسال نوتیفیکیشن به کاربر
        msg = f"درخواست رزرو شما برای کلاس {req.room_name} در {req.master_slot.day} تایید شد."
        notif = Notification(user_id=req.user_id, message=msg)
        db.session.add(notif)
        
        # رد سایر درخواست‌های برای همین کلاس
        Reservation.query.filter(
            Reservation.master_slot_id == req.master_slot_id,
            Reservation.room_name == req.room_name,
            Reservation.id != req.id,
            Reservation.status == 'pending'
        ).update({Reservation.status: 'rejected'}, synchronize_session=False)
        
        flash('تایید شد.', 'success')
        
    elif action == 'reject':
        req.status = 'rejected'
        msg = f"درخواست رزرو شما برای کلاس {req.room_name} رد شد."
        notif = Notification(user_id=req.user_id, message=msg)
        db.session.add(notif)
        flash('رد شد.', 'info')
        
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/add_cancelled_class', methods=['POST'])
@admin_required
def add_cancelled_class():
    prof = request.form.get('professor')
    course = request.form.get('course')
    desc = request.form.get('desc')
    c_date = request.form.get('date') #YYYY-MM-DD
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    
    new_cancel = CancelledClass(
        professor_name=prof,
        course_name=course,
        description=desc,
        cancel_date=datetime.strptime(c_date, '%Y-%m-%d').date() if c_date else None,
        start_date=datetime.strptime(start_date, '%Y-%m-%d').date() if start_date else None,
        end_date=datetime.strptime(end_date, '%Y-%m-%d').date() if end_date else None
    )
    db.session.add(new_cancel)
    db.session.commit()
    flash('لغو کلاس ثبت شد.', 'success')
    return redirect(url_for('admin_dashboard'))

# --- پروفایل ---
@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    user = db.session.get(User, user_id) or abort(404)
    can_edit = (session['current_user_id'] == user_id)
    forms = {'update_profile': UpdateProfileForm(obj=user) if can_edit else None, 'update_password': UpdatePasswordForm() if can_edit else None, 'delete_account': DeleteAccountForm() if can_edit else None}
    return render_template('profile.html', user=user, can_edit=can_edit, update_profile_form=forms['update_profile'], update_password_form=forms['update_password'], delete_account_form=forms['delete_account'])

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    user = db.session.get(User, session['current_user_id']) or abort(404)
    form = UpdateProfileForm(obj=user)
    if form.validate_on_submit():
        user.full_name = form.full_name.data
        user.major = form.major.data
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{user.id}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                user.profile_pic = filename
                session['current_user_pic'] = filename
        db.session.commit()
        session['current_user_name'] = user.full_name
        flash('پروفایل بروزرسانی شد.', 'success')
    return redirect(url_for('profile', user_id=user.id))

@app.route('/update_password', methods=['POST'])
@login_required
def update_password():
    user = db.session.get(User, session['current_user_id']) or abort(404)
    form = UpdatePasswordForm()
    if form.validate_on_submit():
        if check_password_hash(user.password_hash, form.current_password.data):
            user.password_hash = generate_password_hash(form.new_password.data, method='pbkdf2:sha256')
            db.session.commit()
            flash('رمز عبور تغییر کرد.', 'success')
        else: flash('رمز فعلی اشتباه است.', 'error')
    return redirect(url_for('profile', user_id=user.id))

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user = db.session.get(User, session['current_user_id'])
    if user:
        StateManager.set_offline(user.id)
        db.session.delete(user)
        db.session.commit()
    session.clear()
    flash('حساب حذف شد.', 'info')
    return redirect(url_for('index'))

# --- چت و گروه ---
@app.route('/chat')
@login_required
def chat_main():
    conversations = ChatService.get_inbox_conversations(session['current_user_id'])
    active_chat_user = None
    messages = []
    other_user_id = request.args.get('user_id', type=int)
    if other_user_id:
        active_chat_user = db.session.get(User, other_user_id)
        if active_chat_user: messages = ChatService.get_chat_history(session['current_user_id'], other_user_id)
    
    # گروه و کانال
    group_messages = GroupMessage.query.order_by(GroupMessage.timestamp.desc()).limit(50).all()
    channel_messages = ChannelMessage.query.order_by(ChannelMessage.timestamp.desc()).limit(50).all()
    
    return render_template('chat.html', 
                           conversations=conversations, 
                           active_chat_user=active_chat_user, 
                           messages=messages,
                           group_messages=group_messages[::-1],
                           channel_messages=channel_messages[::-1])

@app.route('/upload_chat_file', methods=['POST'])
@login_required
def upload_chat_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    file = request.files['file']
    if file and allowed_file(file.filename):
        filename = secure_filename(f"{session['current_user_id']}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
        filepath = os.path.join(app.config['CHAT_UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return jsonify({'filepath': f'/static/uploads/chat_files/{filename}'})
    return jsonify({'error': 'Invalid file'}), 400

@app.route('/api/user_status/<int:user_id>')
def check_user_online(user_id):
    return jsonify({'online': StateManager.is_online(user_id)})

@app.route('/mark_notification_read/<int:n_id>')
@login_required
def mark_notification_read(n_id):
    notif = Notification.query.get_or_404(n_id)
    if notif.user_id == session['current_user_id']:
        notif.is_read = True
        db.session.commit()
    return jsonify({'status': 'ok'})

# --- سوکت‌ها ---
@socketio.on('connect')
def handle_connect():
    if session.get('current_user_id'): 
        StateManager.set_online(session['current_user_id'])
        join_room(f"user_{session['current_user_id']}") # برای نوتیفیکیشن‌های شخصی

@socketio.on('disconnect')
def handle_disconnect():
    if session.get('current_user_id'): StateManager.set_offline(session['current_user_id'])

@socketio.on('join_chat')
def handle_join_chat(data):
    if session.get('current_user_id') and data.get('other_user_id'):
        uid, oid = session['current_user_id'], data['other_user_id']
        join_room(f"chat-{min(uid, oid)}-{max(uid, oid)}")

@socketio.on('send_message')
def handle_send_message(data):
    uid = session.get('current_user_id')
    if not uid or not data.get('other_user_id') or not data.get('content'): return
    
    file_path = data.get('file_path')
    msg = ChatService.save_message(uid, data['other_user_id'], data['content'], file_path)
    oid = data['other_user_id']
    
    emit('new_message', {
        'sender_name': session['current_user_name'], 
        'content': data['content'], 
        'timestamp': msg.timestamp.strftime('%H:%M'), 
        'sender_id': uid, 
        'file_path': file_path
    }, room=f"chat-{min(uid, oid)}-{max(uid, oid)}")

# گروه عمومی
@socketio.on('join_group')
def handle_join_group():
    join_room('public_group')

@socketio.on('send_group_message')
def handle_group_message(data):
    uid = session.get('current_user_id')
    content = data.get('content')
    file_path = data.get('file_path')
    
    msg = GroupMessage(sender_id=uid, content=content, file_path=file_path)
    db.session.add(msg)
    db.session.commit()
    
    emit('new_group_message', {
        'sender_id': uid,
        'sender_name': session['current_user_name'],
        'content': content,
        'file_path': file_path,
        'timestamp': msg.timestamp.strftime('%H:%M')
    }, room='public_group')

# کانال
@socketio.on('join_channel')
def handle_join_channel():
    join_room('channel')

@socketio.on('send_channel_message')
def handle_channel_message(data):
    if not session.get('is_admin'):
        return # فقط ادمین مجاز است
    
    uid = session.get('current_user_id')
    content = data.get('content')
    file_path = data.get('file_path')
    
    msg = ChannelMessage(sender_id=uid, content=content, file_path=file_path)
    db.session.add(msg)
    db.session.commit()
    
    emit('new_channel_message', {
        'sender_name': 'مدیریت',
        'content': content,
        'file_path': file_path,
        'timestamp': msg.timestamp.strftime('%H:%M')
    }, room='channel')

# --- اجرای برنامه ---
with app.app_context():
    db.create_all()
    if not User.query.filter_by(student_id='admin').first():
        admin = User(full_name='مدیر', student_id='admin', major='مدیریت', password_hash=generate_password_hash('admin', method='pbkdf2:sha256'), is_admin=True)
        db.session.add(admin)
        db.session.commit()

def create_initial_data():
    """ساخت جداول و ایجاد ادمین پیش‌فرض در صورت عدم وجود"""
    db.create_all()
    if not User.query.filter_by(student_id='admin').first():
        admin = User(
            full_name='مدیر', 
            student_id='admin', 
            major='مدیریت', 
            password_hash=generate_password_hash('admin', method='pbkdf2:sha256'), 
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        print("Admin user created.")


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port)