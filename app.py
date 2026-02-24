import eventlet
eventlet.monkey_patch()

import os
import jdatetime
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, abort, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from sqlalchemy import or_, and_, func, case, Index
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask_socketio import SocketIO, emit, join_room
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# --- تنظیمات ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'super-secret-key-change-me')
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

# --- مدیریت آنلاین ---
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
    content = db.Column(db.Text, nullable=True)
    file_path = db.Column(db.String(255), nullable=True)
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
    professor_name = db.Column(db.String(100), nullable=True)
    week_type = db.Column(db.String(10), default='all')

class MasterSchedule(db.Model):
    __tablename__ = 'master_schedule'
    id = db.Column(db.Integer, primary_key=True)
    day = db.Column(db.String(10), nullable=False)
    time_slot = db.Column(db.String(20), nullable=False)
    rooms = db.Column(db.Text, nullable=False)

class Reservation(db.Model):
    __tablename__ = 'reservation'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    master_slot_id = db.Column(db.Integer, db.ForeignKey('master_schedule.id'), nullable=False)
    room_name = db.Column(db.String(50), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, server_default=func.now())

class CancelledClass(db.Model):
    __tablename__ = 'cancelled_class'
    id = db.Column(db.Integer, primary_key=True)
    professor_name = db.Column(db.String(100), nullable=True)
    course_name = db.Column(db.String(100), nullable=True)
    cancel_date = db.Column(db.Date, nullable=True)
    start_date = db.Column(db.Date, nullable=True)
    end_date = db.Column(db.Date, nullable=True)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, server_default=func.now())

class GroupMessage(db.Model):
    __tablename__ = 'group_message'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=True)
    file_path = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, server_default=func.now())

class ChannelMessage(db.Model):
    __tablename__ = 'channel_message'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    file_path = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, server_default=func.now())

class Notification(db.Model):
    __tablename__ = 'notification'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, server_default=func.now())

class SystemSetting(db.Model):
    __tablename__ = 'system_setting'
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.String(100), nullable=True)

# --- فرم‌ها ---
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

# --- دکوراتورها ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'current_user_id' not in session:
            if request.is_json: return jsonify({'error': 'Unauthorized'}), 401
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
    return datetime.now().isocalendar()[1]

def check_weekly_reset():
    try:
        setting = SystemSetting.query.get('last_reset_week')
        current_week = str(get_week_number())
        if not setting:
            setting = SystemSetting(key='last_reset_week', value=current_week)
            db.session.add(setting)
            db.session.commit()
            return
        if setting.value != current_week:
            Reservation.query.delete()
            setting.value = current_week
            db.session.commit()
    except Exception as e:
        print(f"Weekly reset error: {e}")
        db.session.rollback()

# --- روت‌های اصلی ---
@app.route('/')
def index():
    check_weekly_reset()
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
        try:
            hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
            is_admin = (form.student_id.data == 'admin')
            new_user = User(full_name=form.full_name.data, student_id=form.student_id.data, major=form.major.data, password_hash=hashed_password, is_admin=is_admin)
            db.session.add(new_user)
            db.session.commit()
            session['current_user_id'] = new_user.id
            session['current_user_name'] = new_user.full_name
            session['current_user_pic'] = new_user.profile_pic
            session['is_admin'] = new_user.is_admin
            flash('ثبت‌نام موفق.', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('خطا در ثبت نام.', 'error')
    return render_template('register.html', form=form, login_form=LoginForm())

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user = User.query.filter_by(student_id=login_form.student_id.data).first()
        if user and check_password_hash(user.password_hash, login_form.password.data):
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
    
    today_j = jdatetime.date.today()
    weekday_name = ['شنبه', 'یکشنبه', 'دوشنبه', 'سه شنبه', 'چهارشنبه', 'پنجشنبه', 'جمعه'][today_j.weekday()]
    
    cancelled = CancelledClass.query.filter(
        or_(
            CancelledClass.cancel_date == today_j.togregorian(),
            and_(CancelledClass.start_date <= today_j.togregorian(), CancelledClass.end_date >= today_j.togregorian())
        )
    ).all()
    
    notifications = Notification.query.filter_by(user_id=current_user_id, is_read=False).order_by(Notification.created_at.desc()).limit(5).all()

    return render_template('dashboard.html', 
                           schedules=my_schedules, 
                           today_j=today_j, 
                           weekday_name=weekday_name,
                           cancelled_classes=cancelled,
                           notifications=notifications)

# --- APIهای داخلی (CSRF Exempt for AJAX) ---
@app.route('/api/update_schedule', methods=['POST'])
@csrf.exempt
@login_required
def api_update_schedule():
    try:
        data = request.json
        user_id = session['current_user_id']
        
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
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/bulk_add_schedule', methods=['POST'])
@csrf.exempt
@login_required
def api_bulk_add_schedule():
    try:
        data = request.json
        user_id = session['current_user_id']
        items = data.get('items', [])
        
        for item in items:
            if not item.get('course_name'): continue
            
            # حذف قبلی برای آن روز و ساعت
            ClassSchedule.query.filter_by(user_id=user_id, day=item['day'], time_slot=item['time_slot']).delete()
            
            new_schedule = ClassSchedule(
                user_id=user_id,
                day=item['day'],
                time_slot=item['time_slot'],
                course_name=item['course_name'],
                class_location=item.get('location', ''),
                professor_name=item.get('professor', ''),
                week_type=item.get('week_type', 'all')
            )
            db.session.add(new_schedule)
            
        db.session.commit()
        return jsonify({'status': 'success', 'count': len(items)})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/master_schedule')
@login_required
def get_master_schedule():
    slots = MasterSchedule.query.all()
    reservations = Reservation.query.filter_by(status='approved').all()
    reserved_map = {f"{r.master_slot_id}_{r.room_name}": True for r in reservations}

    output = []
    for s in slots:
        rooms_list = [r.strip() for r in s.rooms.split(',')]
        available_rooms = [room for room in rooms_list if f"{s.id}_{room}" not in reserved_map]
        
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
    cancelled = CancelledClass.query.order_by(CancelledClass.created_at.desc()).limit(10).all()
    pending_requests = Reservation.query.filter_by(status='pending').all()
    master_slots = MasterSchedule.query.all()
    return render_template('admin_dashboard.html', slots=master_slots, requests=pending_requests, cancelled_classes=cancelled)

@app.route('/admin/save_master_schedule', methods=['POST'])
@csrf.exempt
@admin_required
def save_master_schedule():
    try:
        data = request.json
        MasterSchedule.query.delete()
        for item in data:
            if item['rooms']:
                slot = MasterSchedule(day=item['day'], time_slot=item['time_slot'], rooms=item['rooms'])
                db.session.add(slot)
        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/admin/handle_reservation/<int:req_id>/<string:action>')
@admin_required
def handle_reservation(req_id, action):
    req = Reservation.query.get_or_404(req_id)
    if action == 'approve':
        req.status = 'approved'
        msg = f"درخواست رزرو شما برای کلاس {req.room_name} تایید شد."
        notif = Notification(user_id=req.user_id, message=msg)
        db.session.add(notif)
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
    try:
        c_date = request.form.get('date')
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        
        new_cancel = CancelledClass(
            professor_name=request.form.get('professor'),
            course_name=request.form.get('course'),
            description=request.form.get('desc'),
            cancel_date=datetime.strptime(c_date, '%Y-%m-%d').date() if c_date else None,
            start_date=datetime.strptime(start_date, '%Y-%m-%d').date() if start_date else None,
            end_date=datetime.strptime(end_date, '%Y-%m-%d').date() if end_date else None
        )
        db.session.add(new_cancel)
        db.session.commit()
        flash('لغو کلاس ثبت شد.', 'success')
    except Exception as e:
        flash('خطا در ثبت.', 'error')
    return redirect(url_for('admin_dashboard'))

# --- پروفایل ---
@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    user = db.session.get(User, user_id) or abort(404)
    can_edit = (session['current_user_id'] == user_id)
    forms = {}
    if can_edit:
        from wtforms import PasswordField
        class TempProfileForm(FlaskForm):
            full_name = StringField('نام', validators=[DataRequired()])
            major = SelectField('رشته', choices=MAJOR_CHOICES)
            submit = SubmitField('بروزرسانی')
        
        class TempPasswordForm(FlaskForm):
            current_password = PasswordField('رمز فعلی', validators=[DataRequired()])
            new_password = PasswordField('رمز جدید', validators=[DataRequired()])
            confirm_new_password = PasswordField('تکرار', validators=[DataRequired(), EqualTo('new_password')])
            submit = SubmitField('تغییر رمز')
            
        forms['update_profile'] = TempProfileForm(obj=user)
        forms['update_password'] = TempPasswordForm()
        
    return render_template('profile.html', user=user, can_edit=can_edit, forms=forms)

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    user = db.session.get(User, session['current_user_id'])
    if user and request.form.get('full_name'):
        user.full_name = request.form.get('full_name')
        user.major = request.form.get('major')
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and file.filename:
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
    user = db.session.get(User, session['current_user_id'])
    if user:
        curr_pwd = request.form.get('current_password')
        new_pwd = request.form.get('new_password')
        if check_password_hash(user.password_hash, curr_pwd):
            user.password_hash = generate_password_hash(new_pwd, method='pbkdf2:sha256')
            db.session.commit()
            flash('رمز عبور تغییر کرد.', 'success')
        else:
            flash('رمز فعلی اشتباه است.', 'error')
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
    # دریافت تاریخچه پیام‌های خصوصی
    conversations = []
    other_user_id = request.args.get('user_id', type=int)
    active_chat_user = None
    messages = []
    
    # منطق پیام‌های خصوصی
    if other_user_id:
        active_chat_user = db.session.get(User, other_user_id)
        if active_chat_user:
            # علامت‌گذاری خوانده شده
            Message.query.filter(and_(Message.sender_id == other_user_id, Message.receiver_id == session['current_user_id'], Message.read_at.is_(None))).update({Message.read_at: func.now()}, synchronize_session=False)
            db.session.commit()
            
            messages = Message.query.filter(or_(
                and_(Message.sender_id == session['current_user_id'], Message.receiver_id == other_user_id),
                and_(Message.sender_id == other_user_id, Message.receiver_id == session['current_user_id'])
            )).order_by(Message.timestamp.asc()).all()
    
    # لیست گفتگوها
    subq = db.session.query(Message.receiver_id, Message.sender_id, func.max(Message.timestamp).label('max_time')).filter(
        or_(Message.sender_id == session['current_user_id'], Message.receiver_id == session['current_user_id'])
    ).group_by(Message.receiver_id, Message.sender_id).subquery()
    
    # این بخش را برای سادگی بهینه کردیم
    
    # گروه و کانال
    group_messages = GroupMessage.query.order_by(GroupMessage.timestamp.asc()).limit(50).all()
    channel_messages = ChannelMessage.query.order_by(ChannelMessage.timestamp.asc()).limit(50).all()
    
    return render_template('chat.html',
                           active_chat_user=active_chat_user,
                           messages=messages,
                           group_messages=group_messages,
                           channel_messages=channel_messages)

@app.route('/upload_chat_file', methods=['POST'])
@login_required
def upload_chat_file():
    if 'file' not in request.files: return jsonify({'error': 'No file'}), 400
    file = request.files['file']
    if file and file.filename:
        filename = secure_filename(f"{session['current_user_id']}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
        file.save(os.path.join(app.config['CHAT_UPLOAD_FOLDER'], filename))
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

@app.route('/api/group_members')
@login_required
def get_group_members():
    # همه کاربران به جز ادمین (یا همه)
    members = User.query.filter(User.id != session['current_user_id']).all()
    return jsonify([{'id': m.id, 'name': m.full_name, 'pic': m.profile_pic, 'online': StateManager.is_online(m.id)} for m in members])

# --- سوکت‌ها ---
@socketio.on('connect')
def handle_connect():
    if session.get('current_user_id'): 
        StateManager.set_online(session['current_user_id'])
        join_room(f"user_{session['current_user_id']}")
        join_room('public_group')
        join_room('channel')

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
    content = data.get('content', '')
    file_path = data.get('file_path')
    oid = data.get('other_user_id')
    
    if not uid or not oid: return
    
    msg = Message(sender_id=uid, receiver_id=oid, content=content, file_path=file_path)
    db.session.add(msg)
    db.session.commit()
    
    emit('new_message', {
        'sender_id': uid, 
        'sender_name': session.get('current_user_name', 'User'),
        'content': content, 
        'file_path': file_path,
        'timestamp': msg.timestamp.strftime('%H:%M')
    }, room=f"chat-{min(uid, oid)}-{max(uid, oid)}")

@socketio.on('send_group_message')
def handle_group_message(data):
    uid = session.get('current_user_id')
    content = data.get('content', '')
    file_path = data.get('file_path')
    
    msg = GroupMessage(sender_id=uid, content=content, file_path=file_path)
    db.session.add(msg)
    db.session.commit()
    
    emit('new_group_message', {
        'sender_id': uid,
        'sender_name': session.get('current_user_name', 'User'),
        'content': content,
        'file_path': file_path,
        'timestamp': msg.timestamp.strftime('%H:%M')
    }, room='public_group')

@socketio.on('send_channel_message')
def handle_channel_message(data):
    if not session.get('is_admin'): return
    
    uid = session.get('current_user_id')
    content = data.get('content', '')
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

# --- توابع راه‌اندازی ---
def create_initial_data():
    db.create_all()
    if not User.query.filter_by(student_id='admin').first():
        admin = User(full_name='مدیر', student_id='admin', major='مدیریت', password_hash=generate_password_hash('admin', method='pbkdf2:sha256'), is_admin=True)
        db.session.add(admin)
        db.session.commit()
        print("Admin created.")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port)