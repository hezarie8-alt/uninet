import eventlet
eventlet.monkey_patch()

import os
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, abort, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from sqlalchemy import or_, and_, func, case, Index
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask_socketio import SocketIO, emit, join_room
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# --- تنظیمات ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_key_change_in_prod')
UPLOAD_FOLDER = 'static/uploads/profile_pics'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

database_url = os.getenv("DATABASE_URL")
if not database_url:
    basedir = os.path.abspath(os.path.dirname(__file__))
    database_url = 'sqlite:///' + os.path.join(basedir, 'app.db')
else:
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {"pool_pre_ping": True, "pool_recycle": 300}
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
limiter = Limiter(key_func=get_remote_address, app=app, storage_uri="memory://")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

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
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=func.now(), index=True)
    read_at = db.Column(db.DateTime, nullable=True)
    __table_args__ = (Index('idx_sender_receiver_timestamp', 'sender_id', 'receiver_id', 'timestamp'),)

# مدل برنامه شخصی (اجازه چند کلاس در یک سلول)
class ClassSchedule(db.Model):
    __tablename__ = 'schedule'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    day = db.Column(db.String(10), nullable=False)
    time_slot = db.Column(db.String(20), nullable=False)
    course_name = db.Column(db.String(100))
    class_location = db.Column(db.String(100))

# مدل کلاس‌های خالی (تعریف شده توسط ادمین)
class EmptyClassSlot(db.Model):
    __tablename__ = 'empty_slots'
    id = db.Column(db.Integer, primary_key=True)
    day = db.Column(db.String(10), nullable=False)
    time_slot = db.Column(db.String(20), nullable=False)
    location = db.Column(db.String(100), default='کلاس نامشخص')
    is_reserved = db.Column(db.Boolean, default=False)

# مدل درخواست رزرو
class ReservationRequest(db.Model):
    __tablename__ = 'reservation'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    slot_id = db.Column(db.Integer, db.ForeignKey('empty_slots.id'), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending') # pending, approved, rejected
    created_at = db.Column(db.DateTime, server_default=func.now())

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
        if User.query.filter_by(student_id=field.data).first(): raise ValidationError('وجود دارد.')

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

# --- روت‌های اصلی ---
@app.route('/')
def index(): return render_template('index.html')

@app.route('/about')
def about(): return render_template('about.html')

@app.route('/auth')
def show_auth_page():
    if session.get('current_user_id'): return redirect(url_for('dashboard'))
    return render_template('register.html', form=RegistrationForm(), login_form=LoginForm())

@app.route('/register', methods=['POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        is_admin = (form.student_id.data == 'admin')
        user = User(full_name=form.full_name.data, student_id=form.student_id.data, major=form.major.data, password_hash=hashed_password, is_admin=is_admin)
        db.session.add(user)
        db.session.commit()
        session['current_user_id'] = user.id
        session['current_user_name'] = user.full_name
        session['current_user_pic'] = user.profile_pic
        session['is_admin'] = user.is_admin
        flash('ثبت‌نام موفق.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('register.html', form=form, login_form=LoginForm())

@app.route('/login', methods=['POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(student_id=form.student_id.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            session['current_user_id'] = user.id
            session['current_user_name'] = user.full_name
            session['current_user_pic'] = user.profile_pic
            session['is_admin'] = user.is_admin
            flash('خوش آمدید.', 'success')
            return redirect(url_for('dashboard'))
        flash('اطلاعات اشتباه است.', 'error')
    return render_template('register.html', form=RegistrationForm(), login_form=form)

@app.route('/logout')
def logout():
    StateManager.set_offline(session.get('current_user_id'))
    session.clear()
    return redirect(url_for('index'))

# --- داشبورد کاربر ---
@app.route('/dashboard')
@login_required
def dashboard():
    uid = session['current_user_id']
    my_schedules = ClassSchedule.query.filter_by(user_id=uid).all()
    my_reservations = ReservationRequest.query.filter_by(user_id=uid).order_by(ReservationRequest.created_at.desc()).limit(10).all()
    return render_template('dashboard.html', schedules=my_schedules, my_reservations=my_reservations)

# API: دریافت کلاس‌های خالی برای دانشجو
@app.route('/api/available_slots')
@login_required
def get_available_slots():
    slots = EmptyClassSlot.query.filter_by(is_reserved=False).all()
    return jsonify([{'id': s.id, 'day': s.day, 'time_slot': s.time_slot, 'location': s.location} for s in slots])

# ذخیره برنامه شخصی (منطق جدید: حذف همه کلاس‌های سلول، سپس اضافه کردن)
@app.route('/update_schedule', methods=['POST'])
@login_required
def update_schedule():
    data = request.json
    uid = session['current_user_id']
    
    # حذف کلاس‌های قبلی آن سلول (پاکسازی قبل از ذخیره جدید)
    # نکته: در فرانت‌اند ما لیست کلاس‌ها را می‌فرستیم
    ClassSchedule.query.filter_by(user_id=uid, day=data['day'], time_slot=data['time_slot']).delete()
    
    classes = data.get('classes', [])
    if classes:
        for c in classes:
            if c.get('name'):
                new_s = ClassSchedule(user_id=uid, day=data['day'], time_slot=data['time_slot'], course_name=c['name'], class_location=c.get('location',''))
                db.session.add(new_s)
    
    db.session.commit()
    return jsonify({'status': 'success'})

# ثبت درخواست رزرو
@app.route('/submit_reservation/<int:slot_id>', methods=['POST'])
@login_required
def submit_reservation(slot_id):
    reason = request.form.get('reason')
    slot = EmptyClassSlot.query.get_or_404(slot_id)
    if slot.is_reserved:
        flash('این کلاس قبلاً رزرو شده است.', 'error')
        return redirect(url_for('dashboard'))
    
    # چک کردن اینکه کاربر قبلا برای این کلاس درخواست داده یا نه
    exists = ReservationRequest.query.filter_by(user_id=session['current_user_id'], slot_id=slot.id, status='pending').first()
    if exists:
        flash('شما قبلاً برای این کلاس درخواست داده‌اید.', 'warning')
        return redirect(url_for('dashboard'))

    new_req = ReservationRequest(user_id=session['current_user_id'], slot_id=slot.id, reason=reason)
    db.session.add(new_req)
    db.session.commit()
    flash('درخواست رزرو ثبت شد.', 'success')
    return redirect(url_for('dashboard'))

# --- پنل ادمین (جدید و جداگانه) ---
@app.route('/admin')
@admin_required
def admin_dashboard():
    pending_requests = ReservationRequest.query.filter_by(status='pending').all()
    # برای نمایش جدول، لیست همه کلاس‌های خالی را می‌فرستیم
    empty_slots = EmptyClassSlot.query.filter_by(is_reserved=False).all()
    return render_template('admin_panel.html', requests=pending_requests, slots=empty_slots)

# اضافه کردن کلاس خالی توسط ادمین
@app.route('/admin/add_slot', methods=['POST'])
@admin_required
def admin_add_slot():
    day = request.form.get('day')
    time_slot = request.form.get('time_slot')
    location = request.form.get('location', 'کلاس')
    
    # محدودیت تکراری نباشد (برای همان روز و ساعت)
    exists = EmptyClassSlot.query.filter_by(day=day, time_slot=time_slot, is_reserved=False).first()
    if exists:
        flash('این زمان قبلاً تعریف شده است.', 'error')
    else:
        db.session.add(EmptyClassSlot(day=day, time_slot=time_slot, location=location))
        db.session.commit()
        flash('کلاس خالی اضافه شد.', 'success')
    return redirect(url_for('admin_dashboard'))

# حذف کلاس خالی
@app.route('/admin/delete_slot/<int:slot_id>')
@admin_required
def admin_delete_slot(slot_id):
    slot = EmptyClassSlot.query.get_or_404(slot_id)
    ReservationRequest.query.filter_by(slot_id=slot.id).delete()
    db.session.delete(slot)
    db.session.commit()
    flash('کلاس حذف شد.', 'success')
    return redirect(url_for('admin_dashboard'))

# مدیریت درخواست‌ها
@app.route('/admin/handle/<int:req_id>/<string:action>')
@admin_required
def handle_reservation(req_id, action):
    req = ReservationRequest.query.get_or_404(req_id)
    slot = EmptyClassSlot.query.get(req.slot_id)

    if action == 'approve':
        if slot and not slot.is_reserved:
            req.status = 'approved'
            slot.is_reserved = True
            # رد کردن بقیه
            ReservationRequest.query.filter(
                ReservationRequest.slot_id == slot.id,
                ReservationRequest.id != req.id,
                ReservationRequest.status == 'pending'
            ).update({ReservationRequest.status: 'rejected'}, synchronize_session=False)
            flash('تایید شد و کلاس رزرو شد.', 'success')
        else:
            flash('این کلاس قبلاً رزرو شده یا وجود ندارد.', 'error')
    elif action == 'reject':
        req.status = 'rejected'
        flash('درخواست رد شد.', 'info')
    
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

# --- پروفایل و چت (با مدیریت خطا) ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/match')
@login_required
def match():
    q = request.args.get('q', '')
    query = User.query.filter(User.id != session['current_user_id'])
    if q: users = query.filter((User.major.contains(q)) | (User.full_name.contains(q))).all()
    else: users = query.limit(20).all()
    return render_template('match.html', users=users)

@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    user = db.session.get(User, user_id)
    if not user: abort(404)
    can_edit = (session['current_user_id'] == user_id)
    forms = {
        'update_profile': UpdateProfileForm(obj=user) if can_edit else None,
        'update_password': UpdatePasswordForm() if can_edit else None
    }
    return render_template('profile.html', user=user, can_edit=can_edit, 
                           update_profile_form=forms['update_profile'],
                           update_password_form=forms['update_password'])

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    user = db.session.get(User, session['current_user_id'])
    if not user: return redirect(url_for('logout'))
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
    user = db.session.get(User, session['current_user_id'])
    form = UpdatePasswordForm()
    if form.validate_on_submit():
        if check_password_hash(user.password_hash, form.current_password.data):
            user.password_hash = generate_password_hash(form.new_password.data)
            db.session.commit()
            flash('رمز تغییر کرد.', 'success')
        else: flash('رمز فعلی اشتباه است.', 'error')
    return redirect(url_for('profile', user_id=user.id))

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user = db.session.get(User, session['current_user_id'])
    if user:
        db.session.delete(user)
        db.session.commit()
    session.clear()
    return redirect(url_for('index'))

@app.route('/chat')
@login_required
def chat_main():
    uid = session['current_user_id']
    
    # منطق پیچیده برای لیست مکالمات (با ایمن‌سازی)
    other_user_id = case((Message.sender_id == uid, Message.receiver_id), else_=Message.sender_id).label("other_user_id")
    subquery = db.session.query(func.max(Message.id).label("last_id")).filter(or_(Message.sender_id == uid, Message.receiver_id == uid)).group_by(other_user_id).subquery()
    
    results = db.session.query(Message, User).join(subquery, Message.id == subquery.c.last_id).join(User, User.id == other_user_id).order_by(Message.timestamp.desc()).all()
    
    conversations = []
    for msg, other_user in results:
        conversations.append({
            'other_user_id': other_user.id, 'other_user_name': other_user.full_name,
            'other_user_pic': other_user.profile_pic, 'last_message_content': msg.content,
            'last_message_timestamp': msg.timestamp, 'is_online': StateManager.is_online(other_user.id)
        })
        
    active_chat_user = None
    messages = []
    other_id = request.args.get('user_id', type=int)
    if other_id:
        active_chat_user = db.session.get(User, other_id)
        if active_chat_user:
            # خواندن پیام‌ها
            Message.query.filter_by(sender_id=other_id, receiver_id=uid, read_at=None).update({Message.read_at: func.now()})
            db.session.commit()
            messages = Message.query.filter(or_(and_(Message.sender_id == uid, Message.receiver_id == other_id), and_(Message.sender_id == other_id, Message.receiver_id == uid))).order_by(Message.timestamp.asc()).all()
            
    return render_template('chat_layout.html', conversations=conversations, active_chat_user=active_chat_user, messages=messages)

@app.route('/api/user_status/<int:user_id>')
def user_status(user_id):
    return jsonify({'online': StateManager.is_online(user_id)})

# --- سوکت‌ها ---
@socketio.on('connect')
def handle_connect():
    if session.get('current_user_id'): StateManager.set_online(session['current_user_id'])

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
    msg = Message(sender_id=uid, receiver_id=data['other_user_id'], content=data['content'])
    db.session.add(msg)
    db.session.commit()
    oid = data['other_user_id']
    emit('new_message', {'sender_name': session['current_user_name'], 'content': data['content'], 'timestamp': msg.timestamp.strftime('%H:%M'), 'sender_id': uid, 'message_id': msg.id}, room=f"chat-{min(uid, oid)}-{max(uid, oid)}")

# --- اجرا ---
with app.app_context():
    db.create_all()
    if not User.query.filter_by(student_id='admin').first():
        admin = User(full_name='مدیر', student_id='admin', major='مدیریت', password_hash=generate_password_hash('admin', method='pbkdf2:sha256'), is_admin=True)
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port)