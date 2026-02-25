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
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask_socketio import SocketIO, emit, join_room
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_key_change_in_prod_2024')

UPLOAD_FOLDER = 'static/uploads/profile_pics'
CHAT_UPLOAD_FOLDER = 'static/uploads/chat_files'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'docx', 'zip'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['CHAT_UPLOAD_FOLDER'] = CHAT_UPLOAD_FOLDER

# ایجاد پوشه‌های مورد نیاز در صورت عدم وجود
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

ONLINE_USERS_MEMORY = set()


class StateManager:
    @staticmethod
    def set_online(user_id):
        ONLINE_USERS_MEMORY.add(user_id)

    @staticmethod
    def set_offline(user_id):
        ONLINE_USERS_MEMORY.discard(user_id)

    @staticmethod
    def is_online(user_id):
        return user_id in ONLINE_USERS_MEMORY


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    student_id = db.Column(db.String(20), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    major = db.Column(db.String(100))
    profile_pic = db.Column(db.String(255), default='default.jpg')
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Message(db.Model):
    __tablename__ = 'message'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    file_path = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    read_at = db.Column(db.DateTime, nullable=True)

    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', foreign_keys=[user_id])
    master_slot = db.relationship('MasterSchedule', foreign_keys=[master_slot_id])


class CancelledClass(db.Model):
    __tablename__ = 'cancelled_class'
    id = db.Column(db.Integer, primary_key=True)
    professor_name = db.Column(db.String(100), nullable=True)
    course_name = db.Column(db.String(100), nullable=True)
    cancel_date = db.Column(db.Date, nullable=True)
    start_date = db.Column(db.Date, nullable=True)
    end_date = db.Column(db.Date, nullable=True)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class GroupMessage(db.Model):
    __tablename__ = 'group_message'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=True)
    file_path = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    sender = db.relationship('User', foreign_keys=[sender_id])


class ChannelMessage(db.Model):
    __tablename__ = 'channel_message'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    file_path = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    sender = db.relationship('User', foreign_keys=[sender_id])


class Notification(db.Model):
    __tablename__ = 'notification'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class SystemSetting(db.Model):
    __tablename__ = 'system_setting'
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.String(100), nullable=True)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


class AuthService:
    @staticmethod
    def register_user(full_name, student_id, major, password):
        try:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            is_admin = (student_id == 'admin')
            new_user = User(
                full_name=full_name,
                student_id=student_id,
                major=major,
                password_hash=hashed_password,
                is_admin=is_admin
            )
            db.session.add(new_user)
            db.session.commit()
            return new_user
        except Exception as e:
            db.session.rollback()
            raise e

    @staticmethod
    def authenticate_user(student_id, password):
        user = User.query.filter_by(student_id=student_id).first()
        if user and check_password_hash(user.password_hash, password):
            return user
        return None


class ChatService:
    @staticmethod
    def get_inbox_conversations(user_id):
        try:
            other_user_id = case(
                (Message.sender_id == user_id, Message.receiver_id),
                else_=Message.sender_id
            ).label("other_user_id")

            subquery = db.session.query(
                func.max(Message.id).label("last_message_id")
            ).filter(
                or_(Message.sender_id == user_id, Message.receiver_id == user_id)
            ).group_by(other_user_id).subquery()

            results = db.session.query(
                Message,
                User,
                func.sum(case(
                    (and_(Message.receiver_id == user_id, Message.read_at.is_(None)), 1),
                    else_=0
                )).label("unread_count")
            ).join(
                subquery, Message.id == subquery.c.last_message_id
            ).join(
                User, User.id == other_user_id
            ).group_by(Message.id, User.id).order_by(Message.timestamp.desc()).all()

            conversations = []
            for msg, other_user, unread in results:
                conversations.append({
                    'other_user_id': other_user.id,
                    'other_user_name': other_user.full_name,
                    'other_user_pic': other_user.profile_pic,
                    'last_message_content': msg.content,
                    'last_message_timestamp': msg.timestamp,
                    'has_unread': unread > 0,
                    'is_online': StateManager.is_online(other_user.id)
                })
            return conversations
        except Exception:
            return []

    @staticmethod
    def get_chat_history(current_user_id, other_user_id, limit=50):
        try:
            Message.query.filter(
                and_(
                    Message.sender_id == other_user_id,
                    Message.receiver_id == current_user_id,
                    Message.read_at.is_(None)
                )
            ).update({Message.read_at: datetime.utcnow()}, synchronize_session=False)
            db.session.commit()

            messages = Message.query.filter(
                or_(
                    and_(Message.sender_id == current_user_id, Message.receiver_id == other_user_id),
                    and_(Message.sender_id == other_user_id, Message.receiver_id == current_user_id)
                )
            ).order_by(Message.timestamp.desc()).limit(limit).all()
            return messages[::-1]
        except Exception:
            return []

    @staticmethod
    def save_message(sender_id, receiver_id, content, file_path=None):
        msg = Message(
            sender_id=sender_id,
            receiver_id=receiver_id,
            content=content,
            file_path=file_path,
            timestamp=datetime.utcnow()
        )
        db.session.add(msg)
        db.session.commit()
        return msg


MAJOR_CHOICES = [
    ('', 'انتخاب کنید'),
    ('مهندسی کامپیوتر', 'مهندسی کامپیوتر'),
    ('علوم کامپیوتر', 'علوم کامپیوتر')
]


class RegistrationForm(FlaskForm):
    full_name = StringField('نام و نام خانوادگی', validators=[DataRequired(message='نام الزامی است')])
    student_id = StringField('شماره دانشجویی', validators=[
        DataRequired(message='شماره دانشجویی الزامی است'),
        Length(min=10, max=10, message='شماره دانشجویی باید ۱۰ رقم باشد')
    ])
    major = SelectField('رشته تحصیلی', choices=MAJOR_CHOICES, validators=[DataRequired(message='انتخاب رشته الزامی است')])
    password = PasswordField('کد ملی (رمز عبور)', validators=[
        DataRequired(message='رمز عبور الزامی است'),
        Length(min=10, max=10, message='رمز عبور باید ۱۰ رقم باشد')
    ])
    confirm_password = PasswordField('تکرار رمز عبور', validators=[
        DataRequired(),
        EqualTo('password', message='رمزهای عبور مطابقت ندارند')
    ])
    submit = SubmitField('ثبت‌نام')

    def validate_student_id(self, field):
        if User.query.filter_by(student_id=field.data).first():
            raise ValidationError('این شماره دانشجویی قبلاً ثبت شده است.')


class LoginForm(FlaskForm):
    student_id = StringField('شماره دانشجویی', validators=[DataRequired(message='شماره دانشجویی الزامی است')])
    password = PasswordField('رمز عبور', validators=[DataRequired(message='رمز عبور الزامی است')])
    submit = SubmitField('ورود')


class UpdateProfileForm(FlaskForm):
    full_name = StringField('نام و نام خانوادگی', validators=[DataRequired()])
    major = SelectField('رشته تحصیلی', choices=MAJOR_CHOICES)
    submit = SubmitField('بروزرسانی')


class UpdatePasswordForm(FlaskForm):
    current_password = PasswordField('رمز عبور فعلی', validators=[DataRequired()])
    new_password = PasswordField('رمز عبور جدید', validators=[DataRequired()])
    confirm_new_password = PasswordField('تکرار رمز جدید', validators=[
        DataRequired(),
        EqualTo('new_password', message='رمزهای جدید مطابقت ندارند')
    ])
    submit = SubmitField('تغییر رمز عبور')


class DeleteAccountForm(FlaskForm):
    submit = SubmitField('حذف حساب کاربری')


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'current_user_id' not in session:
            flash('برای دسترسی به این صفحه ابتدا وارد شوید.', 'info')
            return redirect(url_for('show_auth_page'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            flash('دسترسی غیرمجاز. این صفحه فقط برای مدیران است.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


@app.context_processor
def inject_user():
    user_id = session.get('current_user_id')
    user_name = session.get('current_user_name')
    user_pic = session.get('current_user_pic')
    is_admin = session.get('is_admin', False)
    if user_id and user_name:
        return dict(
            current_user={'id': user_id, 'name': user_name, 'pic': user_pic},
            current_user_id=user_id,
            is_admin=is_admin
        )
    return dict(current_user=None, current_user_id=None, is_admin=False)


def get_week_number():
    return datetime.now().isocalendar()[1]


def check_weekly_reset():
    """بررسی تغییر هفته و ریست رزروها"""
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
    except Exception:
        db.session.rollback()


@app.errorhandler(404)
def not_found_error(e):
    if request.is_json or request.path.startswith('/api/') or request.path.startswith('/admin/save'):
        return jsonify({'error': 'یافت نشد', 'code': 404}), 404
    return render_template('error.html', error_code=404,
                           error_msg='صفحه مورد نظر یافت نشد.'), 404


@app.errorhandler(500)
def internal_error(e):
    db.session.rollback()
    if request.is_json or request.path.startswith('/api/') or request.path.startswith('/admin/save'):
        return jsonify({'error': 'خطای داخلی سرور', 'code': 500}), 500
    return render_template('error.html', error_code=500,
                           error_msg='خطای داخلی سرور. لطفاً دوباره تلاش کنید.'), 500


@app.errorhandler(403)
def forbidden_error(e):
    return render_template('error.html', error_code=403,
                           error_msg='دسترسی به این صفحه مجاز نیست.'), 403


@app.route('/')
def index():
    check_weekly_reset()
    return render_template('index.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/auth')
def show_auth_page():
    if session.get('current_user_id'):
        return redirect(url_for('dashboard'))
    return render_template('register.html', form=RegistrationForm(), login_form=LoginForm())


@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            user = AuthService.register_user(
                form.full_name.data,
                form.student_id.data,
                form.major.data,
                form.password.data
            )
            session['current_user_id'] = user.id
            session['current_user_name'] = user.full_name
            session['current_user_pic'] = user.profile_pic
            session['is_admin'] = user.is_admin
            flash('ثبت‌نام با موفقیت انجام شد. خوش آمدید!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('خطا در ثبت‌نام. لطفاً دوباره تلاش کنید.', 'error')
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
            flash('با موفقیت وارد شدید. خوش آمدید!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('شماره دانشجویی یا رمز عبور اشتباه است.', 'error')
    return render_template('register.html', form=RegistrationForm(), login_form=login_form)


@app.route('/logout')
@login_required
def logout():
    StateManager.set_offline(session.get('current_user_id'))
    session.clear()
    flash('با موفقیت از حساب کاربری خارج شدید.', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    check_weekly_reset()
    current_user_id = session['current_user_id']

    try:
        my_schedules = ClassSchedule.query.filter_by(user_id=current_user_id).all()
    except Exception:
        my_schedules = []

    try:
        today_j = jdatetime.date.today()
        weekday_name = ['شنبه', 'یکشنبه', 'دوشنبه', 'سه‌شنبه', 'چهارشنبه', 'پنجشنبه', 'جمعه'][today_j.weekday()]
        today_gregorian = today_j.togregorian()
    except Exception:
        today_j = None
        weekday_name = ''
        today_gregorian = datetime.today().date()

    # کلاس‌های لغو شده امروز برای نمایش هشدار
    try:
        cancelled_today = CancelledClass.query.filter(
            or_(
                CancelledClass.cancel_date == today_gregorian,
                and_(
                    CancelledClass.start_date <= today_gregorian,
                    CancelledClass.end_date >= today_gregorian
                )
            )
        ).all()
    except Exception:
        cancelled_today = []

    try:
        all_cancelled = CancelledClass.query.order_by(CancelledClass.created_at.desc()).all()
    except Exception:
        all_cancelled = []

    try:
        notifications = Notification.query.filter_by(
            user_id=current_user_id, is_read=False
        ).order_by(Notification.created_at.desc()).limit(5).all()
    except Exception:
        notifications = []

    return render_template(
        'dashboard.html',
        schedules=my_schedules,
        today_j=today_j,
        weekday_name=weekday_name,
        cancelled_classes=cancelled_today,
        all_cancelled_classes=all_cancelled,
        notifications=notifications
    )


@app.route('/update_schedule', methods=['POST'])
@csrf.exempt
@login_required
def update_schedule():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'داده‌ای ارسال نشد'}), 400

        user_id = session['current_user_id']

        ClassSchedule.query.filter_by(
            user_id=user_id,
            day=data.get('day'),
            time_slot=data.get('time_slot')
        ).delete()

        if data.get('course_name') and str(data['course_name']).strip():
            new_schedule = ClassSchedule(
                user_id=user_id,
                day=data['day'],
                time_slot=data['time_slot'],
                course_name=data['course_name'].strip(),
                class_location=data.get('class_location', '').strip(),
                professor_name=data.get('professor_name', '').strip(),
                week_type=data.get('week_type', 'all')
            )
            db.session.add(new_schedule)

        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"update_schedule error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/bulk_update_schedule', methods=['POST'])
@csrf.exempt
@login_required
def bulk_update_schedule():
    """آپلود و پردازش برنامه هفتگی از اکسل (paste از clipboard)"""
    try:
        data = request.get_json()
        if not data or 'schedules' not in data:
            return jsonify({'status': 'error', 'message': 'داده‌ای ارسال نشد'}), 400

        user_id = session['current_user_id']
        schedules = data['schedules']

        ClassSchedule.query.filter_by(user_id=user_id).delete()

        for item in schedules:
            if item.get('course_name') and str(item['course_name']).strip():
                new_schedule = ClassSchedule(
                    user_id=user_id,
                    day=item['day'],
                    time_slot=item['time_slot'],
                    course_name=str(item['course_name']).strip(),
                    class_location=str(item.get('class_location', '')).strip(),
                    professor_name=str(item.get('professor_name', '')).strip(),
                    week_type=item.get('week_type', 'all')
                )
                db.session.add(new_schedule)

        db.session.commit()
        return jsonify({'status': 'success', 'count': len(schedules)})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"bulk_update_schedule error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/master_schedule')
@login_required
def get_master_schedule():
    try:
        slots = MasterSchedule.query.all()
        reservations = Reservation.query.filter_by(status='approved').all()

        reserved_map = {}
        for r in reservations:
            key = f"{r.master_slot_id}_{r.room_name}"
            reserved_map[key] = True

        output = []
        for s in slots:
            rooms_list = [r.strip() for r in s.rooms.split(',') if r.strip()]
            available_rooms = [r for r in rooms_list if f"{s.id}_{r}" not in reserved_map]

            output.append({
                'id': s.id,
                'day': s.day,
                'time_slot': s.time_slot,
                'available_rooms': available_rooms,
                'all_rooms': rooms_list
            })
        return jsonify(output)
    except Exception as e:
        app.logger.error(f"get_master_schedule error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/submit_reservation/<int:slot_id>/<room_name>', methods=['POST'])
@login_required
def submit_reservation(slot_id, room_name):
    try:
        reason = request.form.get('reason', '').strip()
        if not reason:
            flash('لطفاً دلیل رزرو را وارد کنید.', 'error')
            return redirect(url_for('dashboard'))

        exists = Reservation.query.filter_by(
            master_slot_id=slot_id,
            room_name=room_name,
            status='approved'
        ).first()
        if exists:
            flash('این کلاس قبلاً رزرو شده است.', 'error')
            return redirect(url_for('dashboard'))

        new_req = Reservation(
            user_id=session['current_user_id'],
            master_slot_id=slot_id,
            room_name=room_name,
            reason=reason
        )
        db.session.add(new_req)
        db.session.commit()
        flash('درخواست رزرو با موفقیت ثبت شد و در انتظار تأیید است.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"submit_reservation error: {e}")
        flash('خطا در ثبت درخواست. لطفاً دوباره تلاش کنید.', 'error')
    return redirect(url_for('dashboard'))


@app.route('/admin')
@admin_required
def admin_dashboard():
    try:
        cancelled = CancelledClass.query.order_by(CancelledClass.created_at.desc()).limit(20).all()
        pending_requests = Reservation.query.filter_by(status='pending').all()
        master_slots = MasterSchedule.query.all()
        return render_template(
            'admin_dashboard.html',
            slots=master_slots,
            requests=pending_requests,
            cancelled_classes=cancelled
        )
    except Exception as e:
        app.logger.error(f"admin_dashboard error: {e}")
        flash('خطا در بارگذاری پنل مدیریت.', 'error')
        return redirect(url_for('index'))


@app.route('/admin/save_master_schedule', methods=['POST'])
@csrf.exempt
@admin_required
def save_master_schedule():
    """ذخیره برنامه مستر از AJAX - نیاز به csrf.exempt دارد"""
    try:
        data = request.get_json()
        if data is None:
            return jsonify({'status': 'error', 'message': 'داده‌ای ارسال نشد'}), 400

        MasterSchedule.query.delete()
        db.session.flush()

        for item in data:
            if item.get('rooms') and str(item['rooms']).strip():
                slot = MasterSchedule(
                    day=item['day'],
                    time_slot=item['time_slot'],
                    rooms=item['rooms'].strip()
                )
                db.session.add(slot)

        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"save_master_schedule error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/admin/handle_reservation/<int:req_id>/<string:action>')
@admin_required
def handle_reservation(req_id, action):
    try:
        req = Reservation.query.get_or_404(req_id)

        slot = MasterSchedule.query.get(req.master_slot_id)
        slot_info = f"{slot.day} - {slot.time_slot}" if slot else "نامشخص"

        if action == 'approve':
            req.status = 'approved'
            notif = Notification(
                user_id=req.user_id,
                message=f"درخواست رزرو شما برای کلاس {req.room_name} در {slot_info} تأیید شد."
            )
            db.session.add(notif)

            Reservation.query.filter(
                Reservation.master_slot_id == req.master_slot_id,
                Reservation.room_name == req.room_name,
                Reservation.id != req.id,
                Reservation.status == 'pending'
            ).update({Reservation.status: 'rejected'}, synchronize_session=False)

            flash('درخواست رزرو تأیید شد.', 'success')

        elif action == 'reject':
            req.status = 'rejected'
            notif = Notification(
                user_id=req.user_id,
                message=f"متأسفانه درخواست رزرو شما برای کلاس {req.room_name} رد شد."
            )
            db.session.add(notif)
            flash('درخواست رزرو رد شد.', 'info')

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"handle_reservation error: {e}")
        flash('خطا در پردازش درخواست.', 'error')

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/add_cancelled_class', methods=['POST'])
@admin_required
def add_cancelled_class():
    try:
        prof = request.form.get('professor', '').strip()
        course = request.form.get('course', '').strip()
        desc = request.form.get('desc', '').strip()
        c_date = request.form.get('date', '').strip()
        start_date = request.form.get('start_date', '').strip()
        end_date = request.form.get('end_date', '').strip()

        new_cancel = CancelledClass(
            professor_name=prof or None,
            course_name=course or None,
            description=desc or None,
            cancel_date=datetime.strptime(c_date, '%Y-%m-%d').date() if c_date else None,
            start_date=datetime.strptime(start_date, '%Y-%m-%d').date() if start_date else None,
            end_date=datetime.strptime(end_date, '%Y-%m-%d').date() if end_date else None
        )
        db.session.add(new_cancel)
        db.session.commit()
        flash('لغو کلاس با موفقیت ثبت شد.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"add_cancelled_class error: {e}")
        flash('خطا در ثبت لغو کلاس.', 'error')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete_cancelled_class/<int:class_id>', methods=['POST'])
@csrf.exempt
@admin_required
def delete_cancelled_class(class_id):
    try:
        c = CancelledClass.query.get_or_404(class_id)
        db.session.delete(c)
        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    can_edit = (session['current_user_id'] == user_id)
    forms = {
        'update_profile': UpdateProfileForm(obj=user) if can_edit else None,
        'update_password': UpdatePasswordForm() if can_edit else None,
        'delete_account': DeleteAccountForm() if can_edit else None
    }
    return render_template(
        'profile.html',
        user=user,
        can_edit=can_edit,
        update_profile_form=forms['update_profile'],
        update_password_form=forms['update_password'],
        delete_account_form=forms['delete_account']
    )


@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    try:
        user = db.session.get(User, session['current_user_id'])
        if not user:
            abort(404)
        form = UpdateProfileForm(obj=user)
        if form.validate_on_submit():
            user.full_name = form.full_name.data
            user.major = form.major.data
            if 'profile_pic' in request.files:
                file = request.files['profile_pic']
                if file and file.filename and allowed_file(file.filename):
                    filename = secure_filename(f"{user.id}_{file.filename}")
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    user.profile_pic = filename
                    session['current_user_pic'] = filename
            db.session.commit()
            session['current_user_name'] = user.full_name
            flash('پروفایل با موفقیت بروزرسانی شد.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"update_profile error: {e}")
        flash('خطا در بروزرسانی پروفایل.', 'error')
    return redirect(url_for('profile', user_id=session['current_user_id']))


@app.route('/update_password', methods=['POST'])
@login_required
def update_password():
    try:
        user = db.session.get(User, session['current_user_id'])
        if not user:
            abort(404)
        form = UpdatePasswordForm()
        if form.validate_on_submit():
            if check_password_hash(user.password_hash, form.current_password.data):
                user.password_hash = generate_password_hash(
                    form.new_password.data, method='pbkdf2:sha256'
                )
                db.session.commit()
                flash('رمز عبور با موفقیت تغییر کرد.', 'success')
            else:
                flash('رمز عبور فعلی اشتباه است.', 'error')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"update_password error: {e}")
        flash('خطا در تغییر رمز عبور.', 'error')
    return redirect(url_for('profile', user_id=session['current_user_id']))


@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    try:
        user = db.session.get(User, session['current_user_id'])
        if user:
            StateManager.set_offline(user.id)
            db.session.delete(user)
            db.session.commit()
        session.clear()
        flash('حساب کاربری شما با موفقیت حذف شد.', 'info')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"delete_account error: {e}")
        flash('خطا در حذف حساب.', 'error')
    return redirect(url_for('index'))



@app.route('/chat')
@login_required
def chat_main():
    try:
        conversations = ChatService.get_inbox_conversations(session['current_user_id'])
    except Exception:
        conversations = []

    active_chat_user = None
    messages = []
    other_user_id = request.args.get('user_id', type=int)
    if other_user_id:
        active_chat_user = db.session.get(User, other_user_id)
        if active_chat_user:
            messages = ChatService.get_chat_history(session['current_user_id'], other_user_id)

    try:
        group_messages = GroupMessage.query.order_by(GroupMessage.timestamp.desc()).limit(50).all()
        group_messages = group_messages[::-1]
    except Exception:
        group_messages = []

    try:
        channel_messages = ChannelMessage.query.order_by(ChannelMessage.timestamp.desc()).limit(50).all()
        channel_messages = channel_messages[::-1]
    except Exception:
        channel_messages = []

    return render_template(
        'chat.html',
        conversations=conversations,
        active_chat_user=active_chat_user,
        messages=messages,
        group_messages=group_messages,
        channel_messages=channel_messages
    )


@app.route('/upload_chat_file', methods=['POST'])
@login_required
def upload_chat_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'فایلی ارسال نشد'}), 400
        file = request.files['file']
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(
                f"{session['current_user_id']}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}"
            )
            filepath = os.path.join(app.config['CHAT_UPLOAD_FOLDER'], filename)
            file.save(filepath)
            return jsonify({'filepath': f'/static/uploads/chat_files/{filename}'})
        return jsonify({'error': 'نوع فایل مجاز نیست'}), 400
    except Exception as e:
        app.logger.error(f"upload_chat_file error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/user_status/<int:user_id>')
def check_user_online(user_id):
    return jsonify({'online': StateManager.is_online(user_id)})


@app.route('/api/online_users')
@login_required
def get_online_users():
    """لیست کاربران آنلاین برای نمایش در گروه"""
    try:
        online_ids = list(ONLINE_USERS_MEMORY)
        users = User.query.filter(User.id.in_(online_ids)).all() if online_ids else []
        result = [{'id': u.id, 'name': u.full_name, 'pic': u.profile_pic} for u in users]
        return jsonify(result)
    except Exception:
        return jsonify([])


@app.route('/api/all_users')
@login_required
def get_all_users():
    """تمام کاربران سیستم برای نمایش لیست اعضای گروه"""
    try:
        users = User.query.filter(User.id != session['current_user_id']).order_by(User.full_name).all()
        result = [{
            'id': u.id,
            'name': u.full_name,
            'pic': u.profile_pic,
            'student_id': u.student_id,
            'is_online': StateManager.is_online(u.id)
        } for u in users]
        return jsonify(result)
    except Exception:
        return jsonify([])


@app.route('/mark_notification_read/<int:n_id>')
@login_required
def mark_notification_read(n_id):
    try:
        notif = Notification.query.get_or_404(n_id)
        if notif.user_id == session['current_user_id']:
            notif.is_read = True
            db.session.commit()
    except Exception:
        db.session.rollback()
    return jsonify({'status': 'ok'})

@socketio.on('connect')
def handle_connect():
    if session.get('current_user_id'):
        StateManager.set_online(session['current_user_id'])
        join_room(f"user_{session['current_user_id']}")


@socketio.on('disconnect')
def handle_disconnect():
    if session.get('current_user_id'):
        StateManager.set_offline(session['current_user_id'])


@socketio.on('join_chat')
def handle_join_chat(data):
    if session.get('current_user_id') and data.get('other_user_id'):
        uid = session['current_user_id']
        oid = int(data['other_user_id'])
        join_room(f"chat-{min(uid, oid)}-{max(uid, oid)}")


@socketio.on('send_message')
def handle_send_message(data):
    try:
        uid = session.get('current_user_id')
        if not uid:
            emit('error', {'message': 'ابتدا وارد شوید'})
            return
        if not data.get('other_user_id') or not data.get('content'):
            emit('error', {'message': 'اطلاعات ناقص است'})
            return

        file_path = data.get('file_path')
        oid = int(data['other_user_id'])
        now = datetime.utcnow()
        msg = Message(
            sender_id=uid,
            receiver_id=oid,
            content=data['content'],
            file_path=file_path,
            timestamp=now
        )
        db.session.add(msg)
        db.session.commit()

        emit('new_message', {
            'sender_name': session.get('current_user_name', ''),
            'content': data['content'],
            'timestamp': now.strftime('%H:%M'),
            'sender_id': uid,
            'file_path': file_path
        }, room=f"chat-{min(uid, oid)}-{max(uid, oid)}")
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"handle_send_message error: {e}")
        emit('error', {'message': 'خطا در ارسال پیام'})


@socketio.on('join_group')
def handle_join_group():
    join_room('public_group')


@socketio.on('send_group_message')
def handle_group_message(data):
    try:
        uid = session.get('current_user_id')
        if not uid:
            emit('error', {'message': 'ابتدا وارد شوید'})
            return

        content = data.get('content', '').strip()
        file_path = data.get('file_path')

        if not content and not file_path:
            return

        now = datetime.utcnow()
        msg = GroupMessage(
            sender_id=uid,
            content=content,
            file_path=file_path,
            timestamp=now
        )
        db.session.add(msg)
        db.session.commit()

        emit('new_group_message', {
            'sender_id': uid,
            'sender_name': session.get('current_user_name', ''),
            'content': content,
            'file_path': file_path,
            'timestamp': now.strftime('%H:%M')
        }, room='public_group')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"handle_group_message error: {e}")
        emit('error', {'message': 'خطا در ارسال پیام گروهی'})


@socketio.on('join_channel')
def handle_join_channel():
    join_room('channel')


@socketio.on('send_channel_message')
def handle_channel_message(data):
    try:
        if not session.get('is_admin'):
            emit('error', {'message': 'دسترسی غیرمجاز'})
            return

        uid = session.get('current_user_id')
        content = data.get('content', '').strip()
        file_path = data.get('file_path')

        if not content and not file_path:
            return

        now = datetime.utcnow()
        msg = ChannelMessage(
            sender_id=uid,
            content=content,
            file_path=file_path,
            timestamp=now
        )
        db.session.add(msg)
        db.session.commit()

        emit('new_channel_message', {
            'sender_name': 'مدیریت',
            'content': content,
            'file_path': file_path,
            'timestamp': now.strftime('%H:%M')
        }, room='channel')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"handle_channel_message error: {e}")
        emit('error', {'message': 'خطا در ارسال اطلاعیه'})


with app.app_context():
    db.create_all()
    if not User.query.filter_by(student_id='admin').first():
        admin = User(
            full_name='مدیر سیستم',
            student_id='admin',
            major='مدیریت',
            password_hash=generate_password_hash('admin123', method='pbkdf2:sha256'),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        print("Admin created: ID=admin | Password=admin123")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=False)