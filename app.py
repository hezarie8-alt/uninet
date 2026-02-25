import eventlet
eventlet.monkey_patch()

import os
import json
import re
import jdatetime
from datetime import datetime, timedelta, date
from functools import wraps
from zoneinfo import ZoneInfo

from flask import (Flask, render_template, request, redirect, url_for,
                   session, abort, flash, jsonify, send_from_directory)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from sqlalchemy import or_, and_, func, case, Index
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ==========================================
# Timezone  —  همه timestamp‌ها به وقت تهران
# ==========================================
TEHRAN_TZ = ZoneInfo('Asia/Tehran')


def now_tehran():
    """زمان فعلی با timezone تهران (بدون tzinfo برای ذخیره در DB)"""
    return datetime.now(TEHRAN_TZ).replace(tzinfo=None)


def fmt_time(dt):
    """فرمت‌بندی ساعت:دقیقه برای ارسال به کلاینت"""
    if dt is None:
        return ''
    return dt.strftime('%H:%M')


def fmt_datetime(dt):
    """فرمت‌بندی کامل تاریخ و ساعت"""
    if dt is None:
        return ''
    return dt.strftime('%Y-%m-%d %H:%M')


# ==========================================
# App Configuration
# ==========================================
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_key_change_in_prod_2024')

UPLOAD_FOLDER = 'static/uploads/profile_pics'
CHAT_UPLOAD_FOLDER = 'static/uploads/chat_files'
RESOURCE_UPLOAD_FOLDER = 'static/uploads/resources'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'docx', 'zip', 'pptx'}
RESOURCE_ALLOWED_EXTENSIONS = {'pdf', 'docx', 'pptx', 'zip'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['CHAT_UPLOAD_FOLDER'] = CHAT_UPLOAD_FOLDER
app.config['RESOURCE_UPLOAD_FOLDER'] = RESOURCE_UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB

for folder in [UPLOAD_FOLDER, CHAT_UPLOAD_FOLDER, RESOURCE_UPLOAD_FOLDER]:
    os.makedirs(folder, exist_ok=True)

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

# ساعت‌های مجاز تشکیل کلاس
CLASS_TIME_SLOTS = ['08:00-10:00', '10:00-12:00', '12:00-14:00',
                    '14:00-16:00', '16:00-18:00', '18:00-20:00']


# ==========================================
# State Manager
# ==========================================
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


# ==========================================
# Models
# ==========================================

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    student_id = db.Column(db.String(20), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    major = db.Column(db.String(100))
    profile_pic = db.Column(db.String(255), default='default.jpg')
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=now_tehran)
    last_seen = db.Column(db.DateTime, default=now_tehran)
    # تنظیمات حریم خصوصی
    last_seen_visibility = db.Column(db.String(20), default='all')   # all / contacts / none
    profile_pic_visibility = db.Column(db.String(20), default='all')
    who_can_message = db.Column(db.String(20), default='all')        # all / none


class Message(db.Model):
    __tablename__ = 'message'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    file_path = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=now_tehran, index=True)
    read_at = db.Column(db.DateTime, nullable=True)
    delivered_at = db.Column(db.DateTime, nullable=True)
    # ویژگی‌های جدید
    reply_to_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=True)
    is_edited = db.Column(db.Boolean, default=False)
    edit_history = db.Column(db.Text, nullable=True)  # JSON: [{content, edited_at}]
    deleted_for_sender = db.Column(db.Boolean, default=False)
    deleted_for_receiver = db.Column(db.Boolean, default=False)
    is_pinned = db.Column(db.Boolean, default=False)
    forwarded_from_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=True)

    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])
    reply_to = db.relationship('Message', foreign_keys=[reply_to_id], remote_side='Message.id')
    reactions = db.relationship('MessageReaction', backref='message', lazy='dynamic',
                                foreign_keys='MessageReaction.message_id', cascade='all, delete-orphan')
    __table_args__ = (Index('idx_sender_receiver_ts', 'sender_id', 'receiver_id', 'timestamp'),)


class MessageReaction(db.Model):
    __tablename__ = 'message_reaction'
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    emoji = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, default=now_tehran)
    __table_args__ = (db.UniqueConstraint('message_id', 'user_id', 'emoji'),)


class UserBlock(db.Model):
    __tablename__ = 'user_block'
    id = db.Column(db.Integer, primary_key=True)
    blocker_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    blocked_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=now_tehran)
    __table_args__ = (db.UniqueConstraint('blocker_id', 'blocked_id'),)


class GroupMember(db.Model):
    """نقش و وضعیت هر کاربر در گروه عمومی"""
    __tablename__ = 'group_member'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    role = db.Column(db.String(20), default='member')   # member / admin
    is_muted = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)
    joined_at = db.Column(db.DateTime, default=now_tehran)
    user = db.relationship('User', foreign_keys=[user_id])


class GroupSetting(db.Model):
    """تنظیمات گروه عمومی — همیشه یک ردیف"""
    __tablename__ = 'group_setting'
    id = db.Column(db.Integer, primary_key=True)
    is_readonly = db.Column(db.Boolean, default=False)   # فقط ادمین پیام بفرستد
    pinned_message_id = db.Column(db.Integer, nullable=True)


class GroupMessage(db.Model):
    __tablename__ = 'group_message'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=True)
    file_path = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=now_tehran)
    reply_to_id = db.Column(db.Integer, db.ForeignKey('group_message.id'), nullable=True)
    is_deleted = db.Column(db.Boolean, default=False)
    deleted_by = db.Column(db.Integer, nullable=True)
    is_pinned = db.Column(db.Boolean, default=False)
    forwarded_info = db.Column(db.String(255), nullable=True)

    sender = db.relationship('User', foreign_keys=[sender_id])
    reply_to = db.relationship('GroupMessage', foreign_keys=[reply_to_id],
                               remote_side='GroupMessage.id')
    reactions = db.relationship('GroupMessageReaction', backref='group_message', lazy='dynamic',
                                foreign_keys='GroupMessageReaction.message_id',
                                cascade='all, delete-orphan')


class GroupMessageReaction(db.Model):
    __tablename__ = 'group_message_reaction'
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('group_message.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    emoji = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, default=now_tehran)
    __table_args__ = (db.UniqueConstraint('message_id', 'user_id', 'emoji'),)


class ChannelMessage(db.Model):
    __tablename__ = 'channel_message'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    file_path = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=now_tehran)
    view_count = db.Column(db.Integer, default=0)
    is_edited = db.Column(db.Boolean, default=False)
    is_deleted = db.Column(db.Boolean, default=False)
    is_pinned = db.Column(db.Boolean, default=False)

    sender = db.relationship('User', foreign_keys=[sender_id])
    reactions = db.relationship('ChannelMessageReaction', backref='channel_message', lazy='dynamic',
                                foreign_keys='ChannelMessageReaction.message_id',
                                cascade='all, delete-orphan')
    views = db.relationship('ChannelMessageView', backref='channel_message_obj', lazy='dynamic',
                            foreign_keys='ChannelMessageView.message_id',
                            cascade='all, delete-orphan')


class ChannelMessageReaction(db.Model):
    __tablename__ = 'channel_message_reaction'
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('channel_message.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    emoji = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, default=now_tehran)
    __table_args__ = (db.UniqueConstraint('message_id', 'user_id', 'emoji'),)


class ChannelMessageView(db.Model):
    """ردیابی بازدید پیام کانال توسط هر کاربر"""
    __tablename__ = 'channel_message_view'
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('channel_message.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    viewed_at = db.Column(db.DateTime, default=now_tehran)
    __table_args__ = (db.UniqueConstraint('message_id', 'user_id'),)


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
    created_at = db.Column(db.DateTime, default=now_tehran)
    user = db.relationship('User', foreign_keys=[user_id])
    master_slot = db.relationship('MasterSchedule', foreign_keys=[master_slot_id])


class CancelledClass(db.Model):
    """
    منطق:
    - اگر professor_name + course_name + time_slot مشخص باشد → فقط آن کلاس خاص لغو است
    - اگر professor_name + cancel_date مشخص باشد (بدون time_slot) → تمام کلاس‌های آن استاد در آن روز
    - بازه تاریخی: start_date / end_date
    """
    __tablename__ = 'cancelled_class'
    id = db.Column(db.Integer, primary_key=True)
    professor_name = db.Column(db.String(100), nullable=True)
    course_name = db.Column(db.String(100), nullable=True)
    time_slot = db.Column(db.String(20), nullable=True)   # ساعت تشکیل کلاس (جدید)
    cancel_date = db.Column(db.Date, nullable=True)
    start_date = db.Column(db.Date, nullable=True)
    end_date = db.Column(db.Date, nullable=True)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=now_tehran)

    viewer_records = db.relationship('CancelledClassView', backref='cancelled_class',
                                     lazy='dynamic', cascade='all, delete-orphan')


class CancelledClassView(db.Model):
    """ردیابی اینکه کدام کاربر کدام لغو کلاس را دیده"""
    __tablename__ = 'cancelled_class_view'
    id = db.Column(db.Integer, primary_key=True)
    cancelled_class_id = db.Column(db.Integer, db.ForeignKey('cancelled_class.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    viewed_at = db.Column(db.DateTime, default=now_tehran)
    __table_args__ = (db.UniqueConstraint('cancelled_class_id', 'user_id'),)


class Notification(db.Model):
    __tablename__ = 'notification'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=now_tehran)


class SystemSetting(db.Model):
    __tablename__ = 'system_setting'
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.String(100), nullable=True)


# ==========================================
# Deadline Models
# ==========================================

class Deadline(db.Model):
    __tablename__ = 'deadline'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    deadline_type = db.Column(db.String(50), default='other')  # project/exam/assignment/other
    due_date = db.Column(db.Date, nullable=False)  # ذخیره به صورت میلادی
    color = db.Column(db.String(10), default='#6C63FF')
    is_done = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=now_tehran)
    user = db.relationship('User', foreign_keys=[user_id])


# ==========================================
# Study Resource Models
# ==========================================

class StudyResource(db.Model):
    __tablename__ = 'study_resource'
    id = db.Column(db.Integer, primary_key=True)
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    course_name = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50), nullable=False)  # notes/slides/sample_questions/book
    file_path = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, default=0)   # bytes
    file_format = db.Column(db.String(10), nullable=False)  # pdf/docx/pptx/zip
    upload_date = db.Column(db.DateTime, default=now_tehran)
    download_count = db.Column(db.Integer, default=0)
    is_deleted = db.Column(db.Boolean, default=False)

    uploader = db.relationship('User', foreign_keys=[uploader_id])
    likes = db.relationship('ResourceLike', backref='resource', lazy='dynamic',
                            cascade='all, delete-orphan')


class ResourceLike(db.Model):
    __tablename__ = 'resource_like'
    id = db.Column(db.Integer, primary_key=True)
    resource_id = db.Column(db.Integer, db.ForeignKey('study_resource.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=now_tehran)
    __table_args__ = (db.UniqueConstraint('resource_id', 'user_id'),)


# ==========================================
# create_initial_data
# ==========================================

def create_initial_data():
    """ایجاد داده‌های اولیه پس از db.create_all() — ایمن در برابر اجرای مکرر"""
    try:
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
            print("✓ Admin user created: ID=admin | Password=admin123")
        else:
            print("✓ Admin user already exists, skipping.")

        # ایجاد تنظیمات پیش‌فرض گروه
        if not GroupSetting.query.first():
            db.session.add(GroupSetting())
            db.session.commit()
            print("✓ GroupSetting initialized.")
    except Exception as e:
        db.session.rollback()
        print(f"Warning: create_initial_data error: {e}")


# ==========================================
# Helpers
# ==========================================

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def allowed_resource_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in RESOURCE_ALLOWED_EXTENSIONS


def get_file_format(filename):
    return filename.rsplit('.', 1)[1].lower() if '.' in filename else ''


def is_group_admin(user_id):
    """بررسی اینکه آیا کاربر ادمین گروه است (ادمین سایت یا ادمین گروه)"""
    user = db.session.get(User, user_id)
    if user and user.is_admin:
        return True
    member = GroupMember.query.filter_by(user_id=user_id).first()
    return member and member.role == 'admin'


def serialize_reactions(reactions_query):
    """تبدیل reactions به dict برای ارسال به کلاینت"""
    result = {}
    for r in reactions_query.all():
        user = db.session.get(User, r.user_id)
        if r.emoji not in result:
            result[r.emoji] = {'count': 0, 'users': []}
        result[r.emoji]['count'] += 1
        result[r.emoji]['users'].append({
            'id': r.user_id,
            'name': user.full_name if user else '?'
        })
    return result


def serialize_message(msg, current_user_id):
    """تبدیل Message به dict"""
    reply_data = None
    if msg.reply_to_id and msg.reply_to:
        reply_data = {
            'id': msg.reply_to.id,
            'content': msg.reply_to.content,
            'sender_name': msg.reply_to.sender.full_name if msg.reply_to.sender else '?'
        }
    return {
        'id': msg.id,
        'sender_id': msg.sender_id,
        'receiver_id': msg.receiver_id,
        'sender_name': msg.sender.full_name if msg.sender else '?',
        'sender_student_id': msg.sender.student_id if msg.sender else '',
        'content': msg.content,
        'file_path': msg.file_path,
        'timestamp': fmt_time(msg.timestamp),
        'timestamp_full': fmt_datetime(msg.timestamp),
        'read_at': fmt_datetime(msg.read_at),
        'delivered_at': fmt_datetime(msg.delivered_at),
        'is_edited': msg.is_edited,
        'is_pinned': msg.is_pinned,
        'reply_to': reply_data,
        'reactions': serialize_reactions(msg.reactions),
        'deleted_for_sender': msg.deleted_for_sender,
        'deleted_for_receiver': msg.deleted_for_receiver,
        'forwarded_from_id': msg.forwarded_from_id,
        # وضعیت تیک
        'status': ('read' if msg.read_at else
                   'delivered' if msg.delivered_at else 'sent')
    }


def serialize_group_message(msg, current_user_id):
    """تبدیل GroupMessage به dict"""
    reply_data = None
    if msg.reply_to_id and msg.reply_to:
        reply_data = {
            'id': msg.reply_to.id,
            'content': msg.reply_to.content if not msg.reply_to.is_deleted else '[پیام حذف شده]',
            'sender_name': msg.reply_to.sender.full_name if msg.reply_to.sender else '?'
        }
    return {
        'id': msg.id,
        'sender_id': msg.sender_id,
        'sender_name': msg.sender.full_name if msg.sender else '?',
        'sender_student_id': msg.sender.student_id if msg.sender else '',
        'sender_pic': msg.sender.profile_pic if msg.sender else 'default.jpg',
        'content': '[پیام حذف شده]' if msg.is_deleted else (msg.content or ''),
        'file_path': None if msg.is_deleted else msg.file_path,
        'timestamp': fmt_time(msg.timestamp),
        'timestamp_full': fmt_datetime(msg.timestamp),
        'is_deleted': msg.is_deleted,
        'is_pinned': msg.is_pinned,
        'forwarded_info': msg.forwarded_info,
        'reply_to': reply_data,
        'reactions': {} if msg.is_deleted else serialize_reactions(msg.reactions),
    }


def serialize_channel_message(msg, current_user_id, is_admin=False):
    """تبدیل ChannelMessage به dict"""
    result = {
        'id': msg.id,
        'sender_id': msg.sender_id,
        'content': '[پیام حذف شده]' if msg.is_deleted else msg.content,
        'file_path': None if msg.is_deleted else msg.file_path,
        'timestamp': fmt_time(msg.timestamp),
        'timestamp_full': fmt_datetime(msg.timestamp),
        'is_edited': msg.is_edited,
        'is_deleted': msg.is_deleted,
        'is_pinned': msg.is_pinned,
        'reactions': {} if msg.is_deleted else serialize_reactions(msg.reactions),
    }
    # آمار بازدید فقط برای ادمین
    if is_admin:
        result['view_count'] = msg.view_count
    return result


def parse_mentions(content):
    """استخراج شماره دانشجویی‌های mention شده با @"""
    return re.findall(r'@(\w+)', content)


def send_mention_notifications(content, sender_id, context='group'):
    """ارسال نوتیفیکیشن به کاربران mention شده"""
    mentioned_ids = parse_mentions(content)
    sender = db.session.get(User, sender_id)
    sender_name = sender.full_name if sender else '?'
    for sid in mentioned_ids:
        user = User.query.filter_by(student_id=sid).first()
        if user and user.id != sender_id:
            notif = Notification(
                user_id=user.id,
                message=f"{sender_name} در {'گروه' if context == 'group' else 'کانال'} شما را منشن کرد."
            )
            db.session.add(notif)


# ==========================================
# Services
# ==========================================

class AuthService:
    @staticmethod
    def register_user(full_name, student_id, major, password):
        try:
            hashed = generate_password_hash(password, method='pbkdf2:sha256')
            is_admin = (student_id == 'admin')
            new_user = User(
                full_name=full_name,
                student_id=student_id,
                major=major,
                password_hash=hashed,
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
                # بررسی بلاک
                blocked = UserBlock.query.filter(
                    or_(
                        and_(UserBlock.blocker_id == user_id, UserBlock.blocked_id == other_user.id),
                        and_(UserBlock.blocker_id == other_user.id, UserBlock.blocked_id == user_id)
                    )
                ).first()
                conversations.append({
                    'other_user_id': other_user.id,
                    'other_user_name': other_user.full_name,
                    'other_user_student_id': other_user.student_id,
                    'other_user_pic': other_user.profile_pic,
                    'last_message_content': '[پیام حذف شده]' if (
                        (msg.deleted_for_sender and msg.sender_id == user_id) or
                        (msg.deleted_for_receiver and msg.receiver_id == user_id)
                    ) else msg.content,
                    'last_message_timestamp': fmt_time(msg.timestamp),
                    'has_unread': unread > 0,
                    'is_online': StateManager.is_online(other_user.id),
                    'is_blocked': blocked is not None
                })
            return conversations
        except Exception as e:
            app.logger.error(f"get_inbox_conversations error: {e}")
            return []

    @staticmethod
    def get_chat_history(current_user_id, other_user_id, limit=50, offset=0):
        try:
            # علامت‌گذاری پیام‌های خوانده‌نشده به عنوان خوانده‌شده
            Message.query.filter(
                and_(
                    Message.sender_id == other_user_id,
                    Message.receiver_id == current_user_id,
                    Message.read_at.is_(None)
                )
            ).update({Message.read_at: now_tehran()}, synchronize_session=False)
            db.session.commit()

            messages = Message.query.filter(
                or_(
                    and_(Message.sender_id == current_user_id,
                         Message.receiver_id == other_user_id,
                         Message.deleted_for_sender.is_(False)),
                    and_(Message.sender_id == other_user_id,
                         Message.receiver_id == current_user_id,
                         Message.deleted_for_receiver.is_(False))
                )
            ).order_by(Message.timestamp.desc()).limit(limit).offset(offset).all()
            return messages[::-1]
        except Exception as e:
            app.logger.error(f"get_chat_history error: {e}")
            return []

    @staticmethod
    def save_message(sender_id, receiver_id, content, file_path=None,
                     reply_to_id=None, forwarded_from_id=None):
        msg = Message(
            sender_id=sender_id,
            receiver_id=receiver_id,
            content=content,
            file_path=file_path,
            timestamp=now_tehran(),
            reply_to_id=reply_to_id,
            forwarded_from_id=forwarded_from_id
        )
        # اگر گیرنده آنلاین است، delivered_at را همین لحظه ست کن
        if StateManager.is_online(receiver_id):
            msg.delivered_at = now_tehran()
        db.session.add(msg)
        db.session.commit()
        return msg


# ==========================================
# Forms
# ==========================================

MAJOR_CHOICES = [
    ('', 'انتخاب کنید'),
    ('مهندسی کامپیوتر', 'مهندسی کامپیوتر'),
    ('علوم کامپیوتر', 'علوم کامپیوتر')
]


class RegistrationForm(FlaskForm):
    full_name = StringField('نام و نام خانوادگی',
                            validators=[DataRequired(message='نام الزامی است')])
    student_id = StringField('شماره دانشجویی', validators=[
        DataRequired(message='شماره دانشجویی الزامی است'),
        Length(min=10, max=10, message='شماره دانشجویی باید ۱۰ رقم باشد')
    ])
    major = SelectField('رشته تحصیلی', choices=MAJOR_CHOICES,
                        validators=[DataRequired(message='انتخاب رشته الزامی است')])
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
    student_id = StringField('شماره دانشجویی',
                             validators=[DataRequired(message='شماره دانشجویی الزامی است')])
    password = PasswordField('رمز عبور',
                             validators=[DataRequired(message='رمز عبور الزامی است')])
    submit = SubmitField('ورود')


class UpdateProfileForm(FlaskForm):
    full_name = StringField('نام و نام خانوادگی', validators=[DataRequired()])
    major = SelectField('رشته تحصیلی', choices=MAJOR_CHOICES)
    submit = SubmitField('بروزرسانی')


class UpdatePasswordForm(FlaskForm):
    current_password = PasswordField('رمز عبور فعلی', validators=[DataRequired()])
    new_password = PasswordField('رمز عبور جدید', validators=[
        DataRequired(),
        Length(min=6, message='رمز عبور جدید باید حداقل ۶ کاراکتر باشد')
    ])
    confirm_new_password = PasswordField('تکرار رمز جدید', validators=[
        DataRequired(),
        EqualTo('new_password', message='رمزهای جدید مطابقت ندارند')
    ])
    submit = SubmitField('تغییر رمز عبور')


# ==========================================
# Decorators
# ==========================================

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


# ==========================================
# Context Processor
# ==========================================

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


# ==========================================
# Utilities
# ==========================================

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
    except Exception:
        db.session.rollback()


# ==========================================
# Error Handlers
# ==========================================

@app.errorhandler(404)
def not_found_error(e):
    if request.is_json or request.path.startswith('/api/'):
        return jsonify({'error': 'یافت نشد', 'code': 404}), 404
    return render_template('error.html', error_code=404,
                           error_msg='صفحه مورد نظر یافت نشد.'), 404


@app.errorhandler(500)
def internal_error(e):
    db.session.rollback()
    if request.is_json or request.path.startswith('/api/'):
        return jsonify({'error': 'خطای داخلی سرور', 'code': 500}), 500
    return render_template('error.html', error_code=500,
                           error_msg='خطای داخلی سرور. لطفاً دوباره تلاش کنید.'), 500


@app.errorhandler(403)
def forbidden_error(e):
    return render_template('error.html', error_code=403,
                           error_msg='دسترسی به این صفحه مجاز نیست.'), 403


# ==========================================
# Routes — General
# ==========================================

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


# ==========================================
# Routes — Auth
# ==========================================

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
            app.logger.error(f"register error: {e}")
            flash('خطا در ثبت‌نام. لطفاً دوباره تلاش کنید.', 'error')
    else:
        # ارسال خطاهای اعتبارسنجی برای نمایش به کاربر
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{error}', 'error')
    return render_template('register.html', form=form, login_form=LoginForm())


@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user = AuthService.authenticate_user(
            login_form.student_id.data, login_form.password.data
        )
        if user:
            session['current_user_id'] = user.id
            session['current_user_name'] = user.full_name
            session['current_user_pic'] = user.profile_pic
            session['is_admin'] = user.is_admin
            flash('با موفقیت وارد شدید. خوش آمدید!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('شماره دانشجویی یا رمز عبور اشتباه است.', 'error')
    else:
        for field, errors in login_form.errors.items():
            for error in errors:
                flash(f'{error}', 'error')
    return render_template('register.html', form=RegistrationForm(), login_form=login_form)


@app.route('/logout')
@login_required
def logout():
    StateManager.set_offline(session.get('current_user_id'))
    session.clear()
    flash('با موفقیت از حساب کاربری خارج شدید.', 'info')
    return redirect(url_for('index'))


# ==========================================
# Routes — Dashboard
# ==========================================

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
        weekday_name = ['شنبه', 'یکشنبه', 'دوشنبه', 'سه‌شنبه',
                        'چهارشنبه', 'پنجشنبه', 'جمعه'][today_j.weekday()]
        today_gregorian = today_j.togregorian()
    except Exception:
        today_j = None
        weekday_name = ''
        today_gregorian = datetime.today().date()

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

    # شمارش لغو کلاس‌های دیده‌نشده
    try:
        all_cancelled_ids = [c.id for c in all_cancelled]
        if all_cancelled_ids:
            viewed_ids = [v.cancelled_class_id for v in
                          CancelledClassView.query.filter(
                              CancelledClassView.user_id == current_user_id,
                              CancelledClassView.cancelled_class_id.in_(all_cancelled_ids)
                          ).all()]
            unviewed_cancelled_count = len(set(all_cancelled_ids) - set(viewed_ids))
        else:
            unviewed_cancelled_count = 0
    except Exception:
        unviewed_cancelled_count = 0

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
        notifications=notifications,
        unviewed_cancelled_count=unviewed_cancelled_count
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
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/bulk_update_schedule', methods=['POST'])
@csrf.exempt
@login_required
def bulk_update_schedule():
    try:
        data = request.get_json()
        if not data or 'schedules' not in data:
            return jsonify({'status': 'error', 'message': 'داده‌ای ارسال نشد'}), 400
        user_id = session['current_user_id']
        schedules = data['schedules']
        ClassSchedule.query.filter_by(user_id=user_id).delete()
        for item in schedules:
            if item.get('course_name') and str(item['course_name']).strip():
                db.session.add(ClassSchedule(
                    user_id=user_id,
                    day=item['day'],
                    time_slot=item['time_slot'],
                    course_name=str(item['course_name']).strip(),
                    class_location=str(item.get('class_location', '')).strip(),
                    professor_name=str(item.get('professor_name', '')).strip(),
                    week_type=item.get('week_type', 'all')
                ))
        db.session.commit()
        return jsonify({'status': 'success', 'count': len(schedules)})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/master_schedule')
@login_required
def get_master_schedule():
    try:
        slots = MasterSchedule.query.all()
        reservations = Reservation.query.filter_by(status='approved').all()
        reserved_map = {f"{r.master_slot_id}_{r.room_name}": True for r in reservations}
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
            master_slot_id=slot_id, room_name=room_name, status='approved'
        ).first()
        if exists:
            flash('این کلاس قبلاً رزرو شده است.', 'error')
            return redirect(url_for('dashboard'))
        db.session.add(Reservation(
            user_id=session['current_user_id'],
            master_slot_id=slot_id,
            room_name=room_name,
            reason=reason
        ))
        db.session.commit()
        flash('درخواست رزرو با موفقیت ثبت شد و در انتظار تأیید است.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('خطا در ثبت درخواست. لطفاً دوباره تلاش کنید.', 'error')
    return redirect(url_for('dashboard'))


# ==========================================
# Routes — Admin
# ==========================================

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
            cancelled_classes=cancelled,
            class_time_slots=CLASS_TIME_SLOTS
        )
    except Exception as e:
        app.logger.error(f"admin_dashboard error: {e}")
        flash('خطا در بارگذاری پنل مدیریت.', 'error')
        return redirect(url_for('index'))


@app.route('/admin/save_master_schedule', methods=['POST'])
@csrf.exempt
@admin_required
def save_master_schedule():
    try:
        data = request.get_json()
        if data is None:
            return jsonify({'status': 'error', 'message': 'داده‌ای ارسال نشد'}), 400
        MasterSchedule.query.delete()
        db.session.flush()
        for item in data:
            if item.get('rooms') and str(item['rooms']).strip():
                db.session.add(MasterSchedule(
                    day=item['day'],
                    time_slot=item['time_slot'],
                    rooms=item['rooms'].strip()
                ))
        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
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
            db.session.add(Notification(
                user_id=req.user_id,
                message=f"درخواست رزرو شما برای کلاس {req.room_name} در {slot_info} تأیید شد."
            ))
            Reservation.query.filter(
                Reservation.master_slot_id == req.master_slot_id,
                Reservation.room_name == req.room_name,
                Reservation.id != req.id,
                Reservation.status == 'pending'
            ).update({Reservation.status: 'rejected'}, synchronize_session=False)
            flash('درخواست رزرو تأیید شد.', 'success')
        elif action == 'reject':
            req.status = 'rejected'
            db.session.add(Notification(
                user_id=req.user_id,
                message=f"متأسفانه درخواست رزرو شما برای کلاس {req.room_name} رد شد."
            ))
            flash('درخواست رزرو رد شد.', 'info')
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash('خطا در پردازش درخواست.', 'error')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/add_cancelled_class', methods=['POST'])
@admin_required
def add_cancelled_class():
    """
    فرم ارسالی (از تقویم شمسی تبدیل به میلادی):
    - professor, course, time_slot
    - cancel_date_j (شمسی YYYY/MM/DD)، start_date_j، end_date_j
    - desc
    منطق: اگر time_slot ارسال شود → کلاس خاص لغو است
           اگر فقط professor + cancel_date → تمام کلاس‌های آن استاد در آن روز
    """
    try:
        prof = request.form.get('professor', '').strip()
        course = request.form.get('course', '').strip()
        time_slot = request.form.get('time_slot', '').strip()
        desc = request.form.get('desc', '').strip()

        def jalali_to_gregorian(j_str):
            """تبدیل YYYY/MM/DD شمسی به date میلادی"""
            if not j_str:
                return None
            try:
                parts = j_str.replace('-', '/').split('/')
                jd = jdatetime.date(int(parts[0]), int(parts[1]), int(parts[2]))
                return jd.togregorian()
            except Exception:
                return None

        cancel_date = jalali_to_gregorian(request.form.get('cancel_date_j', ''))
        start_date = jalali_to_gregorian(request.form.get('start_date_j', ''))
        end_date = jalali_to_gregorian(request.form.get('end_date_j', ''))

        new_cancel = CancelledClass(
            professor_name=prof or None,
            course_name=course or None,
            time_slot=time_slot or None,
            description=desc or None,
            cancel_date=cancel_date,
            start_date=start_date,
            end_date=end_date
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


@app.route('/admin/conversations')
@admin_required
def admin_conversations():
    """ادمین می‌تواند لیست تمام مکالمات خصوصی را ببیند"""
    try:
        # آخرین پیام هر جفت کاربر
        subq = db.session.query(
            func.min(case(
                (Message.sender_id < Message.receiver_id, Message.sender_id),
                else_=Message.receiver_id
            )).label('u1'),
            func.min(case(
                (Message.sender_id < Message.receiver_id, Message.receiver_id),
                else_=Message.sender_id
            )).label('u2'),
            func.max(Message.id).label('last_id')
        ).group_by(
            case((Message.sender_id < Message.receiver_id, Message.sender_id),
                 else_=Message.receiver_id),
            case((Message.sender_id < Message.receiver_id, Message.receiver_id),
                 else_=Message.sender_id)
        ).subquery()

        results = db.session.query(Message, subq.c.u1, subq.c.u2).filter(
            Message.id == subq.c.last_id
        ).order_by(Message.timestamp.desc()).all()

        conversations = []
        for msg, u1, u2 in results:
            user1 = db.session.get(User, u1)
            user2 = db.session.get(User, u2)
            if user1 and user2:
                conversations.append({
                    'user1': user1,
                    'user2': user2,
                    'last_message': msg
                })
        return render_template('admin_conversations.html', conversations=conversations)
    except Exception as e:
        app.logger.error(f"admin_conversations error: {e}")
        flash('خطا در بارگذاری مکالمات.', 'error')
        return redirect(url_for('admin_dashboard'))


@app.route('/admin/conversation/<int:u1>/<int:u2>')
@admin_required
def admin_view_conversation(u1, u2):
    """ادمین مکالمه خصوصی بین دو کاربر را می‌بیند"""
    user1 = db.session.get(User, u1)
    user2 = db.session.get(User, u2)
    if not user1 or not user2:
        abort(404)
    messages = Message.query.filter(
        or_(
            and_(Message.sender_id == u1, Message.receiver_id == u2),
            and_(Message.sender_id == u2, Message.receiver_id == u1)
        )
    ).order_by(Message.timestamp.asc()).all()
    return render_template('admin_conversation.html',
                           user1=user1, user2=user2, messages=messages)


# ==========================================
# Routes — Cancelled Class API
# ==========================================

@app.route('/api/cancelled_classes/mark_viewed', methods=['POST'])
@csrf.exempt
@login_required
def mark_cancelled_classes_viewed():
    """علامت‌گذاری یک یا چند لغو کلاس به عنوان دیده‌شده"""
    try:
        data = request.get_json() or {}
        class_ids = data.get('ids', [])
        user_id = session['current_user_id']
        for cid in class_ids:
            existing = CancelledClassView.query.filter_by(
                cancelled_class_id=cid, user_id=user_id
            ).first()
            if not existing:
                db.session.add(CancelledClassView(
                    cancelled_class_id=cid, user_id=user_id
                ))
        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/cancelled_classes/unviewed_count')
@login_required
def unviewed_cancelled_count():
    """تعداد لغو کلاس‌های دیده‌نشده برای کاربر فعلی"""
    try:
        user_id = session['current_user_id']
        all_ids = [c.id for c in CancelledClass.query.all()]
        if not all_ids:
            return jsonify({'count': 0})
        viewed_ids = [v.cancelled_class_id for v in
                      CancelledClassView.query.filter(
                          CancelledClassView.user_id == user_id,
                          CancelledClassView.cancelled_class_id.in_(all_ids)
                      ).all()]
        count = len(set(all_ids) - set(viewed_ids))
        return jsonify({'count': count})
    except Exception as e:
        return jsonify({'count': 0})


# ==========================================
# Routes — Profile
# ==========================================

@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    can_edit = (session['current_user_id'] == user_id)
    return render_template(
        'profile.html',
        user=user,
        can_edit=can_edit,
        update_profile_form=UpdateProfileForm(obj=user) if can_edit else None,
        update_password_form=UpdatePasswordForm() if can_edit else None,
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
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(error, 'error')
    except Exception as e:
        db.session.rollback()
        flash('خطا در تغییر رمز عبور.', 'error')
    return redirect(url_for('profile', user_id=session['current_user_id']))


@app.route('/api/privacy_settings', methods=['GET', 'POST'])
@login_required
def privacy_settings():
    user = db.session.get(User, session['current_user_id'])
    if not user:
        return jsonify({'error': 'کاربر یافت نشد'}), 404
    if request.method == 'POST':
        try:
            data = request.get_json() or {}
            if 'last_seen_visibility' in data:
                user.last_seen_visibility = data['last_seen_visibility']
            if 'profile_pic_visibility' in data:
                user.profile_pic_visibility = data['profile_pic_visibility']
            if 'who_can_message' in data:
                user.who_can_message = data['who_can_message']
            db.session.commit()
            return jsonify({'status': 'success'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
    return jsonify({
        'last_seen_visibility': user.last_seen_visibility,
        'profile_pic_visibility': user.profile_pic_visibility,
        'who_can_message': user.who_can_message
    })


# ==========================================
# Routes — Chat
# ==========================================

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
        channel_messages = ChannelMessage.query.filter_by(
            is_deleted=False
        ).order_by(ChannelMessage.timestamp.desc()).limit(50).all()
        channel_messages = channel_messages[::-1]
    except Exception:
        channel_messages = []

    try:
        group_setting = GroupSetting.query.first()
    except Exception:
        group_setting = None

    current_user_id = session['current_user_id']
    group_member = GroupMember.query.filter_by(user_id=current_user_id).first()

    return render_template(
        'chat.html',
        conversations=conversations,
        active_chat_user=active_chat_user,
        messages=messages,
        group_messages=group_messages,
        channel_messages=channel_messages,
        group_setting=group_setting,
        group_member=group_member,
        is_group_admin=is_group_admin(current_user_id)
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
                f"{session['current_user_id']}_{now_tehran().strftime('%Y%m%d%H%M%S')}_{file.filename}"
            )
            filepath = os.path.join(app.config['CHAT_UPLOAD_FOLDER'], filename)
            file.save(filepath)
            return jsonify({'filepath': f'/static/uploads/chat_files/{filename}'})
        return jsonify({'error': 'نوع فایل مجاز نیست'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/user_status/<int:user_id>')
def check_user_online(user_id):
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'online': False})
    return jsonify({
        'online': StateManager.is_online(user_id),
        'last_seen': fmt_datetime(user.last_seen)
    })


@app.route('/api/online_users')
@login_required
def get_online_users():
    try:
        online_ids = list(ONLINE_USERS_MEMORY)
        users = User.query.filter(User.id.in_(online_ids)).all() if online_ids else []
        result = [{'id': u.id, 'name': u.full_name,
                   'student_id': u.student_id, 'pic': u.profile_pic} for u in users]
        return jsonify(result)
    except Exception:
        return jsonify([])


@app.route('/api/all_users')
@login_required
def get_all_users():
    try:
        users = User.query.filter(
            User.id != session['current_user_id']
        ).order_by(User.full_name).all()
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


# ==========================================
# Routes — Message API (خصوصی)
# ==========================================

@app.route('/api/messages/search')
@login_required
def search_messages():
    """جستجو در تاریخچه پیام‌های یک مکالمه"""
    try:
        q = request.args.get('q', '').strip()
        other_user_id = request.args.get('user_id', type=int)
        if not q or not other_user_id:
            return jsonify([])
        current_uid = session['current_user_id']
        msgs = Message.query.filter(
            or_(
                and_(Message.sender_id == current_uid, Message.receiver_id == other_user_id),
                and_(Message.sender_id == other_user_id, Message.receiver_id == current_uid)
            ),
            Message.content.ilike(f'%{q}%'),
            Message.deleted_for_sender.is_(False),
            Message.deleted_for_receiver.is_(False)
        ).order_by(Message.timestamp.desc()).limit(20).all()
        return jsonify([serialize_message(m, current_uid) for m in msgs])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/messages/<int:msg_id>/react', methods=['POST'])
@csrf.exempt
@login_required
def react_message(msg_id):
    try:
        data = request.get_json() or {}
        emoji = data.get('emoji', '').strip()
        if not emoji:
            return jsonify({'error': 'emoji الزامی است'}), 400
        user_id = session['current_user_id']
        msg = Message.query.get_or_404(msg_id)
        # بررسی دسترسی
        if msg.sender_id != user_id and msg.receiver_id != user_id:
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        existing = MessageReaction.query.filter_by(
            message_id=msg_id, user_id=user_id, emoji=emoji
        ).first()
        if existing:
            db.session.delete(existing)
            action = 'removed'
        else:
            db.session.add(MessageReaction(
                message_id=msg_id, user_id=user_id, emoji=emoji
            ))
            action = 'added'
        db.session.commit()
        reactions = serialize_reactions(msg.reactions)
        room = f"chat-{min(msg.sender_id, msg.receiver_id)}-{max(msg.sender_id, msg.receiver_id)}"
        socketio.emit('message_reaction_updated', {
            'message_id': msg_id, 'reactions': reactions
        }, room=room)
        return jsonify({'status': 'success', 'action': action, 'reactions': reactions})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/messages/<int:msg_id>/edit', methods=['POST'])
@csrf.exempt
@login_required
def edit_message(msg_id):
    try:
        data = request.get_json() or {}
        new_content = data.get('content', '').strip()
        if not new_content:
            return jsonify({'error': 'محتوا الزامی است'}), 400
        user_id = session['current_user_id']
        msg = Message.query.get_or_404(msg_id)
        if msg.sender_id != user_id:
            return jsonify({'error': 'فقط فرستنده می‌تواند پیام را ویرایش کند'}), 403
        # ذخیره تاریخچه ویرایش
        history = json.loads(msg.edit_history) if msg.edit_history else []
        history.append({'content': msg.content, 'edited_at': fmt_datetime(now_tehran())})
        msg.content = new_content
        msg.is_edited = True
        msg.edit_history = json.dumps(history, ensure_ascii=False)
        db.session.commit()
        room = f"chat-{min(msg.sender_id, msg.receiver_id)}-{max(msg.sender_id, msg.receiver_id)}"
        socketio.emit('message_edited', {
            'message_id': msg_id, 'new_content': new_content,
            'edit_history': history
        }, room=room)
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/messages/<int:msg_id>/delete', methods=['POST'])
@csrf.exempt
@login_required
def delete_message(msg_id):
    """
    حذف پیام: delete_for=me یا delete_for=everyone
    """
    try:
        data = request.get_json() or {}
        delete_for = data.get('delete_for', 'me')
        user_id = session['current_user_id']
        msg = Message.query.get_or_404(msg_id)
        if msg.sender_id != user_id and msg.receiver_id != user_id:
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        if delete_for == 'everyone' and msg.sender_id == user_id:
            msg.deleted_for_sender = True
            msg.deleted_for_receiver = True
            room = f"chat-{min(msg.sender_id, msg.receiver_id)}-{max(msg.sender_id, msg.receiver_id)}"
            socketio.emit('message_deleted', {
                'message_id': msg_id, 'delete_for': 'everyone'
            }, room=room)
        else:
            if msg.sender_id == user_id:
                msg.deleted_for_sender = True
            else:
                msg.deleted_for_receiver = True
        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/messages/<int:msg_id>/pin', methods=['POST'])
@csrf.exempt
@login_required
def pin_message(msg_id):
    try:
        user_id = session['current_user_id']
        msg = Message.query.get_or_404(msg_id)
        if msg.sender_id != user_id and msg.receiver_id != user_id:
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        msg.is_pinned = not msg.is_pinned
        db.session.commit()
        room = f"chat-{min(msg.sender_id, msg.receiver_id)}-{max(msg.sender_id, msg.receiver_id)}"
        socketio.emit('message_pinned', {
            'message_id': msg_id, 'is_pinned': msg.is_pinned
        }, room=room)
        return jsonify({'status': 'success', 'is_pinned': msg.is_pinned})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/messages/<int:msg_id>/forward', methods=['POST'])
@csrf.exempt
@login_required
def forward_message(msg_id):
    """فوروارد پیام به مکالمه خصوصی یا گروه"""
    try:
        data = request.get_json() or {}
        target_type = data.get('target_type', 'private')  # private / group
        target_id = data.get('target_id')
        user_id = session['current_user_id']
        original = Message.query.get_or_404(msg_id)
        # بررسی دسترسی
        if original.sender_id != user_id and original.receiver_id != user_id:
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403

        now = now_tehran()
        if target_type == 'private' and target_id:
            new_msg = Message(
                sender_id=user_id,
                receiver_id=int(target_id),
                content=original.content,
                file_path=original.file_path,
                timestamp=now,
                forwarded_from_id=msg_id
            )
            if StateManager.is_online(int(target_id)):
                new_msg.delivered_at = now
            db.session.add(new_msg)
            db.session.commit()
            sender = db.session.get(User, user_id)
            room = f"chat-{min(user_id, int(target_id))}-{max(user_id, int(target_id))}"
            socketio.emit('new_message', {
                'sender_name': sender.full_name if sender else '',
                'sender_student_id': sender.student_id if sender else '',
                'content': original.content,
                'timestamp': fmt_time(now),
                'sender_id': user_id,
                'file_path': original.file_path,
                'message_id': new_msg.id,
                'forwarded_from_id': msg_id
            }, room=room)
        elif target_type == 'group':
            fwd_sender = db.session.get(User, original.sender_id)
            fwd_info = f"فوروارد از: {fwd_sender.full_name}" if fwd_sender else "فوروارد"
            grp_msg = GroupMessage(
                sender_id=user_id,
                content=original.content,
                file_path=original.file_path,
                timestamp=now,
                forwarded_info=fwd_info
            )
            db.session.add(grp_msg)
            db.session.commit()
            sender = db.session.get(User, user_id)
            socketio.emit('new_group_message', {
                'id': grp_msg.id,
                'sender_id': user_id,
                'sender_name': sender.full_name if sender else '',
                'content': original.content,
                'file_path': original.file_path,
                'timestamp': fmt_time(now),
                'forwarded_info': fwd_info
            }, room='public_group')

        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/chat/<int:other_user_id>/pinned')
@login_required
def get_pinned_messages(other_user_id):
    try:
        current_uid = session['current_user_id']
        pinned = Message.query.filter(
            or_(
                and_(Message.sender_id == current_uid, Message.receiver_id == other_user_id),
                and_(Message.sender_id == other_user_id, Message.receiver_id == current_uid)
            ),
            Message.is_pinned.is_(True)
        ).order_by(Message.timestamp.desc()).all()
        return jsonify([serialize_message(m, current_uid) for m in pinned])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/messages/<int:msg_id>/edit_history')
@login_required
def get_message_edit_history(msg_id):
    try:
        msg = Message.query.get_or_404(msg_id)
        user_id = session['current_user_id']
        if msg.sender_id != user_id and msg.receiver_id != user_id:
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        history = json.loads(msg.edit_history) if msg.edit_history else []
        return jsonify(history)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==========================================
# Routes — User Management (بلاک)
# ==========================================

@app.route('/api/users/<int:target_id>/block', methods=['POST'])
@csrf.exempt
@login_required
def toggle_block_user(target_id):
    try:
        user_id = session['current_user_id']
        if user_id == target_id:
            return jsonify({'error': 'نمی‌توانید خودتان را بلاک کنید'}), 400
        existing = UserBlock.query.filter_by(
            blocker_id=user_id, blocked_id=target_id
        ).first()
        if existing:
            db.session.delete(existing)
            action = 'unblocked'
        else:
            db.session.add(UserBlock(blocker_id=user_id, blocked_id=target_id))
            action = 'blocked'
        db.session.commit()
        return jsonify({'status': 'success', 'action': action})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/users/blocked')
@login_required
def get_blocked_users():
    try:
        user_id = session['current_user_id']
        blocks = UserBlock.query.filter_by(blocker_id=user_id).all()
        result = []
        for b in blocks:
            u = db.session.get(User, b.blocked_id)
            if u:
                result.append({
                    'id': u.id,
                    'name': u.full_name,
                    'student_id': u.student_id,
                    'pic': u.profile_pic
                })
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==========================================
# Routes — Group API
# ==========================================

@app.route('/api/group/settings', methods=['GET', 'POST'])
@csrf.exempt
@login_required
def group_settings():
    setting = GroupSetting.query.first()
    if not setting:
        setting = GroupSetting()
        db.session.add(setting)
        db.session.commit()
    if request.method == 'POST':
        if not is_group_admin(session['current_user_id']):
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        data = request.get_json() or {}
        if 'is_readonly' in data:
            setting.is_readonly = bool(data['is_readonly'])
        db.session.commit()
        socketio.emit('group_settings_updated', {
            'is_readonly': setting.is_readonly
        }, room='public_group')
        return jsonify({'status': 'success', 'is_readonly': setting.is_readonly})
    return jsonify({
        'is_readonly': setting.is_readonly,
        'pinned_message_id': setting.pinned_message_id
    })


@app.route('/api/group/members')
@login_required
def get_group_members():
    """لیست اعضای گروه همراه با نقش هر عضو"""
    try:
        users = User.query.order_by(User.full_name).all()
        member_map = {m.user_id: m for m in GroupMember.query.all()}
        result = []
        for u in users:
            member = member_map.get(u.id)
            result.append({
                'id': u.id,
                'name': u.full_name,
                'student_id': u.student_id,
                'pic': u.profile_pic,
                'role': 'admin' if u.is_admin else (member.role if member else 'member'),
                'is_muted': member.is_muted if member else False,
                'is_banned': member.is_banned if member else False,
                'is_online': StateManager.is_online(u.id)
            })
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def _get_or_create_group_member(user_id):
    member = GroupMember.query.filter_by(user_id=user_id).first()
    if not member:
        member = GroupMember(user_id=user_id)
        db.session.add(member)
    return member


@app.route('/api/group/mute/<int:user_id>', methods=['POST'])
@csrf.exempt
@login_required
def toggle_mute_group_member(user_id):
    if not is_group_admin(session['current_user_id']):
        return jsonify({'error': 'دسترسی غیرمجاز'}), 403
    try:
        member = _get_or_create_group_member(user_id)
        member.is_muted = not member.is_muted
        db.session.commit()
        return jsonify({'status': 'success', 'is_muted': member.is_muted})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/group/ban/<int:user_id>', methods=['POST'])
@csrf.exempt
@login_required
def toggle_ban_group_member(user_id):
    if not is_group_admin(session['current_user_id']):
        return jsonify({'error': 'دسترسی غیرمجاز'}), 403
    try:
        member = _get_or_create_group_member(user_id)
        member.is_banned = not member.is_banned
        db.session.commit()
        socketio.emit('group_member_banned', {
            'user_id': user_id, 'is_banned': member.is_banned
        }, room='public_group')
        return jsonify({'status': 'success', 'is_banned': member.is_banned})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/group/make_admin/<int:user_id>', methods=['POST'])
@csrf.exempt
@login_required
def toggle_group_admin(user_id):
    if not session.get('is_admin'):
        return jsonify({'error': 'فقط مدیر سیستم می‌تواند نقش ادمین بدهد'}), 403
    try:
        member = _get_or_create_group_member(user_id)
        member.role = 'member' if member.role == 'admin' else 'admin'
        db.session.commit()
        return jsonify({'status': 'success', 'role': member.role})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/group/message/<int:msg_id>/delete', methods=['POST'])
@csrf.exempt
@login_required
def delete_group_message(msg_id):
    """ادمین یا فرستنده می‌تواند پیام گروه را حذف کند"""
    try:
        user_id = session['current_user_id']
        msg = GroupMessage.query.get_or_404(msg_id)
        if msg.sender_id != user_id and not is_group_admin(user_id):
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        msg.is_deleted = True
        msg.deleted_by = user_id
        db.session.commit()
        socketio.emit('group_message_deleted', {'message_id': msg_id}, room='public_group')
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/group/message/<int:msg_id>/pin', methods=['POST'])
@csrf.exempt
@login_required
def pin_group_message(msg_id):
    if not is_group_admin(session['current_user_id']):
        return jsonify({'error': 'دسترسی غیرمجاز'}), 403
    try:
        msg = GroupMessage.query.get_or_404(msg_id)
        msg.is_pinned = not msg.is_pinned
        setting = GroupSetting.query.first()
        if setting:
            setting.pinned_message_id = msg_id if msg.is_pinned else None
        db.session.commit()
        socketio.emit('group_message_pinned', {
            'message_id': msg_id, 'is_pinned': msg.is_pinned
        }, room='public_group')
        return jsonify({'status': 'success', 'is_pinned': msg.is_pinned})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/group/message/<int:msg_id>/react', methods=['POST'])
@csrf.exempt
@login_required
def react_group_message(msg_id):
    try:
        data = request.get_json() or {}
        emoji = data.get('emoji', '').strip()
        if not emoji:
            return jsonify({'error': 'emoji الزامی است'}), 400
        user_id = session['current_user_id']
        msg = GroupMessage.query.get_or_404(msg_id)
        existing = GroupMessageReaction.query.filter_by(
            message_id=msg_id, user_id=user_id, emoji=emoji
        ).first()
        if existing:
            db.session.delete(existing)
            action = 'removed'
        else:
            db.session.add(GroupMessageReaction(
                message_id=msg_id, user_id=user_id, emoji=emoji
            ))
            action = 'added'
        db.session.commit()
        reactions = serialize_reactions(msg.reactions)
        socketio.emit('group_message_reaction_updated', {
            'message_id': msg_id, 'reactions': reactions
        }, room='public_group')
        return jsonify({'status': 'success', 'action': action, 'reactions': reactions})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/group/search')
@login_required
def search_group_messages():
    try:
        q = request.args.get('q', '').strip()
        if not q:
            return jsonify([])
        msgs = GroupMessage.query.filter(
            GroupMessage.content.ilike(f'%{q}%'),
            GroupMessage.is_deleted.is_(False)
        ).order_by(GroupMessage.timestamp.desc()).limit(20).all()
        user_id = session['current_user_id']
        return jsonify([serialize_group_message(m, user_id) for m in msgs])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==========================================
# Routes — Channel API
# ==========================================

@app.route('/api/channel/message/<int:msg_id>/edit', methods=['POST'])
@csrf.exempt
@admin_required
def edit_channel_message(msg_id):
    try:
        data = request.get_json() or {}
        new_content = data.get('content', '').strip()
        if not new_content:
            return jsonify({'error': 'محتوا الزامی است'}), 400
        msg = ChannelMessage.query.get_or_404(msg_id)
        msg.content = new_content
        msg.is_edited = True
        db.session.commit()
        socketio.emit('channel_message_edited', {
            'message_id': msg_id, 'new_content': new_content
        }, room='channel')
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/channel/message/<int:msg_id>/delete', methods=['POST'])
@csrf.exempt
@admin_required
def delete_channel_message(msg_id):
    try:
        msg = ChannelMessage.query.get_or_404(msg_id)
        msg.is_deleted = True
        db.session.commit()
        socketio.emit('channel_message_deleted', {'message_id': msg_id}, room='channel')
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/channel/message/<int:msg_id>/pin', methods=['POST'])
@csrf.exempt
@admin_required
def pin_channel_message(msg_id):
    try:
        msg = ChannelMessage.query.get_or_404(msg_id)
        msg.is_pinned = not msg.is_pinned
        db.session.commit()
        socketio.emit('channel_message_pinned', {
            'message_id': msg_id, 'is_pinned': msg.is_pinned
        }, room='channel')
        return jsonify({'status': 'success', 'is_pinned': msg.is_pinned})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/channel/message/<int:msg_id>/react', methods=['POST'])
@csrf.exempt
@login_required
def react_channel_message(msg_id):
    try:
        data = request.get_json() or {}
        emoji = data.get('emoji', '').strip()
        user_id = session['current_user_id']
        msg = ChannelMessage.query.get_or_404(msg_id)
        existing = ChannelMessageReaction.query.filter_by(
            message_id=msg_id, user_id=user_id, emoji=emoji
        ).first()
        if existing:
            db.session.delete(existing)
            action = 'removed'
        else:
            db.session.add(ChannelMessageReaction(
                message_id=msg_id, user_id=user_id, emoji=emoji
            ))
            action = 'added'
        db.session.commit()
        reactions = serialize_reactions(msg.reactions)
        socketio.emit('channel_message_reaction_updated', {
            'message_id': msg_id, 'reactions': reactions
        }, room='channel')
        return jsonify({'status': 'success', 'action': action, 'reactions': reactions})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/channel/message/<int:msg_id>/view', methods=['POST'])
@csrf.exempt
@login_required
def view_channel_message(msg_id):
    """ثبت بازدید پیام کانال — فقط یک بار برای هر کاربر"""
    try:
        user_id = session['current_user_id']
        existing = ChannelMessageView.query.filter_by(
            message_id=msg_id, user_id=user_id
        ).first()
        if not existing:
            db.session.add(ChannelMessageView(message_id=msg_id, user_id=user_id))
            msg = ChannelMessage.query.get(msg_id)
            if msg:
                msg.view_count = (msg.view_count or 0) + 1
            db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'ok'})


@app.route('/api/channel/pinned')
@login_required
def get_pinned_channel_message():
    try:
        pinned = ChannelMessage.query.filter_by(
            is_pinned=True, is_deleted=False
        ).order_by(ChannelMessage.timestamp.desc()).first()
        if not pinned:
            return jsonify(None)
        user_id = session['current_user_id']
        is_admin = session.get('is_admin', False)
        return jsonify(serialize_channel_message(pinned, user_id, is_admin))
    except Exception as e:
        return jsonify(None)


@app.route('/api/channel/search')
@login_required
def search_channel_messages():
    try:
        q = request.args.get('q', '').strip()
        if not q:
            return jsonify([])
        msgs = ChannelMessage.query.filter(
            ChannelMessage.content.ilike(f'%{q}%'),
            ChannelMessage.is_deleted.is_(False)
        ).order_by(ChannelMessage.timestamp.desc()).limit(20).all()
        user_id = session['current_user_id']
        is_admin = session.get('is_admin', False)
        return jsonify([serialize_channel_message(m, user_id, is_admin) for m in msgs])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==========================================
# Routes — Deadline
# ==========================================

@app.route('/deadline')
@login_required
def deadline_page():
    return render_template('deadline.html')


@app.route('/api/deadlines', methods=['GET'])
@login_required
def get_deadlines():
    try:
        user_id = session['current_user_id']
        deadlines = Deadline.query.filter_by(user_id=user_id).order_by(Deadline.due_date).all()
        today = date.today()
        result = []
        for d in deadlines:
            days_left = (d.due_date - today).days
            # تبدیل تاریخ میلادی به شمسی
            try:
                jd = jdatetime.date.fromgregorian(date=d.due_date)
                due_date_j = jd.strftime('%Y/%m/%d')
            except Exception:
                due_date_j = str(d.due_date)
            result.append({
                'id': d.id,
                'title': d.title,
                'description': d.description,
                'deadline_type': d.deadline_type,
                'due_date': str(d.due_date),
                'due_date_j': due_date_j,
                'color': d.color,
                'is_done': d.is_done,
                'days_left': days_left,
                'is_near': 0 <= days_left <= 7
            })
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/deadlines', methods=['POST'])
@csrf.exempt
@login_required
def create_deadline():
    try:
        data = request.get_json() or {}
        title = data.get('title', '').strip()
        if not title:
            return jsonify({'error': 'عنوان الزامی است'}), 400
        # تبدیل تاریخ شمسی به میلادی
        due_date_j = data.get('due_date_j', '')
        if due_date_j:
            parts = due_date_j.replace('-', '/').split('/')
            jd = jdatetime.date(int(parts[0]), int(parts[1]), int(parts[2]))
            due_date = jd.togregorian()
        else:
            return jsonify({'error': 'تاریخ الزامی است'}), 400

        deadline = Deadline(
            user_id=session['current_user_id'],
            title=title,
            description=data.get('description', ''),
            deadline_type=data.get('deadline_type', 'other'),
            due_date=due_date,
            color=data.get('color', '#6C63FF')
        )
        db.session.add(deadline)
        db.session.commit()
        return jsonify({'status': 'success', 'id': deadline.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/deadlines/<int:deadline_id>', methods=['PUT'])
@csrf.exempt
@login_required
def update_deadline(deadline_id):
    try:
        dl = Deadline.query.get_or_404(deadline_id)
        if dl.user_id != session['current_user_id']:
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        data = request.get_json() or {}
        if 'title' in data:
            dl.title = data['title'].strip()
        if 'description' in data:
            dl.description = data['description']
        if 'deadline_type' in data:
            dl.deadline_type = data['deadline_type']
        if 'due_date_j' in data and data['due_date_j']:
            parts = data['due_date_j'].replace('-', '/').split('/')
            jd = jdatetime.date(int(parts[0]), int(parts[1]), int(parts[2]))
            dl.due_date = jd.togregorian()
        if 'color' in data:
            dl.color = data['color']
        if 'is_done' in data:
            dl.is_done = bool(data['is_done'])
        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/deadlines/<int:deadline_id>', methods=['DELETE'])
@csrf.exempt
@login_required
def delete_deadline(deadline_id):
    try:
        dl = Deadline.query.get_or_404(deadline_id)
        if dl.user_id != session['current_user_id']:
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        db.session.delete(dl)
        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/deadlines/<int:deadline_id>/share', methods=['POST'])
@csrf.exempt
@login_required
def share_deadline(deadline_id):
    """اشتراک‌گذاری ددلاین در گروه یا چت خصوصی"""
    try:
        dl = Deadline.query.get_or_404(deadline_id)
        if dl.user_id != session['current_user_id']:
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        data = request.get_json() or {}
        target_type = data.get('target_type', 'group')
        target_id = data.get('target_id')
        user_id = session['current_user_id']

        try:
            jd = jdatetime.date.fromgregorian(date=dl.due_date)
            due_str = jd.strftime('%Y/%m/%d')
        except Exception:
            due_str = str(dl.due_date)

        type_labels = {
            'project': 'پروژه', 'exam': 'امتحان',
            'assignment': 'تکلیف', 'other': 'سایر'
        }
        share_content = (
            f"📌 ددلاین: {dl.title}\n"
            f"نوع: {type_labels.get(dl.deadline_type, dl.deadline_type)}\n"
            f"تاریخ: {due_str}"
        )
        if dl.description:
            share_content += f"\n{dl.description}"

        # پیام خاص برای اشتراک‌گذاری ددلاین (با JSON metadata)
        share_metadata = json.dumps({
            'type': 'deadline_share',
            'deadline_id': dl.id,
            'title': dl.title,
            'due_date_j': due_str,
            'deadline_type': dl.deadline_type,
            'color': dl.color
        }, ensure_ascii=False)

        now = now_tehran()
        sender = db.session.get(User, user_id)

        if target_type == 'group':
            msg = GroupMessage(
                sender_id=user_id,
                content=share_content,
                timestamp=now
            )
            db.session.add(msg)
            db.session.commit()
            socketio.emit('new_group_message', {
                'id': msg.id,
                'sender_id': user_id,
                'sender_name': sender.full_name if sender else '',
                'content': share_content,
                'timestamp': fmt_time(now),
                'deadline_share': {
                    'id': dl.id,
                    'title': dl.title,
                    'due_date_j': due_str,
                    'deadline_type': dl.deadline_type,
                    'color': dl.color
                }
            }, room='public_group')

        elif target_type == 'private' and target_id:
            msg = Message(
                sender_id=user_id,
                receiver_id=int(target_id),
                content=share_content,
                timestamp=now
            )
            if StateManager.is_online(int(target_id)):
                msg.delivered_at = now
            db.session.add(msg)
            db.session.commit()
            room = f"chat-{min(user_id, int(target_id))}-{max(user_id, int(target_id))}"
            socketio.emit('new_message', {
                'sender_name': sender.full_name if sender else '',
                'sender_student_id': sender.student_id if sender else '',
                'content': share_content,
                'timestamp': fmt_time(now),
                'sender_id': user_id,
                'message_id': msg.id,
                'deadline_share': {
                    'id': dl.id,
                    'title': dl.title,
                    'due_date_j': due_str,
                    'deadline_type': dl.deadline_type,
                    'color': dl.color
                }
            }, room=room)

        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/deadlines/import/<int:deadline_id>', methods=['POST'])
@csrf.exempt
@login_required
def import_shared_deadline(deadline_id):
    """افزودن ددلاین اشتراک‌گذاری‌شده توسط دیگران به ددلاین‌های خودم"""
    try:
        source = Deadline.query.get_or_404(deadline_id)
        user_id = session['current_user_id']
        if source.user_id == user_id:
            return jsonify({'error': 'این ددلاین از شماست'}), 400
        # جلوگیری از تکرار
        exists = Deadline.query.filter_by(
            user_id=user_id,
            title=source.title,
            due_date=source.due_date
        ).first()
        if exists:
            return jsonify({'error': 'این ددلاین قبلاً اضافه شده', 'id': exists.id})
        new_dl = Deadline(
            user_id=user_id,
            title=source.title,
            description=source.description,
            deadline_type=source.deadline_type,
            due_date=source.due_date,
            color=source.color
        )
        db.session.add(new_dl)
        db.session.commit()
        return jsonify({'status': 'success', 'id': new_dl.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# ==========================================
# Routes — Study Resources
# ==========================================

@app.route('/resources')
@login_required
def resources_page():
    return render_template('resources.html')


@app.route('/api/resources', methods=['GET'])
@login_required
def get_resources():
    try:
        user_id = session['current_user_id']
        q = request.args.get('q', '').strip()
        resource_type = request.args.get('type', '').strip()
        course = request.args.get('course', '').strip()
        sort = request.args.get('sort', 'newest')

        query = StudyResource.query.filter_by(is_deleted=False)
        if q:
            query = query.filter(
                or_(
                    StudyResource.title.ilike(f'%{q}%'),
                    StudyResource.course_name.ilike(f'%{q}%')
                )
            )
        if resource_type:
            query = query.filter_by(resource_type=resource_type)
        if course:
            query = query.filter(StudyResource.course_name.ilike(f'%{course}%'))

        if sort == 'popular':
            query = query.order_by(StudyResource.download_count.desc())
        elif sort == 'name':
            query = query.order_by(StudyResource.title)
        else:
            query = query.order_by(StudyResource.upload_date.desc())

        resources = query.all()
        liked_ids = {rl.resource_id for rl in
                     ResourceLike.query.filter_by(user_id=user_id).all()}

        result = []
        for r in resources:
            try:
                jd = jdatetime.date.fromgregorian(date=r.upload_date.date())
                upload_j = jd.strftime('%Y/%m/%d')
            except Exception:
                upload_j = str(r.upload_date)
            result.append({
                'id': r.id,
                'title': r.title,
                'course_name': r.course_name,
                'resource_type': r.resource_type,
                'file_format': r.file_format,
                'file_size': r.file_size,
                'file_size_str': _format_size(r.file_size),
                'upload_date_j': upload_j,
                'download_count': r.download_count,
                'like_count': r.likes.count(),
                'is_liked': r.id in liked_ids,
                'uploader_name': r.uploader.full_name if r.uploader else '?',
                'uploader_student_id': r.uploader.student_id if r.uploader else '',
                'can_delete': (r.uploader_id == user_id or session.get('is_admin'))
            })
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def _format_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f} MB"


@app.route('/api/resources', methods=['POST'])
@login_required
def upload_resource():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'فایلی ارسال نشد'}), 400
        file = request.files['file']
        title = request.form.get('title', '').strip()
        course_name = request.form.get('course_name', '').strip()
        resource_type = request.form.get('resource_type', '').strip()

        if not title or not course_name or not resource_type:
            return jsonify({'error': 'تمام فیلدها الزامی هستند'}), 400
        if not file or not file.filename or not allowed_resource_file(file.filename):
            return jsonify({'error': 'نوع فایل مجاز نیست (pdf, docx, pptx, zip)'}), 400

        file_format = get_file_format(file.filename)
        user_id = session['current_user_id']
        filename = secure_filename(
            f"{user_id}_{now_tehran().strftime('%Y%m%d%H%M%S')}_{file.filename}"
        )
        filepath = os.path.join(app.config['RESOURCE_UPLOAD_FOLDER'], filename)
        file.save(filepath)
        file_size = os.path.getsize(filepath)

        resource = StudyResource(
            uploader_id=user_id,
            title=title,
            course_name=course_name,
            resource_type=resource_type,
            file_path=f'static/uploads/resources/{filename}',
            file_size=file_size,
            file_format=file_format
        )
        db.session.add(resource)
        db.session.commit()
        return jsonify({'status': 'success', 'id': resource.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/resources/<int:resource_id>/like', methods=['POST'])
@csrf.exempt
@login_required
def toggle_resource_like(resource_id):
    try:
        user_id = session['current_user_id']
        existing = ResourceLike.query.filter_by(
            resource_id=resource_id, user_id=user_id
        ).first()
        if existing:
            db.session.delete(existing)
            action = 'unliked'
        else:
            db.session.add(ResourceLike(resource_id=resource_id, user_id=user_id))
            action = 'liked'
        db.session.commit()
        resource = StudyResource.query.get(resource_id)
        like_count = resource.likes.count() if resource else 0
        return jsonify({'status': 'success', 'action': action, 'like_count': like_count})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/resources/<int:resource_id>/download')
@login_required
def download_resource(resource_id):
    try:
        resource = StudyResource.query.get_or_404(resource_id)
        resource.download_count += 1
        db.session.commit()
        # مسیر فایل
        filename = resource.file_path.split('/')[-1]
        return send_from_directory(
            app.config['RESOURCE_UPLOAD_FOLDER'],
            filename,
            as_attachment=True,
            download_name=f"{resource.title}.{resource.file_format}"
        )
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/resources/<int:resource_id>', methods=['DELETE'])
@csrf.exempt
@login_required
def delete_resource(resource_id):
    try:
        user_id = session['current_user_id']
        resource = StudyResource.query.get_or_404(resource_id)
        if resource.uploader_id != user_id and not session.get('is_admin'):
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        resource.is_deleted = True
        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/resources/courses')
@login_required
def get_resource_courses():
    """لیست نام درس‌های موجود در منابع"""
    try:
        courses = db.session.query(StudyResource.course_name).filter_by(
            is_deleted=False
        ).distinct().order_by(StudyResource.course_name).all()
        return jsonify([c[0] for c in courses])
    except Exception as e:
        return jsonify([])


# ==========================================
# Routes — Notifications
# ==========================================

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


@app.route('/api/notifications/mark_all_read', methods=['POST'])
@csrf.exempt
@login_required
def mark_all_notifications_read():
    try:
        Notification.query.filter_by(
            user_id=session['current_user_id'], is_read=False
        ).update({'is_read': True})
        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# ==========================================
# Socket.IO Events
# ==========================================

@socketio.on('connect')
def handle_connect():
    uid = session.get('current_user_id')
    if uid:
        StateManager.set_online(uid)
        join_room(f"user_{uid}")
        # به‌روزرسانی delivered_at برای پیام‌های دریافتی و دیده‌نشده
        try:
            with app.app_context():
                updated = Message.query.filter(
                    Message.receiver_id == uid,
                    Message.delivered_at.is_(None)
                ).all()
                now = now_tehran()
                for m in updated:
                    m.delivered_at = now
                db.session.commit()
                # اطلاع به فرستندگان
                for m in updated:
                    room = f"chat-{min(m.sender_id, m.receiver_id)}-{max(m.sender_id, m.receiver_id)}"
                    socketio.emit('message_delivered', {
                        'message_id': m.id
                    }, room=room)
        except Exception:
            pass
        # به‌روزرسانی last_seen
        try:
            with app.app_context():
                user = db.session.get(User, uid)
                if user:
                    user.last_seen = now_tehran()
                    db.session.commit()
        except Exception:
            pass


@socketio.on('disconnect')
def handle_disconnect():
    uid = session.get('current_user_id')
    if uid:
        StateManager.set_offline(uid)
        try:
            with app.app_context():
                user = db.session.get(User, uid)
                if user:
                    user.last_seen = now_tehran()
                    db.session.commit()
        except Exception:
            pass


@socketio.on('join_chat')
def handle_join_chat(data):
    uid = session.get('current_user_id')
    if uid and data.get('other_user_id'):
        oid = int(data['other_user_id'])
        join_room(f"chat-{min(uid, oid)}-{max(uid, oid)}")


@socketio.on('send_message')
def handle_send_message(data):
    try:
        uid = session.get('current_user_id')
        if not uid:
            emit('error', {'message': 'ابتدا وارد شوید'})
            return
        if not data.get('other_user_id') or (not data.get('content') and not data.get('file_path')):
            emit('error', {'message': 'اطلاعات ناقص است'})
            return

        oid = int(data['other_user_id'])
        # بررسی بلاک
        block = UserBlock.query.filter(
            or_(
                and_(UserBlock.blocker_id == uid, UserBlock.blocked_id == oid),
                and_(UserBlock.blocker_id == oid, UserBlock.blocked_id == uid)
            )
        ).first()
        if block:
            emit('error', {'message': 'ارسال پیام ممکن نیست'})
            return

        content = data.get('content', '')
        file_path = data.get('file_path')
        reply_to_id = data.get('reply_to_id')

        msg = ChatService.save_message(
            sender_id=uid,
            receiver_id=oid,
            content=content,
            file_path=file_path,
            reply_to_id=reply_to_id
        )

        reply_data = None
        if reply_to_id:
            reply_msg = db.session.get(Message, reply_to_id)
            if reply_msg:
                sender_u = db.session.get(User, reply_msg.sender_id)
                reply_data = {
                    'id': reply_msg.id,
                    'content': reply_msg.content,
                    'sender_name': sender_u.full_name if sender_u else '?'
                }

        sender = db.session.get(User, uid)
        room = f"chat-{min(uid, oid)}-{max(uid, oid)}"
        emit('new_message', {
            'message_id': msg.id,
            'sender_name': sender.full_name if sender else '',
            'sender_student_id': sender.student_id if sender else '',
            'sender_pic': sender.profile_pic if sender else 'default.jpg',
            'content': content,
            'timestamp': fmt_time(msg.timestamp),
            'sender_id': uid,
            'file_path': file_path,
            'reply_to': reply_data,
            'status': 'delivered' if msg.delivered_at else 'sent'
        }, room=room)
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"handle_send_message error: {e}")
        emit('error', {'message': 'خطا در ارسال پیام'})


@socketio.on('join_group')
def handle_join_group():
    uid = session.get('current_user_id')
    if uid:
        join_room('public_group')
        # ثبت عضویت در صورت عدم وجود
        try:
            _get_or_create_group_member(uid)
            db.session.commit()
        except Exception:
            db.session.rollback()


@socketio.on('send_group_message')
def handle_group_message(data):
    try:
        uid = session.get('current_user_id')
        if not uid:
            emit('error', {'message': 'ابتدا وارد شوید'})
            return

        # بررسی وضعیت اعضا و تنظیمات گروه
        member = GroupMember.query.filter_by(user_id=uid).first()
        user = db.session.get(User, uid)

        if member and member.is_banned:
            emit('error', {'message': 'شما از گروه محروم شده‌اید'})
            return
        if member and member.is_muted:
            emit('error', {'message': 'ارسال پیام برای شما محدود شده'})
            return

        setting = GroupSetting.query.first()
        if setting and setting.is_readonly and not is_group_admin(uid):
            emit('error', {'message': 'گروه در حالت فقط خواندنی است'})
            return

        content = data.get('content', '').strip()
        file_path = data.get('file_path')
        reply_to_id = data.get('reply_to_id')

        if not content and not file_path:
            return

        now = now_tehran()
        msg = GroupMessage(
            sender_id=uid,
            content=content,
            file_path=file_path,
            timestamp=now,
            reply_to_id=reply_to_id
        )
        db.session.add(msg)

        # نوتیفیکیشن برای mention‌ها
        if content:
            send_mention_notifications(content, uid, 'group')

        db.session.commit()

        reply_data = None
        if reply_to_id:
            reply_msg = db.session.get(GroupMessage, reply_to_id)
            if reply_msg:
                r_sender = db.session.get(User, reply_msg.sender_id)
                reply_data = {
                    'id': reply_msg.id,
                    'content': reply_msg.content if not reply_msg.is_deleted else '[پیام حذف شده]',
                    'sender_name': r_sender.full_name if r_sender else '?'
                }

        emit('new_group_message', {
            'id': msg.id,
            'sender_id': uid,
            'sender_name': user.full_name if user else '',
            'sender_student_id': user.student_id if user else '',
            'sender_pic': user.profile_pic if user else 'default.jpg',
            'content': content,
            'file_path': file_path,
            'timestamp': fmt_time(now),
            'reply_to': reply_data
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
        uid = session.get('current_user_id')
        if not session.get('is_admin'):
            emit('error', {'message': 'دسترسی غیرمجاز'})
            return
        content = data.get('content', '').strip()
        file_path = data.get('file_path')
        if not content and not file_path:
            return
        now = now_tehran()
        msg = ChannelMessage(
            sender_id=uid,
            content=content,
            file_path=file_path,
            timestamp=now
        )
        db.session.add(msg)
        db.session.commit()
        emit('new_channel_message', {
            'id': msg.id,
            'sender_name': 'مدیریت',
            'content': content,
            'file_path': file_path,
            'timestamp': fmt_time(now)
        }, room='channel')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"handle_channel_message error: {e}")
        emit('error', {'message': 'خطا در ارسال اطلاعیه'})


# ==========================================
# Application Startup
# ==========================================
with app.app_context():
    db.create_all()
    create_initial_data()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=False)