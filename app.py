# app.py

import os
from flask import Flask, render_template, flash, redirect, url_for, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, date, timedelta
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from sqlalchemy import func, extract 

# --- 1. KONFİQURASİYA ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'Sizin_cox_gizli_ve_guclu_acariniz'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///solvit_birlestirilmis.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Faylların yüklənməsi üçün tənzimləmələr
UPLOAD_FOLDER = 'static/uploads/issues'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Maksimum 16MB

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' 
login_manager.login_message = 'Bu səhifəyə daxil olmaq üçün hesabınıza daxil olmalısınız.'
login_manager.login_message_category = 'warning'

# --- 2. İCAZƏ VERİLƏN İSTİFADƏÇİLƏR ---
AUTHORIZED_USERS = {
    "s312088@karabakh.edu.az": "Telebe",
    "s326638@karabakh.edu.az": "Telebe",
    "s315593@karabakh.edu.az": "Telebe",
    "s311383@karabakh.edu.az": "Telebe",
    "zahir.avazli@karabakh.edu.az": "Muellim",
    "s323672@karabakh.edu.az": "Telebe",
    "elnur.babayev@karabakh.edu.az": "Inzibati Heyyet",
}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- 3. MƏLUMAT BAZASI MODELLƏRİ ---

class User(UserMixin, db.Model): 
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(50), default='Telebe')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        
    def can_solve_issue(self):
        return self.role in ['Admin', 'Inzibati Heyyet', 'Muellim']

class Issue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Open') 
    priority = db.Column(db.String(20), default='2') 
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    is_public = db.Column(db.Boolean, default=True) 
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    author = db.relationship('User', foreign_keys=[user_id], backref='my_reports')
    assigned_user = db.relationship('User', foreign_keys=[assigned_to_id], backref='my_tasks')
    images = db.relationship('IssueImage', backref='issue', lazy=True, cascade="all, delete-orphan")
    
    # Şərhlər üçün əlaqə (DÜZƏLDİLDİ)
    comments = db.relationship('IssueComment', backref='related_issue', lazy='dynamic', cascade="all, delete-orphan")

class IssueImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_path = db.Column(db.String(255), nullable=False)
    issue_id = db.Column(db.Integer, db.ForeignKey('issue.id'), nullable=False)

class IssueComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    issue_id = db.Column(db.Integer, db.ForeignKey('issue.id'), nullable=False)
    
    # Backref adı "user_comments" olaraq dəyişdirildi (DÜZƏLDİLDİ)
    author = db.relationship('User', backref='user_comments')

# --- 4. FORMALAR ---

class RegistrationForm(FlaskForm):
    full_name = StringField('Tam Ad', validators=[DataRequired(), Length(min=3, max=100)])
    email = StringField('Korporativ Email', validators=[DataRequired(), Email()])
    password = PasswordField('Şifrə', validators=[DataRequired(), Length(min=6)])
    password_confirm = PasswordField('Şifrəni Təsdiqlə', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Qeydiyyatdan Keç')

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError('Bu email adresi artıq qeydiyyatdan keçib.')
        if email.data not in AUTHORIZED_USERS:
            raise ValidationError('Bu email adresi qeydiyyat üçün səlahiyyətli deyil.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Şifrə', validators=[DataRequired()])
    remember_me = BooleanField('Məni Xatırla')
    submit = SubmitField('Daxil Ol')

# --- 5. MARŞRUTLAR ---

@app.route('/',methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Giriş uğursuz oldu. Email və ya şifrə səhvdir.', 'danger')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user_role = AUTHORIZED_USERS.get(form.email.data, 'Telebe') 
        user = User(full_name=form.full_name.data, email=form.email.data, role=user_role)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Qeydiyyat tamamlandı!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    today = date.today()
    
    # 1. Giriş icazəsi olan müraciətləri filtr etmək üçün baza sorğusu (Base Query)
    # Şərt: (İctimai olanlar) VƏ YA (Müəllif mənəm) VƏ YA (Mənə təyin olunub/Tag edilib)
    visible_issues_query = Issue.query.filter(
        (Issue.is_public == True) | 
        (Issue.user_id == current_user.id) | 
        (Issue.assigned_to_id == current_user.id)
    )

    # Statistika (Yalnız istifadəçinin görməyə icazəsi olanlar üzərindən)
    total_open = visible_issues_query.filter(Issue.status != 'Closed').count()
    
    high_priority = visible_issues_query.filter(
        Issue.priority.in_(['3', '4']), 
        Issue.status != 'Closed'
    ).count()
    
    closed_today = visible_issues_query.filter(
        Issue.status == 'Closed', 
        func.date(Issue.timestamp) == today
    ).count()
    
    # Şəxsi tapşırıqlar (Tag olunduğum müraciətlər)
    assigned_to_me = Issue.query.filter_by(assigned_to_id=current_user.id).filter(Issue.status != 'Closed').count()

    # Cədvəl üçün son müraciətlər (Məxfilik nəzərə alınmaqla)
    recent_issues = visible_issues_query.order_by(Issue.timestamp.desc()).limit(7).all()

    # Qrafik üçün datalar
    labels = []
    new_issues_count = []
    closed_issues_count = []
    for i in range(6, -1, -1):
        d = today - timedelta(days=i)
        labels.append(d.strftime('%d %b'))
        # Qrafikdə də məxfilik qorunur
        new_issues_count.append(visible_issues_query.filter(func.date(Issue.timestamp) == d).count())
        closed_issues_count.append(visible_issues_query.filter(Issue.status == 'Closed', func.date(Issue.timestamp) == d).count())

    chart_data = {
        "labels": labels,
        "new_issues": new_issues_count,
        "closed_issues": closed_issues_count
    }

    aylar = {1: 'Yanvar', 2: 'Fevral', 3: 'Mart', 4: 'Aprel', 5: 'May', 6: 'İyun', 
             7: 'İyul', 8: 'Avqust', 9: 'Sentyabr', 10: 'Oktyabr', 11: 'Noyabr', 12: 'Dekabr'}
    formatted_date = f"{today.day} {aylar[today.month]} {today.year}"

    return render_template('dashboard.html', 
                            total_open=total_open, 
                            high_priority=high_priority,
                            closed_today=closed_today,
                            assigned_to_me=assigned_to_me,
                            recent_issues=recent_issues,
                            chart_data=chart_data,
                            user=current_user,
                            current_date=formatted_date)
@app.route('/issue/action/<int:issue_id>', methods=['POST'])
@login_required
def issue_action(issue_id):
    issue = Issue.query.get_or_404(issue_id)
    
    # Yalnız səlahiyyətli şəxslər (Admin, Müəllim, İnzibati heyət) cavab yaza bilər
    if not current_user.can_solve_issue():
        flash('Bu əməliyyat üçün icazəniz yoxdur.', 'danger')
        return redirect(url_for('issue_detail', issue_id=issue.id))

    if issue.status == 'Closed':
        flash('Bu müraciət artıq bağlanıb.', 'warning')
        return redirect(url_for('issue_detail', issue_id=issue.id))

    status = request.form.get('status')
    body = request.form.get('comment')

    if body:
        new_comment = IssueComment(
            body=body,
            user_id=current_user.id,
            issue_id=issue.id
        )
        issue.status = status
        db.session.add(new_comment)
        db.session.commit()
        flash('Məlumat uğurla yeniləndi.', 'success')

    return redirect(url_for('issue_detail', issue_id=issue.id))
@app.route('/new_issue', methods=['GET', 'POST'])
@login_required
def new_issue():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        priority = request.form.get('priority')
        is_public = request.form.get('is_public') == 'true'
        # Seçilən məsul şəxsin ID-si
        assigned_to_id = request.form.get('assigned_to_id')

        try:
            new_issue_obj = Issue(
                title=title, 
                description=description, 
                priority=priority, 
                is_public=is_public,
                user_id=current_user.id,
                assigned_to_id=assigned_to_id if assigned_to_id else None
            )
            db.session.add(new_issue_obj)
            db.session.flush() 

            # Şəkillərin yüklənməsi
            files = request.files.getlist('attachments')
            for file in files:
                if file and file.filename != '':
                    filename = secure_filename(f"{new_issue_obj.id}_{file.filename}")
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    img_entry = IssueImage(image_path=f"uploads/issues/{filename}", issue_id=new_issue_obj.id)
                    db.session.add(img_entry)

            db.session.commit()
            return jsonify({"message": "Uğurla yaradıldı", "id": new_issue_obj.id}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500

    # GET SORGUSU: Rolu 'Telebe' olmayan hamını çəkirik
    resolvers = User.query.filter(User.role != 'Telebe').all()
    return render_template('new_issue.html', resolvers=resolvers)
from sqlalchemy import or_ # Faylın ən başında bu importun olduğundan əmin olun

from sqlalchemy import or_

@app.route('/explore')
@login_required
def explore_issues():
    # Məntiq: 
    # 1. Ya hər kəsə açıqdır (is_public == True)
    # 2. Ya mən yaratmışam (user_id == current_user.id)
    # 3. Ya da mənə TAG edilib (assigned_to_id == current_user.id)
    issues = Issue.query.filter(
        or_(
            Issue.is_public == True,
            Issue.user_id == current_user.id,
            Issue.assigned_to_id == current_user.id
        )
    ).order_by(Issue.timestamp.desc()).all()
    
    return render_template('explore.html', issues=issues)
@app.route('/issue/<int:issue_id>')
@login_required
def issue_detail(issue_id):
    issue = Issue.query.get_or_404(issue_id)
    
    # Əgər private-dırsa və (mən müəllif deyiləm VƏ mənə tag edilməyib)
    if not issue.is_public:
        if current_user.id != issue.user_id and current_user.id != issue.assigned_to_id:
            flash('Bu məlumat məxfidir.', 'danger')
            return redirect(url_for('dashboard'))
            
    return render_template('issue_detail.html', issue=issue, user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        # Dəyişikliklərin tətbiqi üçün bazanı sıfırdan yaratmaq tövsiyə olunur
        db.create_all() 
    app.run(debug=True)