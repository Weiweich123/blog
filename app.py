import os
import re
import requests
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from flask_wtf import FlaskForm  # 引入 FlaskForm
from wtforms import StringField, PasswordField, validators
from flask_wtf.csrf import CSRFProtect
from datetime import datetime
from wtforms import TextAreaField
from markdown import markdown

# 配置類別
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'supersecretkey12345'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///blog.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

# 初始化 Flask 應用程式
app = Flask(__name__)
app.config.from_object(Config)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key')

# 啟用 CSRF 保護
csrf = CSRFProtect(app)

# 初始化 SQLAlchemy
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# 初始化 LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# 定義資料庫模型
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    articles = db.relationship('Article', backref='author', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'

class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<Article {self.title}>"

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'author': self.author.username if self.author else "Unknown",
            'content': self.content,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M') if self.created_at else "N/A"
        }
    
# 文章表單類別
class ArticleForm(FlaskForm):
    title = StringField('標題', [validators.DataRequired()])
    content = TextAreaField('內容', [validators.DataRequired()])
    author = StringField('作者', default='', render_kw={'readonly': True})

# 使用者登入管理
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 註冊表單類別
class RegistrationForm(FlaskForm):
    username = StringField('用戶名', [validators.Length(min=4, max=100), validators.DataRequired()])
    password = PasswordField('密碼', [validators.DataRequired(), validators.Length(min=6)])
    confirm_password = PasswordField('確認密碼', [validators.DataRequired(), validators.EqualTo('password', message='密碼必須相同')])

# 登入表單類別
class LoginForm(FlaskForm):
    username = StringField('用戶名', [validators.DataRequired()])
    password = PasswordField('密碼', [validators.DataRequired()])

# 註冊頁面
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password = form.password.data
        hashed_password = generate_password_hash(password)

        # 檢查用戶名是否已存在
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("用戶名已存在，請選擇其他用戶名。", "danger")
            return redirect(url_for('register'))

        new_user = User(username=username, password=hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash("註冊成功！現在可以登入了。", "success")
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f"註冊失敗！請稍後再試。錯誤: {str(e)}", "danger")

    return render_template('register.html', form=form)

# 登入頁面
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password = form.password.data

        if not username or not password:
            flash("請填寫所有欄位。", "danger")
            return redirect(url_for('login'))

        # 查詢用戶
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)  # 使用 Flask-Login 進行登入
            flash("登入成功！歡迎回來。", "success")
            return redirect(url_for('index'))
        else:
            flash("帳號或密碼錯誤，請再試一次。", "danger")
            return render_template('login.html', form=form)  # 渲染時傳遞表單和錯誤訊息

    return render_template('login.html', form=form)

# 登出
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("已成功登出！", "info")
    return redirect(url_for('login'))

# 首頁路由
@app.route('/')
def index():
    articles = Article.query.all()
    return render_template('index.html', articles=articles)

@app.route('/article/<int:id>', methods=['GET', 'POST'])
def article(id):
    article = Article.query.get_or_404(id)
    form = ArticleForm()  # 初始化表單

    if request.method == 'POST' and form.validate_on_submit():
        # 在這裡處理表單提交的邏輯
        pass

    return render_template('article.html', article=article, form=form)

@app.route('/new_article', methods=['GET', 'POST'])
@login_required
def new_article():
    form = ArticleForm()

    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data

        # 1. 轉換換行符為 <br>，僅在純文字狀態下處理
        content_with_br = content.replace("\n", "<br>")

        # 2. 使用正則表達式將網址轉換為超連結
        url_pattern = re.compile(r'https?://[^\s]+')
        content_with_links = re.sub(
            url_pattern, 
            lambda match: f'<a href="{match.group(0)}" target="_blank">{match.group(0)}</a>', 
            content_with_br
        )

        # 3. 直接保存轉換後的 HTML（如需 Markdown，這一步可用於渲染）
        content_html = markdown(content_with_links)

        # 4. 創建新文章並保存
        article = Article(title=title, content=content_html, author_id=current_user.id)

        try:
            db.session.add(article)
            db.session.commit()
            flash('文章已成功創建!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'創建文章失敗: {str(e)}', 'danger')

    return render_template('new_article.html', form=form)


@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_article(id):
    article = Article.query.get_or_404(id)

    # 確保當前用戶是文章的創建者
    if article.author_id != current_user.id:
        flash("您無權編輯此文章！", "danger")
        return redirect(url_for('index'))

    form = ArticleForm(obj=article)  # 使用表單來處理資料

    if form.validate_on_submit():
        article.title = form.title.data

        # 將 Markdown 內容轉換為 HTML
        raw_content = form.content.data
        article.content = markdown(raw_content)

        try:
            db.session.commit()
            flash('文章已成功更新!', 'success')
            return redirect(url_for('article', id=article.id))
        except Exception as e:
            db.session.rollback()
            flash(f'更新文章失敗: {str(e)}', 'danger')

    # 預填表單時，將 HTML 轉換回原始 Markdown（如果需要）
    form.content.data = article.content
    return render_template('edit.html', form=form, article=article)

# 刪除文章
@app.route('/delete_article/<int:id>', methods=['POST'])
@login_required
def delete_article(id):
    article = Article.query.get_or_404(id)

    # 確保當前用戶是文章的創建者
    if article.author_id != current_user.id:
        flash("您無權刪除此文章！", "danger")
        return redirect(url_for('index'))

    try:
        db.session.delete(article)
        db.session.commit()
        flash('文章已成功刪除!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'刪除文章失敗: {str(e)}', 'danger')

    return redirect(url_for('index'))

# 文章 API 路由
@app.route('/api/articles', methods=['POST'])
@login_required
def create_article_api():
    data = request.get_json()
    title = data.get('title')
    content = data.get('content')

    if not title or not content:
        return jsonify({'message': '標題和內容為必填欄位！'}), 400

    new_article = Article(title=title, content=content, author_id=current_user.id)

    try:
        db.session.add(new_article)
        db.session.commit()
        return jsonify(new_article.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'新增文章失敗！錯誤: {str(e)}'}), 500

# API 路由：讀取所有文章
@app.route('/api/articles', methods=['GET'])
def get_articles_api():
    articles = Article.query.all()
    return jsonify([article.to_dict() for article in articles]), 200

# API 路由：讀取單篇文章
@app.route('/api/articles/<int:id>', methods=['GET'])
def get_article_api(id):
    article = Article.query.get_or_404(id)
    return jsonify(article.to_dict()), 200

# API 路由：更新文章
@app.route('/api/articles/<int:id>', methods=['PUT'])
@login_required
def update_article_api(id):
    article = Article.query.get_or_404(id)

    if article.author_id != current_user.id:
        return jsonify({'message': '您無權更新此文章！'}), 403

    data = request.get_json()
    article.title = data.get('title', article.title)
    article.content = data.get('content', article.content)

    try:
        db.session.commit()
        return jsonify(article.to_dict()), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'更新文章失敗！錯誤: {str(e)}'}), 500

# API 路由：刪除文章
@app.route('/api/articles/<int:id>', methods=['DELETE'])
@login_required
def delete_article_api(id):
    article = Article.query.get_or_404(id)

    if article.author_id != current_user.id:
        return jsonify({'message': '您無權刪除此文章！'}), 403

    try:
        db.session.delete(article)
        db.session.commit()
        return jsonify({'message': '文章已成功刪除!'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'刪除文章失敗！錯誤: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True)
