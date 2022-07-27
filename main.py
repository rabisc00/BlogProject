from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Text, ForeignKey, create_engine, update
from sqlalchemy.orm import relationship, Session
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from functools import wraps
from flask_gravatar import Gravatar
from dotenv import load_dotenv
from os import getenv

load_dotenv("C:\Python\EnvironmentVariables\.env")

# Flask Setup
app = Flask(__name__)
app.config['SECRET_KEY'] = getenv('FLASK_SECRET_KEY')

# Libraries setup
ckeditor = CKEditor(app)
login_manager = LoginManager()

login_manager.init_app(app)
Bootstrap(app)

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False,
                    base_url=None)

# Database Setup
app.config['SQLALCHEMY_DATABASE_URI'] = getenv('DATABASE_URL', 'sqlite:///blog.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

engine = create_engine('sqlite:///blog.db?check_same_thread=False')
session = Session(engine)

db = SQLAlchemy(app)


class User(db.Model, UserMixin):
    __tablename__ = "user"

    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    password = Column(String(100), nullable=False)


# Creating tables
class BlogPost(db.Model):
    __tablename__ = 'blog_posts'

    author_id = Column(Integer, ForeignKey('user.id'))
    author = relationship("User", back_populates="posts")

    comments = relationship("Comment", back_populates="post")

    id = Column(Integer, primary_key=True)
    title = Column(String(250), unique=True, nullable=False)
    subtitle = Column(String(250), nullable=False)
    date = Column(String(250), nullable=False)
    body = Column(Text, nullable=False)
    img_url = Column(String(250), nullable=False)


class Comment(db.Model):
    __tablename__ = 'comments'

    author_id = Column(Integer, ForeignKey('user.id'))
    author = relationship("User", back_populates="comments")

    post_id = Column(Integer, ForeignKey('blog_posts.id'))
    post = relationship("BlogPost", back_populates="comments")

    id = Column(Integer, primary_key=True)
    text = Column(Text, nullable=False)


db.create_all()

for user in User.query.all():
    gravatar.__call__(user.email)


@login_manager.user_loader
def load_user(user_id: str):
    return session.query(User).filter_by(id=user_id).first()


admin = User.query.first()


def admin_only(function):
    @wraps(function)
    def admin_wrapper(**kw):
        if current_user != admin:
            return abort(403)
        else:
            return function(**kw)
    return admin_wrapper


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()

    return render_template("index.html", all_posts=posts, admin=admin)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method="pbkdf2:sha256", salt_length=10)
        user_email = form.email.data

        if session.query(User).filter_by(email=user_email).first():
            flash("Email already registered. Try logging in instead.")
            return redirect(url_for('login'))
        else:
            new_user = User(name=form.name.data, email=user_email, password=hashed_password)  # Type: ignore
            session.add(new_user)
            session.commit()

            return redirect(url_for('login'))
    else:
        return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        logging_user: User = session.query(User).filter_by(email=form.email.data).first()
        if not logging_user:
            flash("This email doesn't exist. Try checking if you typed correctly or register a new user.")
        else:
            if check_password_hash(logging_user.password, form.password.data):
                login_user(logging_user)
                return redirect(url_for('get_all_posts'))
            else:
                flash("Incorrect password. Try again.")

    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()

    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(text=form.body.data, author_id=current_user.id, post_id=post_id)
            session.add(new_comment)
            session.commit()
        else:
            flash('You need to login before leaving any comments.')
            return redirect(url_for('login'))

    return render_template("post.html", post=requested_post, admin=admin, form=form, comments=Comment.query.all())


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()

        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/post/<int:post_id>/edit-post", methods=['GET', 'POST'])
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )

    if edit_form.validate_on_submit():
        engine.execute(update(BlogPost).values({
            "title": edit_form.title.data,
            "subtitle": edit_form.subtitle.data,
            "img_url": edit_form.img_url.data,
            "body": edit_form.body.data,
        }).where(BlogPost.id == post_id))

        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/post/<int:post_id>/delete", methods=['GET', 'POST'])
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
