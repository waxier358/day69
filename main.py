from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor, CKEditorField
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# #CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# login part
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
# #CONFIGURE TABLES


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="parent_post")


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)

    comment_author = relationship("User", back_populates="comments")
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    parent_post = relationship("BlogPost", back_populates="comments")
    parent_post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))


db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def get_all_posts():
    user_is_logged_in = False
    if current_user.is_authenticated:
        user_is_logged_in = True
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, user_is_logged_in=user_is_logged_in, id=current_user)


@app.route('/register', methods=['POST', 'GET'])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        new_email = request.form.get('email')
        is_mail_in_database = User.query.filter_by(email=new_email).first()
        if is_mail_in_database:
            flash('Email already in the database.')
            return redirect(url_for("login"))
        else:
            new_user = User(
                email=request.form.get('email'),
                name=request.form.get('name'),
                password=generate_password_hash(request.form.get('password'), method='pbkdf2:sha256', salt_length=8)
            )
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for("login"))
    return render_template("register.html", form=register_form)


@app.route('/login', methods=['POST', 'GET'])
def login():
    login_form = LoginForm()
    user_is_logged_in = False
    if current_user.is_authenticated:
        user_is_logged_in = True
    if login_form.validate_on_submit():
        new_email = request.form.get('email')
        user = User.query.filter_by(email=new_email).first()
        if not user:
            flash('Email not in the database.')
            return redirect(url_for("login"))
        else:
            if check_password_hash(user.password, request.form.get('password')):
                login_user(user)
                return redirect(url_for("get_all_posts"))
            else:
                flash('Incorrect password.')
                return redirect(url_for("login"))
    return render_template("login.html", form=login_form, user_is_logged_in=user_is_logged_in)


@app.route('/logout', methods=['POST', 'GET'])
def logout():
    logout_user()
    user_is_logged_in = False
    if current_user.is_authenticated:
        user_is_logged_in = True
    return redirect(url_for('get_all_posts', user_is_logged_in=user_is_logged_in))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    commentform = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    comments = requested_post.comments
    gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False,
                        use_ssl=False, base_url=None)
    user_is_logged_in = False
    if current_user.is_authenticated:
        user_is_logged_in = True
    if commentform.validate_on_submit():
        if user_is_logged_in:
            new_comment = Comment(
                text=request.form.get('comment'),
                comment_author=current_user,
                parent_post=requested_post,
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("show_post", post_id=post_id))
        elif not current_user.is_authenticated:
            flash('You can save comment only if you are logged in!')
        return redirect(url_for("login"))
    return render_template("post.html", post=requested_post, user_is_logged_in=user_is_logged_in, id=current_user,
                           commentform=commentform, comments=comments, gravatar=gravatar)


@app.route("/about")
def about():
    user_is_logged_in = False
    if current_user.is_authenticated:
        user_is_logged_in = True
    return render_template("about.html", user_is_logged_in=user_is_logged_in)


@app.route("/contact")
def contact():
    user_is_logged_in = False
    if current_user.is_authenticated:
        user_is_logged_in = True
    return render_template("contact.html", user_is_logged_in=user_is_logged_in)


@app.route("/new-post", methods=['POST', 'GET'])
@admin_only
def add_new_post():
    user_is_logged_in = False
    if current_user.is_authenticated:
        user_is_logged_in = True
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, user_is_logged_in=user_is_logged_in)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    user_is_logged_in = False
    if current_user.is_authenticated:
        user_is_logged_in = True
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, user_is_logged_in=user_is_logged_in)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)


