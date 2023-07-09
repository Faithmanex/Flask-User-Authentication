from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_migrate import Migrate


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.secret_key = 'your_secret_key'

db = SQLAlchemy(app)
# Initialize the Flask-Migrate extension
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_blocked = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        """Set the password for the user by generating a hash"""
        self.password = generate_password_hash(password)

    def check_password(self, password):
        """Check if the provided password matches the user's hashed password"""
        return check_password_hash(self.password, password)

    def __repr__(self):
        """Return a string representation of the User object"""
        return f"User('{self.username}', '{self.is_admin}')"

@login_manager.user_loader
def load_user(user_id):
    """Load the user object from the database based on the user_id"""
    return User.query.get(int(user_id))


# Routes
@app.route('/')
def home():
    """Render the home page"""
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle the login functionality"""
    if current_user.is_authenticated:
        return redirect('/admin' if current_user.is_admin else '/user')

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect('/admin' if user.is_admin else '/user')
        else:
            return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle the registration functionality"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        return redirect('/login')

    return render_template('register.html')


@app.route('/reset_password', methods=['GET', 'POST'])
def reset():
    """Render the reset password page"""
    return render_template('reset_password.html')

@app.route('/admin')
@login_required
def admin_dashboard():
    """Render the admin dashboard"""
    if current_user.is_admin:
        users = User.query.all()
        return render_template('admin_dashboard.html', users=users)

    return redirect('/user')

@app.route('/admin/users')
@login_required
def admin_users():
    """Render the admin users page"""
    if current_user.is_admin:
        users = User.query.all()
        return render_template('admin_users.html', users=users)
    else:
        return redirect('/admin')

@app.route('/user')
@login_required
def user_dashboard():
    """Render the user dashboard"""
    return render_template('user_dashboard.html')

# @app.route('/register')
# @login_required
# def register_dashboard():
#     """Render the user dashboard"""
#     return render_template('user_dashboard.html')

@app.route('/logout')
@login_required
def logout():
    """Handle the logout functionality"""
    logout_user()
    return redirect('/login')

@app.route('/admin/block_user/<int:user_id>', methods=['POST'])
@login_required
def block_user(user_id):
    """Block a user by setting is_blocked to True and modifying the password"""
    if current_user.is_admin:
        user = User.query.get(user_id)
        if user:
            user.is_blocked = True
            user.password = f'{user.password}_blocked'
            db.session.commit()
    return redirect('/admin/users')

@app.route('/admin/unblock_user/<int:user_id>', methods=['POST'])
@login_required
def unblock_user(user_id):
    """Unblock a user by setting is_blocked to False and removing the "_blocked" suffix from the password"""
    if current_user.is_admin:
        user = User.query.get(user_id)
        if user:
            user.is_blocked = False
            user.password = user.password.replace('_blocked', '')
            db.session.commit()
    return redirect('/admin/users')

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    """Delete a user by removing them from the database"""
    if current_user.is_admin:
        user = User.query.get(user_id)
        if user:
            db.session.delete(user)
            db.session.commit()
    return redirect('/admin/users')

def create_tables():
    """Create database tables"""
    with app.app_context():
        db.create_all()

if __name__ == '__main__':
    create_tables()
    app.run(debug=True)
