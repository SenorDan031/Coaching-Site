from flask import Flask, flash, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///UserInfo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = "supersecretkey"  # required for sessions


db = SQLAlchemy(app)

class User(db.Model) :
    User_id = db.Column(db.Integer, primary_key=True)
    User_name = db.Column(db.String(35), unique=True, nullable=False)
    User_email = db.Column(db.String(40), unique=True, nullable=False)
    User_pass = db.Column(db.String(200),  nullable=False)
    User_role = db.Column(db.String(9), nullable=False, default='student')
    
@app.route('/') 
def WelcomePage() :
    return render_template('Welcome.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    errors = {}
    values = {}

    if request.method == 'POST':
        Uname  = request.form.get('User_name', '').strip()
        Uemail = request.form.get('User_email', '').strip()
        Upass  = request.form.get('User_pass', '').strip()
        Urole  = request.form.get('User_role', '').strip()

        values = {'User_name': Uname, 'User_email': Uemail}

        # validations
        if len(Uname) < 3:
            errors['User_name'] = "Username must be at least 3 characters"

        if '@' not in Uemail or '.' not in Uemail:
            errors['User_email'] = "Enter a valid email address"

        if len(Upass) < 6:
            errors['User_pass'] = "Password must be at least 6 characters"
            
        if Urole not in ['student', 'teacher', 'admin']:
            errors['User_role'] = "Please select a valid role"

        if errors:
            return render_template('signup.html', errors=errors, values=values)
        
        

        hide = generate_password_hash(Upass)

        try:
            user = User(User_name=Uname, User_email=Uemail, User_pass=hide, User_role=Urole)
            db.session.add(user)
            db.session.commit()

            flash("Account created successfully 🎉", "success")
            return redirect('/select-role')

        except IntegrityError:
            db.session.rollback()
            errors['User_email'] = "Email or username already exists"
            return render_template('signup.html', errors=errors, values=values)

    return render_template('signup.html', errors=errors, values=values)

@app.route('/select-role')
def select_role():
    return render_template('User_Role.html')

@app.route('/select-role/<User_role>')
def role_redirect(User_role):

    return redirect(url_for('login', User_role=User_role))


@app.route('/login', methods=['GET', 'POST'])    
def login():
    
    

    # get selected role from URL
    selected_role = request.args.get('User_role')
    
    if not selected_role:
        return redirect('/select-role')

    if request.method == 'POST':

        email = request.form['User_email']
        password = request.form['User_pass']

        user = User.query.filter_by(User_email=email).first()

        # CHECK USER + PASSWORD
        if user and check_password_hash(user.User_pass, password):

            # CHECK ROLE MATCH

           
            # SAVE SESSION
            session['user_id'] = user.User_id
            session['User_role'] = user.User_role

            # ROLE BASED REDIRECT
            if user.User_role == 'student':
                return redirect('/StudentDash')

            elif user.User_role == 'teacher':
                return redirect('/TeacherDash')

            elif user.User_role == 'admin':
                return redirect('/AdminDash')

        else:

            flash("Invalid email or password", "danger")

            return redirect(url_for('login', User_role=selected_role))

    return render_template(
        'login.html',
        User_role=selected_role
    )

    return render_template('login.html')

@app.route('/StudentDash')
def StudentDash():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])   # 👈 get actual user
        return render_template('StudentDash.html', user=user)
    
    
    else :
        return redirect('/login')

@app.route('/TeacherDash')
def StaffDash():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])   # 👈 get actual user
        return render_template('TeacherDash.html', user=user)
    
    else :
        return redirect('/login')

@app.route('/AdminDash')
def AdminDash():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])   # 👈 get actual user
        return render_template('AdminDash.html', user=user)
    
    else :
        return redirect('/login')
    
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect('/login')
       

if __name__=='__main__' :
    app.run(debug=True, use_reloader=True)