from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
# Use environment variable for secret key, with a default for development
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY') or 'dev-key-for-development-only'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///research.db'
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')

# Add allowed file extensions
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'xlsx', 'xls'}

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = None  # Remove the default login message

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# College and Department Data Structure
college_dept_data = {
    "College of Engineering": [
        "Civil Engineering", "Mechanical Engineering", "Water Resource and Irrigation Engineering",
        "Surveying Engineering", "Electrical and Computer Engineering", "Construction Technology and Management",
        "Engineering Drawing and Design (Summer)", "Architecture"
    ],
    "College of Computing": [
        "Computer Science", "Information System", "Information Science", "Information Technology"
    ],
    "College of Natural and Computational Science": [
        "Mathematics", "Statistics", "Physics", "Chemistry", "Biology", "Environmental Science", "Sport Science"
    ],
    "College of Agriculture & Natural Resource": [
        "Agricultural Economics", "Forestry", "Plant Science", "Biodiversity Conservation and Ecotourism",
        "Natural Resource Management", "Rural Development & Agricultural Extension", "Animal Science"
    ],
    "College of Medicine and Health Science": [
        "Medicine", "Pharmacy", "Medical laboratory", "Nursing (GRH and SHC)", "Midwifery (GRH and SHC)",
        "Public Health (GRH and SHC)"
    ],
    "College of Social Science and Humanities": [
        "Afan Oromo and Literature", "Amharic Language and Literature", "Civics and Ethical Education",
        "English Language and Literature", "Sociology", "Geography and Environmental Study",
        "History and Heritage Management", "Journalism and Communication", "GIS & Land Resource Management"
    ],
    "College of Business and Economics": [
        "Management", "Accounting and Finance", "Economics", "Marketing Management",
        "Hotel & Tourism Management", "Business Education"
    ],
    "College of Education and Behavioural Studies": [
        "Adult Education and Community Development", "Educational Planning and Management", "Psychology",
        "Early Childhood Education & Development"
    ],
    "School of Law": [
        "Law"
    ]
}

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    research_papers = db.relationship('ResearchPaper', backref='author', lazy=True)
    is_ban = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class ResearchPaper(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    abstract = db.Column(db.Text)
    file_path = db.Column(db.String(200))
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    submission_date = db.Column(db.Date, nullable=False)
    college = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(100), nullable=False)
    keywords = db.Column(db.String(200))
    status = db.Column(db.String(20), default='proposed', nullable=False)
    principal_investigator = db.Column(db.String(200), nullable=False)
    co_investigators = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    papers = ResearchPaper.query.order_by(ResearchPaper.upload_date.desc()).all()
    return render_template('index.html', papers=papers)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        if len(password)<8:
            flash("Password must be at least 8 characters long")
            return render_template('register.html')
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        # Log in the user after registration
        login_user(user)
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            if user.is_admin == True:
                return redirect(url_for('admin'))
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_paper():
    if request.method == 'POST':
        title = request.form.get('title')
        principal_investigator = request.form.get('principal_investigator')
        co_investigators = request.form.get('co_investigators')
        abstract = request.form.get('abstract')
        keywords = request.form.get('keywords')
        college = request.form.get('college')
        department = request.form.get('department')
        status = request.form.get('status')
        submission_date_str = request.form.get('submission_date')
        file = request.files.get('paper')

        # Pass submitted form data back to template in case of error
        form_data = request.form 

        # Basic validation
        if not all([title, principal_investigator, abstract, keywords, college, department, status, submission_date_str, file]):
             flash('Please fill in all required fields.', 'error')
             return render_template('upload.html', 
                                    colleges=college_dept_data.keys(), 
                                    college_dept_data=college_dept_data, 
                                    form_data=form_data)

        # File validation
        if file and file.filename:
            if not allowed_file(file.filename):
                flash('Invalid file type. Please upload a PDF or Excel file (.pdf, .xlsx, .xls).', 'error')
                return render_template('upload.html',
                                    colleges=college_dept_data.keys(),
                                    college_dept_data=college_dept_data,
                                    form_data=form_data)

        try:
            submission_date = datetime.strptime(submission_date_str, '%Y-%m-%d').date()
        except ValueError:
             flash('Invalid submission date format. Please use YYYY-MM-DD.', 'error')
             return render_template('upload.html', 
                                    colleges=college_dept_data.keys(), 
                                    college_dept_data=college_dept_data, 
                                    form_data=form_data)

        if file:
            filename = f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            try:
                file.save(file_path)
            except Exception as e:
                flash(f'Error saving file: {e}', 'error')
                return render_template('upload.html', 
                                       colleges=college_dept_data.keys(), 
                                       college_dept_data=college_dept_data, 
                                       form_data=form_data)

            paper = ResearchPaper(
                title=title,
                principal_investigator=principal_investigator,
                co_investigators=co_investigators,
                abstract=abstract,
                file_path=filename,
                college=college,
                department=department,
                keywords=keywords,
                status=status,
                submission_date=submission_date,
                user_id=current_user.id
            )
            db.session.add(paper)
            try:
                db.session.commit()
                flash('Paper uploaded successfully')
                return redirect(url_for('index'))
            except Exception as e:
                 db.session.rollback()
                 flash(f'Error saving paper to database: {e}', 'error')
                 if os.path.exists(file_path):
                     os.remove(file_path)
                 return render_template('upload.html', 
                                        colleges=college_dept_data.keys(), 
                                        college_dept_data=college_dept_data, 
                                        form_data=form_data)

        else:
            flash('No file selected.', 'error')
            return render_template('upload.html', 
                                   colleges=college_dept_data.keys(), 
                                   college_dept_data=college_dept_data, 
                                   form_data=form_data)
            
    # Pass college data to the template for the GET request
    return render_template('upload.html', 
                           colleges=college_dept_data.keys(), 
                           college_dept_data=college_dept_data)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    selected_college = request.args.get('college', '')
    selected_department = request.args.get('department', '')
    
    papers_query = ResearchPaper.query
    
    if query:
        papers_query = papers_query.filter(
            db.or_(
                ResearchPaper.title.ilike(f'%{query}%'),
                ResearchPaper.principal_investigator.ilike(f'%{query}%'),
                ResearchPaper.keywords.ilike(f'%{query}%')
            )
        )
    
    if selected_college:
        papers_query = papers_query.filter(ResearchPaper.college == selected_college)
    
    if selected_department:
        papers_query = papers_query.filter(ResearchPaper.department == selected_department)
    
    papers = papers_query.order_by(ResearchPaper.upload_date.desc()).all()
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        # For AJAX requests from the navigation search
        if request.args.get('from') == 'nav':
            return render_template('_nav_search_results.html', papers=papers, query=query)
        # For AJAX requests from the search page
        return render_template('_papers_list.html', papers=papers)
    
    # For full page requests
    return render_template('search.html', 
                         papers=papers,
                         query=query,
                         selected_college=selected_college,
                         selected_department=selected_department,
                         colleges=college_dept_data.keys(),
                         college_dept_data=college_dept_data)

# Add a route to view/download papers
@app.route('/paper/<int:paper_id>')
def view_paper(paper_id):
    paper = ResearchPaper.query.get_or_404(paper_id)
    
    # Check if file_path is a full path or just a filename
    if os.path.isabs(paper.file_path):
        # It's a full path, extract just the filename
        filename = os.path.basename(paper.file_path)
    else:
        # It's already just a filename
        filename = paper.file_path
    
    # Log for debugging
    print(f"Attempting to serve file: {filename} from {app.config['UPLOAD_FOLDER']}")
    
    # Directly serve the file from the uploads directory
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Add a route to serve files from uploads directory
@app.route('/uploads/<path:filename>')
def serve_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Add an admin route to manage users
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('index'))

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        action = request.form.get('action')

        user = User.query.get(user_id)
        if user:
            if action == 'ban':
                user.is_ban = True
            elif action == 'unban':
                user.is_ban = False
            db.session.commit()
            flash(f'User {user.username} has been updated.', 'success')
        else:
            flash('User not found.', 'error')

    
    users = User.query.all()
    papers = ResearchPaper.query.all()
    return render_template('admin.html', users =users, papers =papers )
@app.route('/paper/<int:paper_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_paper(paper_id):
    paper = ResearchPaper.query.get_or_404(paper_id)
    if not (current_user.is_admin or current_user.id == paper.user_id):
        flash('You do not have permission to edit this paper.', 'error')
        return redirect(url_for('index'))
    if request.method == 'POST':
        paper.title = request.form.get('title')
        paper.principal_investigator = request.form.get('principal_investigator')
        paper.co_investigators = request.form.get('co_investigators')
        paper.abstract = request.form.get('abstract')
        paper.keywords = request.form.get('keywords')
        paper.college = request.form.get('college')
        paper.department = request.form.get('department')
        paper.status = request.form.get('status')
        try:
            paper.submission_date = datetime.strptime(request.form.get('submission_date'), '%Y-%m-%d').date()
        except Exception:
            flash('Invalid submission date format.', 'error')
            return render_template('edit_paper.html', paper=paper, colleges=college_dept_data.keys(), college_dept_data=college_dept_data)
        db.session.commit()
        flash('Paper updated successfully.', 'success')
        return redirect(url_for('admin'))
    return render_template('edit_paper.html', paper=paper, colleges=college_dept_data.keys(), college_dept_data=college_dept_data)

@app.route('/paper/<int:paper_id>/delete', methods=['POST'])
@login_required
def delete_paper(paper_id):
    paper = ResearchPaper.query.get_or_404(paper_id)
    if not (current_user.is_admin or current_user.id == paper.user_id):
        flash('You do not have permission to delete this paper.', 'error')
        return redirect(url_for('index'))
    db.session.delete(paper)
    db.session.commit()
    flash('Paper deleted successfully.', 'success')
    return redirect(url_for('admin'))

if __name__ == '__main__':
    with app.app_context():
        # Check if is_admin column exists
        try:
            # Try to query using is_admin to test if column exists
            User.query.filter_by(is_admin=True).first()
            print("Database schema is up to date")
            
            # Update file paths for existing papers
            papers = ResearchPaper.query.all()
            updated = 0
            for paper in papers:
                if os.path.isabs(paper.file_path) or '/' in paper.file_path or '\\' in paper.file_path:
                    # Convert full path to just filename
                    paper.file_path = os.path.basename(paper.file_path)
                    updated += 1
            if updated > 0:
                db.session.commit()
                print(f"Updated {updated} paper file paths to use just filenames")
                
        except Exception as e:
            if "no such column: user.is_admin" in str(e):
                print("Recreating database with updated schema...")
                # Get all existing users first
                users_data = []
                try:
                    users = User.query.all()
                    for user in users:
                        users_data.append({
                            'username': user.username,
                            'email': user.email,
                            'password_hash': user.password_hash
                        })
                except Exception:
                    print("Could not retrieve existing users")
                
                # Drop all tables
                db.drop_all()
                
                # Create all tables with updated schema
                db.create_all()
                
                # Restore users if any were retrieved
                for user_data in users_data:
                    user = User(
                        username=user_data['username'],
                        email=user_data['email'],
                        password_hash=user_data['password_hash'],
                        is_admin=False
                    )
                    db.session.add(user)
                
                db.session.commit()
                print("Database has been updated!")
            else:
                print(f"Database error: {e}")
                
    app.run(debug=True)