"""Main Flask application"""
import os
from datetime import timedelta
from flask import Flask, render_template
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import extensions
from extensions import db, migrate, jwt, bcrypt, cors, init_extensions

# Import models (needed for migrations)
from models import Vulnerability, VulnerabilityHistory, User, JiraTicket, VulnerabilitySource

# Import blueprints
from api import auth_bp, vulnerabilities_bp, jira_bp, reports_bp, import_bp


def create_app():
    """Create and configure Flask application"""
    app = Flask(__name__)

    # Configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'dev-jwt-secret-key-change-in-production')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)

    # Database configuration
    data_dir = os.getenv('DATA_DIR', 'data')
    os.makedirs(data_dir, exist_ok=True)

    database_url = os.getenv('DATABASE_URL', f'sqlite:///{data_dir}/vulnerabilities.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # File upload configuration
    app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max upload
    app.config['UPLOAD_FOLDER'] = 'uploads'
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Initialize extensions
    init_extensions(app)

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(vulnerabilities_bp)
    app.register_blueprint(jira_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(import_bp)

    # Web routes
    @app.route('/')
    def index():
        """Serve main application page"""
        return render_template('index.html')

    @app.route('/login')
    def login_page():
        """Serve login page"""
        return render_template('login.html')

    @app.route('/dashboard')
    def dashboard():
        """Serve dashboard page"""
        return render_template('dashboard.html')

    @app.route('/vulnerabilities')
    def vulnerabilities_page():
        """Serve vulnerabilities list page"""
        return render_template('vulnerabilities.html')

    @app.route('/reports')
    def reports_page():
        """Serve reports page"""
        return render_template('reports.html')

    @app.route('/import')
    def import_page():
        """Serve import page"""
        return render_template('import.html')

    # Create tables and initial data
    with app.app_context():
        db.create_all()
        init_database()

    return app


def init_database():
    """Initialize database with default data"""
    # Create default admin user if none exists
    if User.query.count() == 0:
        admin_email = os.getenv('ADMIN_EMAIL', 'admin@example.com')
        admin_password = os.getenv('ADMIN_PASSWORD', 'admin')

        admin = User(
            username='admin',
            email=admin_email,
            full_name='System Administrator',
            role='admin',
            is_admin=True,
            is_active=True
        )
        admin.set_password(admin_password)

        db.session.add(admin)
        db.session.commit()

        print(f"Created default admin user: {admin_email}")
        print(f"Default password: {admin_password}")
        print("PLEASE CHANGE THE DEFAULT PASSWORD AFTER FIRST LOGIN!")

    # Initialize vulnerability sources
    sources = ['Wiz', 'Veracode', 'Arctic Wolf', 'Crowdstrike', 'Burp']
    for source_name in sources:
        if not VulnerabilitySource.query.filter_by(name=source_name).first():
            source = VulnerabilitySource(
                name=source_name,
                sync_type='csv',
                enabled=True
            )
            db.session.add(source)

    db.session.commit()


if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=os.getenv('FLASK_ENV') == 'development')
