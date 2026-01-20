"""Vulnerability import API endpoints with comprehensive tracking"""
import os
from datetime import datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
from extensions import db
from models import ImportLog, ImportError
from parsers import WizParser, VeracodeParser, ArcticWolfParser
from utils.import_service import ImportService

import_bp = Blueprint('import', __name__, url_prefix='/api/import')

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'csv', 'xml', 'json'}


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def process_import(source_name: str, parser, file, current_user: str):
    """
    Generic import processing with comprehensive tracking

    Returns: (result_dict, status_code)
    """
    import_log = None
    filepath = None

    try:
        # Save file
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        file_size = os.path.getsize(filepath)

        # Start import tracking
        import_log = ImportService.start_import(source_name, filename, file_size, current_user)

        # Parse file based on type
        if filepath.endswith('.csv'):
            parsed_data, columns_found, errors, warnings = parser.parse_csv_with_tracking(filepath)
        elif filepath.endswith('.xml'):
            parsed_data, columns_found, errors, warnings = parser.parse_xml_with_tracking(filepath)
        else:
            raise ValueError("Unsupported file type")

        # Complete import with tracking
        result = ImportService.complete_import(
            import_log,
            parsed_data,
            columns_found,
            errors,
            warnings,
            current_user
        )

        # Clean up file
        if filepath and os.path.exists(filepath):
            os.remove(filepath)

        return {
            'message': f'{source_name} vulnerabilities imported successfully',
            'import_log_id': result['import_log_id'],
            'imported': result['imported'],
            'updated': result['updated'],
            'duplicates': result['duplicates'],
            'errors': result['errors'],
            'total': result['total'],
            'status': import_log.status
        }, 200

    except Exception as e:
        # Mark import as failed
        if import_log:
            ImportService.fail_import(import_log, str(e))

        # Clean up file
        if filepath and os.path.exists(filepath):
            os.remove(filepath)

        return {
            'error': f'Import failed: {str(e)}',
            'import_log_id': import_log.id if import_log else None
        }, 500


@import_bp.route('/wiz', methods=['POST'])
@jwt_required()
def import_wiz():
    """Import vulnerabilities from Wiz CSV file"""
    current_user = get_jwt_identity()

    # Check if file is present
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Only CSV, XML, and JSON files are allowed'}), 400

    result, status_code = process_import('Wiz', WizParser, file, current_user)
    return jsonify(result), status_code


@import_bp.route('/veracode', methods=['POST'])
@jwt_required()
def import_veracode():
    """Import vulnerabilities from Veracode XML file"""
    current_user = get_jwt_identity()

    # Check if file is present
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Only CSV, XML, and JSON files are allowed'}), 400

    result, status_code = process_import('Veracode', VeracodeParser, file, current_user)
    return jsonify(result), status_code


@import_bp.route('/arctic-wolf', methods=['POST'])
@jwt_required()
def import_arctic_wolf():
    """Import vulnerabilities from Arctic Wolf CSV file"""
    current_user = get_jwt_identity()

    # Check if file is present
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Only CSV, XML, and JSON files are allowed'}), 400

    result, status_code = process_import('Arctic Wolf', ArcticWolfParser, file, current_user)
    return jsonify(result), status_code


@import_bp.route('/logs', methods=['GET'])
@jwt_required()
def list_import_logs():
    """List all import logs with filtering"""
    # Get filter parameters
    filters = {}
    if request.args.get('source'):
        filters['source'] = request.args.get('source')
    if request.args.get('status'):
        filters['status'] = request.args.get('status')
    if request.args.get('imported_by'):
        filters['imported_by'] = request.args.get('imported_by')
    if request.args.get('start_date'):
        filters['start_date'] = request.args.get('start_date')
    if request.args.get('end_date'):
        filters['end_date'] = request.args.get('end_date')

    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 200)

    result = ImportService.get_import_logs(filters, page, per_page)
    return jsonify(result), 200


@import_bp.route('/logs/<int:log_id>', methods=['GET'])
@jwt_required()
def get_import_log(log_id):
    """Get detailed information about a specific import"""
    import_log = ImportLog.query.get_or_404(log_id)
    return jsonify(import_log.to_dict()), 200


@import_bp.route('/logs/<int:log_id>/errors', methods=['GET'])
@jwt_required()
def get_import_errors(log_id):
    """Get detailed errors for a specific import"""
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 100, type=int), 500)

    result = ImportService.get_import_errors(log_id, page, per_page)
    return jsonify(result), 200


@import_bp.route('/sources', methods=['GET'])
@jwt_required()
def list_sources():
    """List all vulnerability sources and their sync status"""
    from models import VulnerabilitySource
    sources = VulnerabilitySource.query.all()
    return jsonify([source.to_dict() for source in sources]), 200


@import_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_import_stats():
    """Get import statistics"""
    from sqlalchemy import func

    # Total imports
    total_imports = ImportLog.query.count()

    # Imports by status
    status_counts = db.session.query(
        ImportLog.status,
        func.count(ImportLog.id)
    ).group_by(ImportLog.status).all()

    # Imports by source
    source_counts = db.session.query(
        ImportLog.source,
        func.count(ImportLog.id)
    ).group_by(ImportLog.source).all()

    # Recent imports (last 10)
    recent_imports = ImportLog.query.order_by(
        ImportLog.started_at.desc()
    ).limit(10).all()

    # Total vulnerabilities imported
    total_imported = db.session.query(
        func.sum(ImportLog.rows_imported)
    ).scalar() or 0

    total_updated = db.session.query(
        func.sum(ImportLog.rows_updated)
    ).scalar() or 0

    total_duplicates = db.session.query(
        func.sum(ImportLog.rows_duplicates)
    ).scalar() or 0

    total_errors = db.session.query(
        func.sum(ImportLog.rows_errors)
    ).scalar() or 0

    return jsonify({
        'total_imports': total_imports,
        'by_status': {status: count for status, count in status_counts},
        'by_source': {source: count for source, count in source_counts},
        'recent_imports': [log.to_dict() for log in recent_imports],
        'total_vulnerabilities_imported': total_imported,
        'total_vulnerabilities_updated': total_updated,
        'total_duplicates': total_duplicates,
        'total_errors': total_errors
    }), 200
