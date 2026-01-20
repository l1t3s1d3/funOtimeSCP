"""Vulnerability import API endpoints"""
import os
from datetime import datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
from extensions import db
from models import Vulnerability, VulnerabilitySource
from parsers import WizParser, VeracodeParser, ArcticWolfParser
from utils.history_tracker import create_initial_history

import_bp = Blueprint('import', __name__, url_prefix='/api/import')

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'csv', 'xml', 'json'}


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


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

    try:
        # Save file
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        # Parse file
        parser = WizParser()
        vulnerabilities_data = parser.parse_csv(filepath)

        # Import vulnerabilities
        imported_count = 0
        updated_count = 0

        for vuln_data in vulnerabilities_data:
            # Check if vulnerability already exists
            existing_vuln = Vulnerability.query.filter_by(
                source='Wiz',
                source_id=vuln_data['source_id']
            ).first()

            if existing_vuln:
                # Update existing vulnerability
                for key, value in vuln_data.items():
                    if key not in ['source', 'source_id'] and value is not None:
                        setattr(existing_vuln, key, value)
                existing_vuln.updated_at = datetime.utcnow()
                existing_vuln.updated_by = current_user
                updated_count += 1
            else:
                # Create new vulnerability
                vuln = Vulnerability(**vuln_data)
                vuln.created_by = current_user
                vuln.updated_by = current_user
                db.session.add(vuln)
                db.session.flush()  # Get the ID
                create_initial_history(vuln, current_user)
                imported_count += 1

        # Update source status
        source = VulnerabilitySource.query.filter_by(name='Wiz').first()
        if not source:
            source = VulnerabilitySource(name='Wiz', sync_type='csv')
            db.session.add(source)

        source.last_sync_at = datetime.utcnow()
        source.last_sync_status = 'success'
        source.vulnerabilities_imported = imported_count
        source.vulnerabilities_updated = updated_count

        db.session.commit()

        # Clean up file
        os.remove(filepath)

        return jsonify({
            'message': 'Wiz vulnerabilities imported successfully',
            'imported': imported_count,
            'updated': updated_count,
            'total': len(vulnerabilities_data)
        }), 200

    except Exception as e:
        db.session.rollback()
        if os.path.exists(filepath):
            os.remove(filepath)

        # Update source status
        source = VulnerabilitySource.query.filter_by(name='Wiz').first()
        if source:
            source.last_sync_at = datetime.utcnow()
            source.last_sync_status = 'failed'
            source.last_sync_error = str(e)
            db.session.commit()

        return jsonify({'error': f'Import failed: {str(e)}'}), 500


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

    try:
        # Save file
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        # Parse file
        parser = VeracodeParser()
        vulnerabilities_data = parser.parse_xml(filepath)

        # Import vulnerabilities
        imported_count = 0
        updated_count = 0

        for vuln_data in vulnerabilities_data:
            # Check if vulnerability already exists
            existing_vuln = Vulnerability.query.filter_by(
                source='Veracode',
                source_id=vuln_data['source_id']
            ).first()

            if existing_vuln:
                # Update existing vulnerability
                for key, value in vuln_data.items():
                    if key not in ['source', 'source_id'] and value is not None:
                        setattr(existing_vuln, key, value)
                existing_vuln.updated_at = datetime.utcnow()
                existing_vuln.updated_by = current_user
                updated_count += 1
            else:
                # Create new vulnerability
                vuln = Vulnerability(**vuln_data)
                vuln.created_by = current_user
                vuln.updated_by = current_user
                db.session.add(vuln)
                db.session.flush()  # Get the ID
                create_initial_history(vuln, current_user)
                imported_count += 1

        # Update source status
        source = VulnerabilitySource.query.filter_by(name='Veracode').first()
        if not source:
            source = VulnerabilitySource(name='Veracode', sync_type='csv')
            db.session.add(source)

        source.last_sync_at = datetime.utcnow()
        source.last_sync_status = 'success'
        source.vulnerabilities_imported = imported_count
        source.vulnerabilities_updated = updated_count

        db.session.commit()

        # Clean up file
        os.remove(filepath)

        return jsonify({
            'message': 'Veracode vulnerabilities imported successfully',
            'imported': imported_count,
            'updated': updated_count,
            'total': len(vulnerabilities_data)
        }), 200

    except Exception as e:
        db.session.rollback()
        if os.path.exists(filepath):
            os.remove(filepath)

        # Update source status
        source = VulnerabilitySource.query.filter_by(name='Veracode').first()
        if source:
            source.last_sync_at = datetime.utcnow()
            source.last_sync_status = 'failed'
            source.last_sync_error = str(e)
            db.session.commit()

        return jsonify({'error': f'Import failed: {str(e)}'}), 500


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

    try:
        # Save file
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        # Parse file
        parser = ArcticWolfParser()
        vulnerabilities_data = parser.parse_csv(filepath)

        # Import vulnerabilities
        imported_count = 0
        updated_count = 0

        for vuln_data in vulnerabilities_data:
            # Check if vulnerability already exists
            existing_vuln = Vulnerability.query.filter_by(
                source='Arctic Wolf',
                source_id=vuln_data['source_id']
            ).first()

            if existing_vuln:
                # Update existing vulnerability
                for key, value in vuln_data.items():
                    if key not in ['source', 'source_id'] and value is not None:
                        setattr(existing_vuln, key, value)
                existing_vuln.updated_at = datetime.utcnow()
                existing_vuln.updated_by = current_user
                updated_count += 1
            else:
                # Create new vulnerability
                vuln = Vulnerability(**vuln_data)
                vuln.created_by = current_user
                vuln.updated_by = current_user
                db.session.add(vuln)
                db.session.flush()  # Get the ID
                create_initial_history(vuln, current_user)
                imported_count += 1

        # Update source status
        source = VulnerabilitySource.query.filter_by(name='Arctic Wolf').first()
        if not source:
            source = VulnerabilitySource(name='Arctic Wolf', sync_type='csv')
            db.session.add(source)

        source.last_sync_at = datetime.utcnow()
        source.last_sync_status = 'success'
        source.vulnerabilities_imported = imported_count
        source.vulnerabilities_updated = updated_count

        db.session.commit()

        # Clean up file
        os.remove(filepath)

        return jsonify({
            'message': 'Arctic Wolf vulnerabilities imported successfully',
            'imported': imported_count,
            'updated': updated_count,
            'total': len(vulnerabilities_data)
        }), 200

    except Exception as e:
        db.session.rollback()
        if os.path.exists(filepath):
            os.remove(filepath)

        # Update source status
        source = VulnerabilitySource.query.filter_by(name='Arctic Wolf').first()
        if source:
            source.last_sync_at = datetime.utcnow()
            source.last_sync_status = 'failed'
            source.last_sync_error = str(e)
            db.session.commit()

        return jsonify({'error': f'Import failed: {str(e)}'}), 500


@import_bp.route('/sources', methods=['GET'])
@jwt_required()
def list_sources():
    """List all vulnerability sources and their sync status"""
    sources = VulnerabilitySource.query.all()
    return jsonify([source.to_dict() for source in sources]), 200
