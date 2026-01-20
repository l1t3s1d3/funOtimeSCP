"""Vulnerability API endpoints"""
from datetime import datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from sqlalchemy import and_, or_
from extensions import db
from models import Vulnerability, VulnerabilityHistory
from utils.history_tracker import track_changes

vulnerabilities_bp = Blueprint('vulnerabilities', __name__, url_prefix='/api/vulnerabilities')


@vulnerabilities_bp.route('', methods=['GET'])
@jwt_required()
def list_vulnerabilities():
    """
    List vulnerabilities with filtering and pagination

    Query parameters:
    - severity: Filter by severity (Critical, High, Medium, Low, Informational)
    - status: Filter by status (open, false-positive, risk-accepted, in-progress, resolved, delayed, poamd)
    - environment: Filter by environment (Dev, Stage, Test, Production)
    - source: Filter by source (Wiz, Veracode, Arctic Wolf, etc.)
    - cve_id: Filter by CVE ID
    - date_found_start: Filter by date found (start date, ISO format)
    - date_found_end: Filter by date found (end date, ISO format)
    - date_remediated_start: Filter by date remediated (start date, ISO format)
    - date_remediated_end: Filter by date remediated (end date, ISO format)
    - assigned_to: Filter by assignee
    - assigned_team: Filter by team
    - page: Page number (default: 1)
    - per_page: Items per page (default: 50, max: 500)
    - sort_by: Sort field (default: date_found)
    - sort_order: Sort order (asc or desc, default: desc)
    - group_by_cve: Group results by CVE (true/false, default: false)
    """
    # Build query
    query = Vulnerability.query

    # Apply filters
    severity = request.args.get('severity')
    if severity:
        query = query.filter(Vulnerability.severity == severity)

    status = request.args.get('status')
    if status:
        query = query.filter(Vulnerability.status == status)

    environment = request.args.get('environment')
    if environment:
        query = query.filter(Vulnerability.environment == environment)

    source = request.args.get('source')
    if source:
        query = query.filter(Vulnerability.source == source)

    cve_id = request.args.get('cve_id')
    if cve_id:
        query = query.filter(Vulnerability.cve_id == cve_id)

    date_found_start = request.args.get('date_found_start')
    if date_found_start:
        query = query.filter(Vulnerability.date_found >= datetime.fromisoformat(date_found_start))

    date_found_end = request.args.get('date_found_end')
    if date_found_end:
        query = query.filter(Vulnerability.date_found <= datetime.fromisoformat(date_found_end))

    date_remediated_start = request.args.get('date_remediated_start')
    if date_remediated_start:
        query = query.filter(Vulnerability.date_remediated >= datetime.fromisoformat(date_remediated_start))

    date_remediated_end = request.args.get('date_remediated_end')
    if date_remediated_end:
        query = query.filter(Vulnerability.date_remediated <= datetime.fromisoformat(date_remediated_end))

    assigned_to = request.args.get('assigned_to')
    if assigned_to:
        query = query.filter(Vulnerability.assigned_to == assigned_to)

    assigned_team = request.args.get('assigned_team')
    if assigned_team:
        query = query.filter(Vulnerability.assigned_team == assigned_team)

    # Search
    search = request.args.get('search')
    if search:
        search_filter = or_(
            Vulnerability.title.ilike(f'%{search}%'),
            Vulnerability.description.ilike(f'%{search}%'),
            Vulnerability.cve_id.ilike(f'%{search}%'),
            Vulnerability.asset_name.ilike(f'%{search}%')
        )
        query = query.filter(search_filter)

    # Sorting
    sort_by = request.args.get('sort_by', 'date_found')
    sort_order = request.args.get('sort_order', 'desc')

    valid_sort_fields = ['date_found', 'date_remediated', 'severity', 'status', 'created_at', 'updated_at']
    if sort_by not in valid_sort_fields:
        sort_by = 'date_found'

    sort_column = getattr(Vulnerability, sort_by)
    if sort_order == 'asc':
        query = query.order_by(sort_column.asc())
    else:
        query = query.order_by(sort_column.desc())

    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 500)

    # Check if grouping by CVE
    group_by_cve = request.args.get('group_by_cve', 'false').lower() == 'true'

    if group_by_cve:
        # Group by CVE and return counts
        results = query.all()
        grouped = {}
        for vuln in results:
            cve = vuln.cve_id or 'No CVE'
            if cve not in grouped:
                grouped[cve] = {
                    'cve_id': cve,
                    'count': 0,
                    'severities': {},
                    'vulnerabilities': []
                }
            grouped[cve]['count'] += 1
            sev = vuln.severity
            grouped[cve]['severities'][sev] = grouped[cve]['severities'].get(sev, 0) + 1
            grouped[cve]['vulnerabilities'].append(vuln.to_dict())

        return jsonify({
            'total': len(grouped),
            'groups': list(grouped.values())
        }), 200
    else:
        # Regular pagination
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)

        return jsonify({
            'total': pagination.total,
            'page': pagination.page,
            'per_page': pagination.per_page,
            'pages': pagination.pages,
            'vulnerabilities': [v.to_dict() for v in pagination.items]
        }), 200


@vulnerabilities_bp.route('/<int:vuln_id>', methods=['GET'])
@jwt_required()
def get_vulnerability(vuln_id):
    """Get a single vulnerability with history"""
    vulnerability = Vulnerability.query.get_or_404(vuln_id)

    vuln_dict = vulnerability.to_dict()
    vuln_dict['history'] = [h.to_dict() for h in vulnerability.history]

    return jsonify(vuln_dict), 200


@vulnerabilities_bp.route('/<int:vuln_id>', methods=['PUT'])
@jwt_required()
def update_vulnerability(vuln_id):
    """Update a vulnerability"""
    current_user = get_jwt_identity()
    vulnerability = Vulnerability.query.get_or_404(vuln_id)

    data = request.get_json()

    # Store old values for history tracking
    old_data = {
        'status': vulnerability.status,
        'severity': vulnerability.severity,
        'assigned_to': vulnerability.assigned_to,
        'assigned_team': vulnerability.assigned_team,
        'environment': vulnerability.environment,
        'remediation_notes': vulnerability.remediation_notes,
        'false_positive_reason': vulnerability.false_positive_reason,
        'risk_acceptance_reason': vulnerability.risk_acceptance_reason,
        'risk_acceptance_approver': vulnerability.risk_acceptance_approver,
        'poam_id': vulnerability.poam_id,
        'date_remediated': vulnerability.date_remediated,
        'due_date': vulnerability.due_date
    }

    # Update allowed fields
    if 'status' in data:
        vulnerability.status = data['status']
        # Auto-set date_remediated if status is resolved
        if data['status'] == 'resolved' and not vulnerability.date_remediated:
            vulnerability.date_remediated = datetime.utcnow()

    if 'severity' in data:
        vulnerability.severity = data['severity']
    if 'assigned_to' in data:
        vulnerability.assigned_to = data['assigned_to']
    if 'assigned_team' in data:
        vulnerability.assigned_team = data['assigned_team']
    if 'environment' in data:
        vulnerability.environment = data['environment']
    if 'remediation_notes' in data:
        vulnerability.remediation_notes = data['remediation_notes']
    if 'false_positive_reason' in data:
        vulnerability.false_positive_reason = data['false_positive_reason']
    if 'risk_acceptance_reason' in data:
        vulnerability.risk_acceptance_reason = data['risk_acceptance_reason']
    if 'risk_acceptance_approver' in data:
        vulnerability.risk_acceptance_approver = data['risk_acceptance_approver']
    if 'poam_id' in data:
        vulnerability.poam_id = data['poam_id']
    if 'date_remediated' in data:
        if data['date_remediated']:
            vulnerability.date_remediated = datetime.fromisoformat(data['date_remediated'])
        else:
            vulnerability.date_remediated = None
    if 'due_date' in data:
        if data['due_date']:
            vulnerability.due_date = datetime.fromisoformat(data['due_date'])
        else:
            vulnerability.due_date = None

    vulnerability.updated_by = current_user
    vulnerability.updated_at = datetime.utcnow()

    # Track changes
    new_data = {
        'status': vulnerability.status,
        'severity': vulnerability.severity,
        'assigned_to': vulnerability.assigned_to,
        'assigned_team': vulnerability.assigned_team,
        'environment': vulnerability.environment,
        'remediation_notes': vulnerability.remediation_notes,
        'false_positive_reason': vulnerability.false_positive_reason,
        'risk_acceptance_reason': vulnerability.risk_acceptance_reason,
        'risk_acceptance_approver': vulnerability.risk_acceptance_approver,
        'poam_id': vulnerability.poam_id,
        'date_remediated': vulnerability.date_remediated,
        'due_date': vulnerability.due_date
    }

    track_changes(vulnerability, old_data, new_data, current_user, data.get('change_reason'))

    db.session.commit()

    return jsonify({
        'message': 'Vulnerability updated successfully',
        'vulnerability': vulnerability.to_dict()
    }), 200


@vulnerabilities_bp.route('/<int:vuln_id>', methods=['DELETE'])
@jwt_required()
def delete_vulnerability(vuln_id):
    """Delete a vulnerability (admin only)"""
    claims = get_jwt()
    if not claims.get('is_admin'):
        return jsonify({'error': 'Admin access required'}), 403

    vulnerability = Vulnerability.query.get_or_404(vuln_id)
    db.session.delete(vulnerability)
    db.session.commit()

    return jsonify({'message': 'Vulnerability deleted successfully'}), 200


@vulnerabilities_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_stats():
    """Get vulnerability statistics"""
    # Total counts by status
    status_counts = db.session.query(
        Vulnerability.status,
        db.func.count(Vulnerability.id)
    ).group_by(Vulnerability.status).all()

    # Total counts by severity
    severity_counts = db.session.query(
        Vulnerability.severity,
        db.func.count(Vulnerability.id)
    ).group_by(Vulnerability.severity).all()

    # Total counts by environment
    environment_counts = db.session.query(
        Vulnerability.environment,
        db.func.count(Vulnerability.id)
    ).group_by(Vulnerability.environment).all()

    # Total counts by source
    source_counts = db.session.query(
        Vulnerability.source,
        db.func.count(Vulnerability.id)
    ).group_by(Vulnerability.source).all()

    # Top CVEs
    top_cves = db.session.query(
        Vulnerability.cve_id,
        db.func.count(Vulnerability.id).label('count')
    ).filter(Vulnerability.cve_id.isnot(None)).group_by(
        Vulnerability.cve_id
    ).order_by(db.desc('count')).limit(10).all()

    # Resolved vulnerabilities count
    resolved_count = Vulnerability.query.filter_by(status='resolved').count()

    return jsonify({
        'total': Vulnerability.query.count(),
        'by_status': {status: count for status, count in status_counts},
        'by_severity': {severity: count for severity, count in severity_counts},
        'by_environment': {env: count for env, count in environment_counts},
        'by_source': {source: count for source, count in source_counts},
        'top_cves': [{'cve_id': cve, 'count': count} for cve, count in top_cves],
        'resolved_count': resolved_count
    }), 200
