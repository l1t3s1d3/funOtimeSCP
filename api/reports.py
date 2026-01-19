"""Reports API endpoints"""
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from sqlalchemy import func
from extensions import db
from models import Vulnerability, VulnerabilityHistory

reports_bp = Blueprint('reports', __name__, url_prefix='/api/reports')


@reports_bp.route('/summary', methods=['GET'])
@jwt_required()
def get_summary():
    """
    Get high-level summary report for executives/managers
    """
    # Total vulnerabilities
    total = Vulnerability.query.count()

    # By severity
    severity_breakdown = db.session.query(
        Vulnerability.severity,
        func.count(Vulnerability.id)
    ).group_by(Vulnerability.severity).all()

    # By status
    status_breakdown = db.session.query(
        Vulnerability.status,
        func.count(Vulnerability.id)
    ).group_by(Vulnerability.status).all()

    # By environment
    environment_breakdown = db.session.query(
        Vulnerability.environment,
        func.count(Vulnerability.id)
    ).group_by(Vulnerability.environment).all()

    # Open critical/high vulnerabilities
    critical_high_open = Vulnerability.query.filter(
        Vulnerability.severity.in_(['Critical', 'High']),
        Vulnerability.status == 'open'
    ).count()

    # Resolved this month
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    resolved_this_month = Vulnerability.query.filter(
        Vulnerability.status == 'resolved',
        Vulnerability.date_remediated >= thirty_days_ago
    ).count()

    # Top 10 CVEs
    top_cves = db.session.query(
        Vulnerability.cve_id,
        func.count(Vulnerability.id).label('count')
    ).filter(
        Vulnerability.cve_id.isnot(None)
    ).group_by(
        Vulnerability.cve_id
    ).order_by(db.desc('count')).limit(10).all()

    # Average remediation time (for resolved vulnerabilities)
    avg_remediation_query = db.session.query(
        func.avg(
            func.julianday(Vulnerability.date_remediated) - func.julianday(Vulnerability.date_found)
        ).label('avg_days')
    ).filter(
        Vulnerability.status == 'resolved',
        Vulnerability.date_remediated.isnot(None)
    ).first()

    avg_remediation_days = round(avg_remediation_query[0], 1) if avg_remediation_query[0] else 0

    return jsonify({
        'total_vulnerabilities': total,
        'severity_breakdown': {sev: count for sev, count in severity_breakdown},
        'status_breakdown': {status: count for status, count in status_breakdown},
        'environment_breakdown': {env: count for env, count in environment_breakdown},
        'critical_high_open': critical_high_open,
        'resolved_last_30_days': resolved_this_month,
        'top_cves': [{'cve_id': cve, 'count': count} for cve, count in top_cves],
        'avg_remediation_days': avg_remediation_days,
        'generated_at': datetime.utcnow().isoformat()
    }), 200


@reports_bp.route('/trends', methods=['GET'])
@jwt_required()
def get_trends():
    """
    Get vulnerability trends over time
    Query params:
    - days: Number of days to look back (default: 90)
    """
    days = request.args.get('days', 90, type=int)
    start_date = datetime.utcnow() - timedelta(days=days)

    # New vulnerabilities by week
    new_vulns_by_week = db.session.query(
        func.strftime('%Y-%W', Vulnerability.date_found).label('week'),
        func.count(Vulnerability.id).label('count')
    ).filter(
        Vulnerability.date_found >= start_date
    ).group_by('week').order_by('week').all()

    # Resolved vulnerabilities by week
    resolved_by_week = db.session.query(
        func.strftime('%Y-%W', Vulnerability.date_remediated).label('week'),
        func.count(Vulnerability.id).label('count')
    ).filter(
        Vulnerability.date_remediated >= start_date,
        Vulnerability.status == 'resolved'
    ).group_by('week').order_by('week').all()

    return jsonify({
        'new_vulnerabilities': [{'week': week, 'count': count} for week, count in new_vulns_by_week],
        'resolved_vulnerabilities': [{'week': week, 'count': count} for week, count in resolved_by_week],
        'period_days': days,
        'generated_at': datetime.utcnow().isoformat()
    }), 200


@reports_bp.route('/by-team', methods=['GET'])
@jwt_required()
def get_by_team():
    """
    Get vulnerability breakdown by assigned team
    """
    team_breakdown = db.session.query(
        Vulnerability.assigned_team,
        Vulnerability.status,
        func.count(Vulnerability.id).label('count')
    ).filter(
        Vulnerability.assigned_team.isnot(None)
    ).group_by(
        Vulnerability.assigned_team,
        Vulnerability.status
    ).all()

    # Organize by team
    teams = {}
    for team, status, count in team_breakdown:
        if team not in teams:
            teams[team] = {'team': team, 'by_status': {}, 'total': 0}
        teams[team]['by_status'][status] = count
        teams[team]['total'] += count

    return jsonify({
        'teams': list(teams.values()),
        'generated_at': datetime.utcnow().isoformat()
    }), 200


@reports_bp.route('/aging', methods=['GET'])
@jwt_required()
def get_aging():
    """
    Get aging report for open vulnerabilities
    """
    now = datetime.utcnow()

    # Get all open vulnerabilities
    open_vulns = Vulnerability.query.filter(
        Vulnerability.status.in_(['open', 'in-progress', 'delayed'])
    ).all()

    # Categorize by age
    age_buckets = {
        '0-30 days': 0,
        '31-60 days': 0,
        '61-90 days': 0,
        '91-180 days': 0,
        '181+ days': 0
    }

    severity_aging = {
        'Critical': {'0-30': 0, '31-60': 0, '61-90': 0, '91-180': 0, '181+': 0},
        'High': {'0-30': 0, '31-60': 0, '61-90': 0, '91-180': 0, '181+': 0},
        'Medium': {'0-30': 0, '31-60': 0, '61-90': 0, '91-180': 0, '181+': 0},
        'Low': {'0-30': 0, '31-60': 0, '61-90': 0, '91-180': 0, '181+': 0},
    }

    for vuln in open_vulns:
        age_days = (now - vuln.date_found).days

        # Determine bucket
        if age_days <= 30:
            bucket = '0-30 days'
            sev_bucket = '0-30'
        elif age_days <= 60:
            bucket = '31-60 days'
            sev_bucket = '31-60'
        elif age_days <= 90:
            bucket = '61-90 days'
            sev_bucket = '61-90'
        elif age_days <= 180:
            bucket = '91-180 days'
            sev_bucket = '91-180'
        else:
            bucket = '181+ days'
            sev_bucket = '181+'

        age_buckets[bucket] += 1

        if vuln.severity in severity_aging:
            severity_aging[vuln.severity][sev_bucket] += 1

    return jsonify({
        'age_distribution': age_buckets,
        'by_severity': severity_aging,
        'total_open': len(open_vulns),
        'generated_at': datetime.utcnow().isoformat()
    }), 200


@reports_bp.route('/cio', methods=['GET'])
@jwt_required()
def get_cio_report():
    """
    Executive summary report for CIO
    """
    # Total counts
    total = Vulnerability.query.count()
    open_count = Vulnerability.query.filter_by(status='open').count()
    resolved_count = Vulnerability.query.filter_by(status='resolved').count()

    # Critical/High open
    critical_open = Vulnerability.query.filter_by(severity='Critical', status='open').count()
    high_open = Vulnerability.query.filter_by(severity='High', status='open').count()

    # Production vulnerabilities
    prod_critical = Vulnerability.query.filter_by(
        environment='Production',
        severity='Critical'
    ).filter(
        Vulnerability.status.in_(['open', 'in-progress'])
    ).count()

    prod_high = Vulnerability.query.filter_by(
        environment='Production',
        severity='High'
    ).filter(
        Vulnerability.status.in_(['open', 'in-progress'])
    ).count()

    # Trends (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    new_last_30 = Vulnerability.query.filter(Vulnerability.date_found >= thirty_days_ago).count()
    resolved_last_30 = Vulnerability.query.filter(
        Vulnerability.status == 'resolved',
        Vulnerability.date_remediated >= thirty_days_ago
    ).count()

    # Risk accepted / POAMs
    risk_accepted = Vulnerability.query.filter_by(status='risk-accepted').count()
    poamd = Vulnerability.query.filter_by(status='poamd').count()

    # Average remediation time
    avg_remediation_query = db.session.query(
        func.avg(
            func.julianday(Vulnerability.date_remediated) - func.julianday(Vulnerability.date_found)
        ).label('avg_days')
    ).filter(
        Vulnerability.status == 'resolved',
        Vulnerability.date_remediated.isnot(None)
    ).first()

    avg_remediation_days = round(avg_remediation_query[0], 1) if avg_remediation_query[0] else 0

    return jsonify({
        'executive_summary': {
            'total_vulnerabilities': total,
            'open': open_count,
            'resolved': resolved_count,
            'resolution_rate': round((resolved_count / total * 100), 1) if total > 0 else 0
        },
        'critical_high': {
            'critical_open': critical_open,
            'high_open': high_open,
            'production_critical': prod_critical,
            'production_high': prod_high
        },
        'trends_last_30_days': {
            'new': new_last_30,
            'resolved': resolved_last_30,
            'net_change': new_last_30 - resolved_last_30
        },
        'risk_management': {
            'risk_accepted': risk_accepted,
            'poam': poamd
        },
        'metrics': {
            'avg_remediation_days': avg_remediation_days
        },
        'generated_at': datetime.utcnow().isoformat()
    }), 200


@reports_bp.route('/export/csv', methods=['GET'])
@jwt_required()
def export_csv():
    """
    Export vulnerabilities to CSV
    Accepts same filters as list endpoint
    """
    import csv
    from io import StringIO

    # Build query with filters (reuse logic from vulnerabilities endpoint)
    query = Vulnerability.query

    # Apply filters (same as list_vulnerabilities)
    severity = request.args.get('severity')
    if severity:
        query = query.filter(Vulnerability.severity == severity)

    status = request.args.get('status')
    if status:
        query = query.filter(Vulnerability.status == status)

    environment = request.args.get('environment')
    if environment:
        query = query.filter(Vulnerability.environment == environment)

    # Get all matching vulnerabilities
    vulnerabilities = query.all()

    # Create CSV
    output = StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow([
        'ID', 'CVE', 'Title', 'Severity', 'Status', 'Environment',
        'Asset', 'Source', 'Date Found', 'Date Remediated', 'Assigned To'
    ])

    # Write data
    for vuln in vulnerabilities:
        writer.writerow([
            vuln.id,
            vuln.cve_id or '',
            vuln.title,
            vuln.severity,
            vuln.status,
            vuln.environment,
            vuln.asset_name,
            vuln.source,
            vuln.date_found.isoformat() if vuln.date_found else '',
            vuln.date_remediated.isoformat() if vuln.date_remediated else '',
            vuln.assigned_to or ''
        ])

    return output.getvalue(), 200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': f'attachment; filename=vulnerabilities_{datetime.utcnow().strftime("%Y%m%d")}.csv'
    }
