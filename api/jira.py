"""Jira integration API endpoints"""
from datetime import datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from extensions import db
from models import Vulnerability, JiraTicket
from utils.jira_service import JiraService

jira_bp = Blueprint('jira', __name__, url_prefix='/api/jira')


@jira_bp.route('/create/<int:vuln_id>', methods=['POST'])
@jwt_required()
def create_ticket(vuln_id):
    """Create a Jira ticket for a vulnerability"""
    current_user = get_jwt_identity()
    vulnerability = Vulnerability.query.get_or_404(vuln_id)

    # Check if ticket already exists
    existing_ticket = JiraTicket.query.filter_by(vulnerability_id=vuln_id).first()
    if existing_ticket:
        return jsonify({'error': 'Jira ticket already exists for this vulnerability'}), 400

    try:
        # Create Jira ticket
        jira_service = JiraService()
        ticket_data = jira_service.create_ticket(vulnerability.to_dict())

        # Save ticket to database
        ticket = JiraTicket(
            vulnerability_id=vuln_id,
            jira_key=ticket_data['jira_key'],
            jira_id=ticket_data['jira_id'],
            jira_url=ticket_data['jira_url'],
            project_key=jira_service.project_key,
            title=vulnerability.title,
            description=vulnerability.description,
            status=ticket_data['status'],
            created_by=current_user,
            last_synced_at=datetime.utcnow()
        )

        db.session.add(ticket)
        db.session.commit()

        return jsonify({
            'message': 'Jira ticket created successfully',
            'ticket': ticket.to_dict()
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@jira_bp.route('/sync/<int:ticket_id>', methods=['POST'])
@jwt_required()
def sync_ticket(ticket_id):
    """Sync Jira ticket status from Jira Cloud"""
    ticket = JiraTicket.query.get_or_404(ticket_id)

    try:
        jira_service = JiraService()
        status_data = jira_service.sync_ticket_status(ticket.jira_key)

        # Update ticket
        ticket.status = status_data['status']
        ticket.assignee = status_data['assignee']
        ticket.last_synced_at = datetime.utcnow()
        ticket.sync_error = None

        db.session.commit()

        return jsonify({
            'message': 'Ticket synced successfully',
            'ticket': ticket.to_dict()
        }), 200

    except Exception as e:
        ticket.sync_error = str(e)
        ticket.last_synced_at = datetime.utcnow()
        db.session.commit()

        return jsonify({'error': str(e)}), 500


@jira_bp.route('/comment/<int:ticket_id>', methods=['POST'])
@jwt_required()
def add_comment(ticket_id):
    """Add a comment to a Jira ticket"""
    ticket = JiraTicket.query.get_or_404(ticket_id)
    data = request.get_json()

    if 'comment' not in data:
        return jsonify({'error': 'Missing comment field'}), 400

    try:
        jira_service = JiraService()
        jira_service.add_comment(ticket.jira_key, data['comment'])

        return jsonify({'message': 'Comment added successfully'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@jira_bp.route('/bulk-create', methods=['POST'])
@jwt_required()
def bulk_create_tickets():
    """Create Jira tickets for multiple vulnerabilities"""
    current_user = get_jwt_identity()
    data = request.get_json()

    if 'vulnerability_ids' not in data:
        return jsonify({'error': 'Missing vulnerability_ids field'}), 400

    vulnerability_ids = data['vulnerability_ids']
    results = {
        'created': [],
        'skipped': [],
        'errors': []
    }

    jira_service = JiraService()

    for vuln_id in vulnerability_ids:
        vulnerability = Vulnerability.query.get(vuln_id)
        if not vulnerability:
            results['errors'].append({
                'vulnerability_id': vuln_id,
                'error': 'Vulnerability not found'
            })
            continue

        # Check if ticket already exists
        existing_ticket = JiraTicket.query.filter_by(vulnerability_id=vuln_id).first()
        if existing_ticket:
            results['skipped'].append({
                'vulnerability_id': vuln_id,
                'reason': 'Ticket already exists'
            })
            continue

        try:
            # Create Jira ticket
            ticket_data = jira_service.create_ticket(vulnerability.to_dict())

            # Save ticket to database
            ticket = JiraTicket(
                vulnerability_id=vuln_id,
                jira_key=ticket_data['jira_key'],
                jira_id=ticket_data['jira_id'],
                jira_url=ticket_data['jira_url'],
                project_key=jira_service.project_key,
                title=vulnerability.title,
                description=vulnerability.description,
                status=ticket_data['status'],
                created_by=current_user,
                last_synced_at=datetime.utcnow()
            )

            db.session.add(ticket)
            results['created'].append({
                'vulnerability_id': vuln_id,
                'jira_key': ticket_data['jira_key']
            })

        except Exception as e:
            results['errors'].append({
                'vulnerability_id': vuln_id,
                'error': str(e)
            })

    db.session.commit()

    return jsonify({
        'message': 'Bulk ticket creation completed',
        'results': results
    }), 200


@jira_bp.route('/tickets', methods=['GET'])
@jwt_required()
def list_tickets():
    """List all Jira tickets"""
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 500)

    query = JiraTicket.query

    # Filter by status
    status = request.args.get('status')
    if status:
        query = query.filter(JiraTicket.status == status)

    # Sort by creation date
    query = query.order_by(JiraTicket.created_at.desc())

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        'total': pagination.total,
        'page': pagination.page,
        'per_page': pagination.per_page,
        'pages': pagination.pages,
        'tickets': [t.to_dict() for t in pagination.items]
    }), 200
