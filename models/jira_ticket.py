from datetime import datetime
from extensions import db

class JiraTicket(db.Model):
    """Jira ticket tracking for vulnerabilities"""
    __tablename__ = 'jira_tickets'

    id = db.Column(db.Integer, primary_key=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey('vulnerabilities.id'), nullable=False, index=True)

    # Jira information
    jira_key = db.Column(db.String(50), unique=True, nullable=False, index=True)  # e.g., VULN-123
    jira_id = db.Column(db.String(50), unique=True, nullable=False)  # Jira internal ID
    jira_url = db.Column(db.String(500))

    # Ticket details
    project_key = db.Column(db.String(50), nullable=False)
    title = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text)

    # Status tracking
    status = db.Column(db.String(50), nullable=False, default='Open')  # Open, In Progress, Resolved, Closed, etc.
    assignee = db.Column(db.String(200))
    reporter = db.Column(db.String(200))

    # Metadata
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.String(200))  # User who created the ticket in our system

    # Sync information
    last_synced_at = db.Column(db.DateTime)  # Last time we synced with Jira
    sync_error = db.Column(db.Text)  # Any errors during sync

    def to_dict(self):
        """Convert ticket to dictionary"""
        return {
            'id': self.id,
            'vulnerability_id': self.vulnerability_id,
            'jira_key': self.jira_key,
            'jira_id': self.jira_id,
            'jira_url': self.jira_url,
            'project_key': self.project_key,
            'title': self.title,
            'description': self.description,
            'status': self.status,
            'assignee': self.assignee,
            'reporter': self.reporter,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'created_by': self.created_by,
            'last_synced_at': self.last_synced_at.isoformat() if self.last_synced_at else None,
            'sync_error': self.sync_error
        }
