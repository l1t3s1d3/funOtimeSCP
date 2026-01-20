from datetime import datetime
from extensions import db

class VulnerabilitySource(db.Model):
    """Track vulnerability sources and their sync status"""
    __tablename__ = 'vulnerability_sources'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False, index=True)  # Wiz, Veracode, Arctic Wolf, etc.

    # Configuration
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    sync_type = db.Column(db.String(20), nullable=False)  # 'api' or 'csv'

    # API configuration (if applicable)
    api_endpoint = db.Column(db.String(500))
    api_key_configured = db.Column(db.Boolean, default=False)

    # Sync status
    last_sync_at = db.Column(db.DateTime, index=True)
    last_sync_status = db.Column(db.String(20))  # success, failed, in-progress
    last_sync_error = db.Column(db.Text)
    vulnerabilities_imported = db.Column(db.Integer, default=0)
    vulnerabilities_updated = db.Column(db.Integer, default=0)

    # Metadata
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        """Convert source to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'enabled': self.enabled,
            'sync_type': self.sync_type,
            'api_endpoint': self.api_endpoint,
            'api_key_configured': self.api_key_configured,
            'last_sync_at': self.last_sync_at.isoformat() if self.last_sync_at else None,
            'last_sync_status': self.last_sync_status,
            'last_sync_error': self.last_sync_error,
            'vulnerabilities_imported': self.vulnerabilities_imported,
            'vulnerabilities_updated': self.vulnerabilities_updated,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
