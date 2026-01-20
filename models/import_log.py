"""Import log model for tracking all import activities"""
from datetime import datetime
from extensions import db


class ImportLog(db.Model):
    """Track all import activities with detailed status and errors"""
    __tablename__ = 'import_logs'

    id = db.Column(db.Integer, primary_key=True)

    # Import metadata
    source = db.Column(db.String(50), nullable=False, index=True)  # Wiz, Veracode, Arctic Wolf
    filename = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer)  # Size in bytes

    # Import status
    status = db.Column(db.String(20), nullable=False, default='pending', index=True)
    # Status values: pending, in-progress, success, partial-success, failed

    # Import results
    total_rows = db.Column(db.Integer, default=0)
    rows_parsed = db.Column(db.Integer, default=0)
    rows_skipped = db.Column(db.Integer, default=0)
    rows_duplicates = db.Column(db.Integer, default=0)
    rows_imported = db.Column(db.Integer, default=0)
    rows_updated = db.Column(db.Integer, default=0)
    rows_errors = db.Column(db.Integer, default=0)

    # Column mapping info
    columns_found = db.Column(db.Text)  # JSON string of column mappings
    columns_missing = db.Column(db.Text)  # JSON string of missing critical columns

    # Error details
    error_message = db.Column(db.Text)  # Main error if import failed
    error_details = db.Column(db.Text)  # JSON string of detailed errors per row
    warnings = db.Column(db.Text)  # JSON string of warnings

    # Timing
    started_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    completed_at = db.Column(db.DateTime, index=True)
    duration_seconds = db.Column(db.Float)

    # User tracking
    imported_by = db.Column(db.String(200), nullable=False)

    # Relationships
    import_errors = db.relationship('ImportError', backref='import_log', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        """Convert import log to dictionary"""
        import json

        return {
            'id': self.id,
            'source': self.source,
            'filename': self.filename,
            'file_size': self.file_size,
            'status': self.status,
            'total_rows': self.total_rows,
            'rows_parsed': self.rows_parsed,
            'rows_skipped': self.rows_skipped,
            'rows_duplicates': self.rows_duplicates,
            'rows_imported': self.rows_imported,
            'rows_updated': self.rows_updated,
            'rows_errors': self.rows_errors,
            'columns_found': json.loads(self.columns_found) if self.columns_found else {},
            'columns_missing': json.loads(self.columns_missing) if self.columns_missing else [],
            'error_message': self.error_message,
            'error_details': json.loads(self.error_details) if self.error_details else [],
            'warnings': json.loads(self.warnings) if self.warnings else [],
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'duration_seconds': self.duration_seconds,
            'imported_by': self.imported_by,
            'error_count': len(self.import_errors) if self.import_errors else 0
        }


class ImportError(db.Model):
    """Track individual row errors during import"""
    __tablename__ = 'import_errors'

    id = db.Column(db.Integer, primary_key=True)
    import_log_id = db.Column(db.Integer, db.ForeignKey('import_logs.id'), nullable=False, index=True)

    # Error details
    row_number = db.Column(db.Integer, nullable=False)
    error_type = db.Column(db.String(50))  # parsing, validation, duplicate, database
    error_message = db.Column(db.Text, nullable=False)
    row_data = db.Column(db.Text)  # JSON string of the problematic row data

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self):
        """Convert import error to dictionary"""
        import json

        return {
            'id': self.id,
            'import_log_id': self.import_log_id,
            'row_number': self.row_number,
            'error_type': self.error_type,
            'error_message': self.error_message,
            'row_data': json.loads(self.row_data) if self.row_data else {},
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
