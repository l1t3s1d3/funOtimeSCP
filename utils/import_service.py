"""Import service for tracking and managing vulnerability imports"""
import os
import json
from datetime import datetime
from typing import List, Dict, Any, Tuple
from extensions import db
from models import Vulnerability, ImportLog, ImportError, VulnerabilitySource
from utils.history_tracker import create_initial_history


class ImportService:
    """Service for handling vulnerability imports with comprehensive tracking"""

    @staticmethod
    def start_import(source: str, filename: str, file_size: int, user: str) -> ImportLog:
        """Create and return a new import log entry"""
        import_log = ImportLog(
            source=source,
            filename=filename,
            file_size=file_size,
            status='in-progress',
            imported_by=user,
            started_at=datetime.utcnow()
        )
        db.session.add(import_log)
        db.session.commit()
        return import_log

    @staticmethod
    def complete_import(import_log: ImportLog,
                       parsed_data: List[Dict[str, Any]],
                       columns_found: Dict[str, str],
                       errors: List[Tuple[int, str, str]],
                       warnings: List[str],
                       user: str) -> Dict[str, Any]:
        """
        Process parsed vulnerabilities and complete the import

        Returns: Dictionary with import results
        """
        imported_count = 0
        updated_count = 0
        duplicate_count = 0
        error_count = 0

        # Store column info
        import_log.columns_found = json.dumps(columns_found)
        import_log.total_rows = len(parsed_data)
        import_log.rows_parsed = len(parsed_data)

        # Process each vulnerability
        for idx, vuln_data in enumerate(parsed_data):
            try:
                # Check for duplicates
                existing_vuln = Vulnerability.query.filter_by(
                    source=vuln_data['source'],
                    source_id=vuln_data['source_id']
                ).first()

                if existing_vuln:
                    # Check if this is a real duplicate or an update
                    if ImportService._is_duplicate(existing_vuln, vuln_data):
                        duplicate_count += 1
                        ImportService._log_error(
                            import_log,
                            idx,
                            'duplicate',
                            f"Duplicate vulnerability: {vuln_data.get('title', 'Unknown')} (ID: {vuln_data['source_id']})",
                            vuln_data
                        )
                    else:
                        # Update existing vulnerability
                        for key, value in vuln_data.items():
                            if key not in ['source', 'source_id'] and value is not None:
                                setattr(existing_vuln, key, value)
                        existing_vuln.updated_at = datetime.utcnow()
                        existing_vuln.updated_by = user
                        updated_count += 1
                else:
                    # Create new vulnerability
                    vuln = Vulnerability(**vuln_data)
                    vuln.created_by = user
                    vuln.updated_by = user
                    db.session.add(vuln)
                    db.session.flush()  # Get the ID
                    create_initial_history(vuln, user)
                    imported_count += 1

            except Exception as e:
                error_count += 1
                ImportService._log_error(
                    import_log,
                    idx,
                    'database',
                    str(e),
                    vuln_data
                )

        # Store parsing errors
        for row_num, error_type, error_msg in errors:
            ImportService._log_error(import_log, row_num, error_type, error_msg, {})

        # Update import log with results
        import_log.rows_imported = imported_count
        import_log.rows_updated = updated_count
        import_log.rows_duplicates = duplicate_count
        import_log.rows_errors = error_count
        import_log.rows_skipped = len(parsed_data) - imported_count - updated_count - duplicate_count
        import_log.warnings = json.dumps(warnings) if warnings else None
        import_log.completed_at = datetime.utcnow()
        import_log.duration_seconds = (import_log.completed_at - import_log.started_at).total_seconds()

        # Determine final status
        if error_count == len(parsed_data):
            import_log.status = 'failed'
        elif error_count > 0 or duplicate_count > 0:
            import_log.status = 'partial-success'
        else:
            import_log.status = 'success'

        # Update source status
        source = VulnerabilitySource.query.filter_by(name=vuln_data['source']).first()
        if not source:
            source = VulnerabilitySource(name=vuln_data['source'], sync_type='csv')
            db.session.add(source)

        source.last_sync_at = datetime.utcnow()
        source.last_sync_status = import_log.status
        source.vulnerabilities_imported = imported_count
        source.vulnerabilities_updated = updated_count

        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            import_log.status = 'failed'
            import_log.error_message = str(e)
            db.session.commit()
            raise

        return {
            'imported': imported_count,
            'updated': updated_count,
            'duplicates': duplicate_count,
            'errors': error_count,
            'total': len(parsed_data),
            'import_log_id': import_log.id
        }

    @staticmethod
    def fail_import(import_log: ImportLog, error_message: str):
        """Mark import as failed"""
        import_log.status = 'failed'
        import_log.error_message = error_message
        import_log.completed_at = datetime.utcnow()
        if import_log.started_at:
            import_log.duration_seconds = (import_log.completed_at - import_log.started_at).total_seconds()
        db.session.commit()

    @staticmethod
    def _is_duplicate(existing: Vulnerability, new_data: Dict[str, Any]) -> bool:
        """
        Check if the new data is truly a duplicate or an update
        Returns True if it's a duplicate (no changes), False if it's an update
        """
        # Compare key fields to determine if this is really a duplicate
        fields_to_compare = ['title', 'severity', 'status', 'description', 'cve_id', 'asset_name']

        for field in fields_to_compare:
            existing_value = getattr(existing, field, None)
            new_value = new_data.get(field)

            # Convert to strings for comparison
            existing_str = str(existing_value) if existing_value is not None else ''
            new_str = str(new_value) if new_value is not None else ''

            if existing_str != new_str:
                return False  # Found a difference, so it's an update

        return True  # No differences found, it's a duplicate

    @staticmethod
    def _log_error(import_log: ImportLog, row_number: int, error_type: str,
                   error_message: str, row_data: Dict[str, Any]):
        """Log an individual row error"""
        error = ImportError(
            import_log_id=import_log.id,
            row_number=row_number,
            error_type=error_type,
            error_message=error_message,
            row_data=json.dumps(row_data) if row_data else None
        )
        db.session.add(error)

    @staticmethod
    def get_import_logs(filters: Dict[str, Any] = None, page: int = 1, per_page: int = 50):
        """
        Get import logs with filtering and pagination

        Filters:
        - source: Filter by source (Wiz, Veracode, Arctic Wolf)
        - status: Filter by status (success, failed, partial-success)
        - imported_by: Filter by user
        - start_date: Filter by start date
        - end_date: Filter by end date
        """
        query = ImportLog.query

        if filters:
            if filters.get('source'):
                query = query.filter(ImportLog.source == filters['source'])
            if filters.get('status'):
                query = query.filter(ImportLog.status == filters['status'])
            if filters.get('imported_by'):
                query = query.filter(ImportLog.imported_by == filters['imported_by'])
            if filters.get('start_date'):
                query = query.filter(ImportLog.started_at >= datetime.fromisoformat(filters['start_date']))
            if filters.get('end_date'):
                query = query.filter(ImportLog.started_at <= datetime.fromisoformat(filters['end_date']))

        # Order by most recent first
        query = query.order_by(ImportLog.started_at.desc())

        # Paginate
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)

        return {
            'total': pagination.total,
            'page': pagination.page,
            'per_page': pagination.per_page,
            'pages': pagination.pages,
            'logs': [log.to_dict() for log in pagination.items]
        }

    @staticmethod
    def get_import_errors(import_log_id: int, page: int = 1, per_page: int = 100):
        """Get detailed errors for a specific import"""
        query = ImportError.query.filter_by(import_log_id=import_log_id)
        query = query.order_by(ImportError.row_number.asc())

        pagination = query.paginate(page=page, per_page=per_page, error_out=False)

        return {
            'total': pagination.total,
            'page': pagination.page,
            'per_page': pagination.per_page,
            'pages': pagination.pages,
            'errors': [error.to_dict() for error in pagination.items]
        }
