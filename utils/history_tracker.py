"""Utility for tracking vulnerability field changes"""
from datetime import datetime
from typing import Any, Optional
from extensions import db
from models import VulnerabilityHistory


def track_changes(vulnerability, old_data: dict, new_data: dict, user: str, reason: Optional[str] = None):
    """
    Track changes to a vulnerability and create history records

    Args:
        vulnerability: Vulnerability model instance
        old_data: Dictionary of old field values
        new_data: Dictionary of new field values
        user: Username of the person making the change
        reason: Optional reason for the change
    """
    # Fields to track
    tracked_fields = [
        'status', 'severity', 'assigned_to', 'assigned_team', 'environment',
        'remediation_notes', 'false_positive_reason', 'risk_acceptance_reason',
        'risk_acceptance_approver', 'poam_id', 'date_remediated', 'due_date'
    ]

    for field in tracked_fields:
        old_value = old_data.get(field)
        new_value = new_data.get(field)

        # Convert datetime to string for comparison
        if isinstance(old_value, datetime):
            old_value = old_value.isoformat()
        if isinstance(new_value, datetime):
            new_value = new_value.isoformat()

        # Convert None to string for storage
        old_value = str(old_value) if old_value is not None else None
        new_value = str(new_value) if new_value is not None else None

        # Only create history record if value changed
        if old_value != new_value:
            history_record = VulnerabilityHistory(
                vulnerability_id=vulnerability.id,
                field_name=field,
                old_value=old_value,
                new_value=new_value,
                changed_by=user,
                changed_at=datetime.utcnow(),
                change_reason=reason
            )
            db.session.add(history_record)


def create_initial_history(vulnerability, user: str):
    """
    Create initial history record when vulnerability is first created

    Args:
        vulnerability: Vulnerability model instance
        user: Username of the person creating the vulnerability
    """
    history_record = VulnerabilityHistory(
        vulnerability_id=vulnerability.id,
        field_name='created',
        old_value=None,
        new_value='Vulnerability created',
        changed_by=user,
        changed_at=datetime.utcnow(),
        change_reason='Initial creation'
    )
    db.session.add(history_record)
