"""Jira Cloud integration service"""
import os
from datetime import datetime
from typing import Dict, Any, Optional
from jira import JIRA
from jira.exceptions import JIRAError


class JiraService:
    """Service for creating and managing Jira tickets"""

    def __init__(self):
        """Initialize Jira client"""
        self.jira_url = os.getenv('JIRA_URL')
        self.jira_email = os.getenv('JIRA_EMAIL')
        self.jira_token = os.getenv('JIRA_API_TOKEN')
        self.project_key = os.getenv('JIRA_PROJECT_KEY', 'VULN')

        self.client = None
        if self.jira_url and self.jira_email and self.jira_token:
            try:
                self.client = JIRA(
                    server=self.jira_url,
                    basic_auth=(self.jira_email, self.jira_token)
                )
            except Exception as e:
                print(f"Failed to initialize Jira client: {str(e)}")

    def is_configured(self) -> bool:
        """Check if Jira is properly configured"""
        return self.client is not None

    def create_ticket(self, vulnerability: Dict[str, Any], project_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a Jira ticket for a vulnerability

        Args:
            vulnerability: Vulnerability data dictionary
            project_key: Optional project key override

        Returns:
            Dictionary with ticket information (jira_key, jira_id, jira_url)
        """
        if not self.is_configured():
            raise Exception("Jira is not configured. Check JIRA_URL, JIRA_EMAIL, and JIRA_API_TOKEN environment variables.")

        try:
            project = project_key or self.project_key

            # Build title
            title = self._build_ticket_title(vulnerability)

            # Build description
            description = self._build_ticket_description(vulnerability)

            # Create issue
            issue_dict = {
                'project': {'key': project},
                'summary': title,
                'description': description,
                'issuetype': {'name': 'Bug'},
            }

            # Add priority based on severity
            priority = self._map_severity_to_priority(vulnerability.get('severity'))
            if priority:
                issue_dict['priority'] = {'name': priority}

            # Create the issue
            new_issue = self.client.create_issue(fields=issue_dict)

            return {
                'jira_key': new_issue.key,
                'jira_id': new_issue.id,
                'jira_url': f"{self.jira_url}/browse/{new_issue.key}",
                'status': 'Open',
                'assignee': None
            }

        except JIRAError as e:
            raise Exception(f"Failed to create Jira ticket: {str(e)}")

    def update_ticket(self, jira_key: str, fields: Dict[str, Any]) -> bool:
        """
        Update an existing Jira ticket

        Args:
            jira_key: Jira issue key (e.g., VULN-123)
            fields: Dictionary of fields to update

        Returns:
            True if successful
        """
        if not self.is_configured():
            raise Exception("Jira is not configured.")

        try:
            issue = self.client.issue(jira_key)
            issue.update(fields=fields)
            return True
        except JIRAError as e:
            raise Exception(f"Failed to update Jira ticket {jira_key}: {str(e)}")

    def get_ticket_status(self, jira_key: str) -> Dict[str, Any]:
        """
        Get the current status of a Jira ticket

        Args:
            jira_key: Jira issue key (e.g., VULN-123)

        Returns:
            Dictionary with ticket status information
        """
        if not self.is_configured():
            raise Exception("Jira is not configured.")

        try:
            issue = self.client.issue(jira_key)

            return {
                'jira_key': issue.key,
                'status': issue.fields.status.name,
                'assignee': issue.fields.assignee.displayName if issue.fields.assignee else None,
                'updated': issue.fields.updated
            }
        except JIRAError as e:
            raise Exception(f"Failed to get Jira ticket status for {jira_key}: {str(e)}")

    def sync_ticket_status(self, jira_key: str) -> Dict[str, Any]:
        """
        Sync ticket status from Jira

        Args:
            jira_key: Jira issue key (e.g., VULN-123)

        Returns:
            Dictionary with updated ticket information
        """
        return self.get_ticket_status(jira_key)

    def add_comment(self, jira_key: str, comment: str) -> bool:
        """
        Add a comment to a Jira ticket

        Args:
            jira_key: Jira issue key (e.g., VULN-123)
            comment: Comment text

        Returns:
            True if successful
        """
        if not self.is_configured():
            raise Exception("Jira is not configured.")

        try:
            issue = self.client.issue(jira_key)
            self.client.add_comment(issue, comment)
            return True
        except JIRAError as e:
            raise Exception(f"Failed to add comment to Jira ticket {jira_key}: {str(e)}")

    def _build_ticket_title(self, vulnerability: Dict[str, Any]) -> str:
        """Build Jira ticket title from vulnerability"""
        severity = vulnerability.get('severity', 'Unknown')
        title = vulnerability.get('title', 'Unknown Vulnerability')
        asset = vulnerability.get('asset_name', 'Unknown Asset')

        return f"[{severity}] {title} - {asset}"

    def _build_ticket_description(self, vulnerability: Dict[str, Any]) -> str:
        """Build Jira ticket description from vulnerability"""
        lines = []

        lines.append(f"*Vulnerability Details*")
        lines.append("")

        if vulnerability.get('cve_id'):
            lines.append(f"*CVE:* {vulnerability['cve_id']}")

        if vulnerability.get('cwe_id'):
            lines.append(f"*CWE:* {vulnerability['cwe_id']}")

        lines.append(f"*Severity:* {vulnerability.get('severity', 'Unknown')}")

        if vulnerability.get('cvss_score'):
            lines.append(f"*CVSS Score:* {vulnerability['cvss_score']}")

        lines.append(f"*Asset:* {vulnerability.get('asset_name', 'Unknown')}")
        lines.append(f"*Environment:* {vulnerability.get('environment', 'Unknown')}")
        lines.append(f"*Source:* {vulnerability.get('source', 'Unknown')}")
        lines.append("")

        if vulnerability.get('description'):
            lines.append("*Description:*")
            lines.append(vulnerability['description'])
            lines.append("")

        if vulnerability.get('source_url'):
            lines.append(f"*Source Link:* {vulnerability['source_url']}")

        lines.append("")
        lines.append(f"_Created from vulnerability management system on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC_")

        return "\n".join(lines)

    def create_grouped_ticket(self, vulnerabilities: list, project_key: Optional[str] = None) -> Dict[str, Any]:
        """Create a single Jira ticket for multiple vulnerabilities"""
        if not self.is_configured():
            raise Exception("Jira is not configured. Check JIRA_URL, JIRA_EMAIL, and JIRA_API_TOKEN environment variables.")

        if not vulnerabilities:
            raise Exception("No vulnerabilities provided for ticket creation")

        try:
            project = project_key or self.project_key
            title = self._build_grouped_ticket_title(vulnerabilities)
            description = self._build_grouped_ticket_description(vulnerabilities)
            highest_severity = self._get_highest_severity(vulnerabilities)

            issue_dict = {
                'project': {'key': project},
                'summary': title,
                'description': description,
                'issuetype': {'name': 'Bug'},
            }

            priority = self._map_severity_to_priority(highest_severity)
            if priority:
                issue_dict['priority'] = {'name': priority}

            new_issue = self.client.create_issue(fields=issue_dict)

            return {
                'jira_key': new_issue.key,
                'jira_id': new_issue.id,
                'jira_url': f"{self.jira_url}/browse/{new_issue.key}",
                'status': 'Open',
                'assignee': None
            }

        except JIRAError as e:
            raise Exception(f"Failed to create grouped Jira ticket: {str(e)}")

    def _build_grouped_ticket_title(self, vulnerabilities: list) -> str:
        """Build Jira ticket title for multiple vulnerabilities"""
        count = len(vulnerabilities)
        severity_counts = {}
        for v in vulnerabilities:
            sev = v.get('severity', 'Unknown')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        severity_order = ['Critical', 'High', 'Medium', 'Low', 'Informational']
        severity_parts = []
        for sev in severity_order:
            if sev in severity_counts:
                severity_parts.append(f"{severity_counts[sev]} {sev}")
        for sev, c in sorted(severity_counts.items()):
            if sev not in severity_order:
                severity_parts.append(f"{c} {sev}")

        severity_summary = ', '.join(severity_parts)
        return f"Bulk Remediation: {count} Vulnerabilities ({severity_summary})"

    def _build_grouped_ticket_description(self, vulnerabilities: list) -> str:
        """Build Jira ticket description for multiple vulnerabilities"""
        lines = []
        lines.append("*Bulk Vulnerability Remediation Ticket*")
        lines.append("")
        lines.append(f"This ticket tracks remediation of {len(vulnerabilities)} vulnerabilities.")
        lines.append("")

        severity_counts = {}
        for v in vulnerabilities:
            sev = v.get('severity', 'Unknown')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        lines.append("*Summary by Severity:*")
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Informational']:
            if severity in severity_counts:
                lines.append(f"- {severity}: {severity_counts[severity]}")
        lines.append("")

        env_counts = {}
        for v in vulnerabilities:
            env = v.get('environment', 'Unknown')
            env_counts[env] = env_counts.get(env, 0) + 1

        if env_counts:
            lines.append("*Summary by Environment:*")
            for env, count in sorted(env_counts.items()):
                lines.append(f"- {env}: {count}")
            lines.append("")

        lines.append("*Vulnerabilities:*")
        lines.append("")

        for idx, v in enumerate(vulnerabilities, 1):
            lines.append(f"h4. {idx}. {v.get('title', 'Unknown Vulnerability')}")
            lines.append(f"*Severity:* {v.get('severity', 'Unknown')}")

            if v.get('cve_id'):
                lines.append(f"*CVE:* {v['cve_id']}")
            if v.get('cvss_score'):
                lines.append(f"*CVSS Score:* {v['cvss_score']}")

            lines.append(f"*Asset:* {v.get('asset_name', 'Unknown')}")
            lines.append(f"*Environment:* {v.get('environment', 'Unknown')}")
            lines.append(f"*Source:* {v.get('source', 'Unknown')}")

            if v.get('description'):
                desc = v['description']
                if len(desc) > 200:
                    desc = desc[:200] + "..."
                lines.append(f"*Description:* {desc}")

            if v.get('source_url'):
                lines.append(f"*Source Link:* {v['source_url']}")
            lines.append("")

        lines.append(f"_Created from vulnerability management system on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC_")
        return "\n".join(lines)

    def _get_highest_severity(self, vulnerabilities: list) -> str:
        """Determine the highest severity from a list of vulnerabilities"""
        severity_order = ['Critical', 'High', 'Medium', 'Low', 'Informational']
        for severity in severity_order:
            for v in vulnerabilities:
                if v.get('severity') == severity:
                    return severity
        return 'Medium'

    def _map_severity_to_priority(self, severity: str) -> Optional[str]:
        """Map vulnerability severity to Jira priority"""
        severity_map = {
            'Critical': 'Highest',
            'High': 'High',
            'Medium': 'Medium',
            'Low': 'Low',
            'Informational': 'Lowest'
        }
        return severity_map.get(severity)
