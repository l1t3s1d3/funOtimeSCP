"""Parser for Wiz vulnerability data"""
import csv
import json
from datetime import datetime
from typing import List, Dict, Any
import pandas as pd


class WizParser:
    """Parse Wiz vulnerability exports (CSV and API)"""

    @staticmethod
    def parse_csv(file_path: str) -> List[Dict[str, Any]]:
        """
        Parse Wiz CSV export
        Expected columns: Issue ID, Title, Severity, Status, Resource, CVE, CVSS,
                         First Detected, Last Detected, Description
        """
        vulnerabilities = []

        try:
            df = pd.read_csv(file_path)

            for _, row in df.iterrows():
                vuln = WizParser._parse_wiz_row(row)
                if vuln:
                    vulnerabilities.append(vuln)

        except Exception as e:
            raise ValueError(f"Error parsing Wiz CSV: {str(e)}")

        return vulnerabilities

    @staticmethod
    def _parse_wiz_row(row) -> Dict[str, Any]:
        """Parse a single Wiz row into vulnerability dictionary"""
        try:
            # Map severity to standard format
            severity_map = {
                'CRITICAL': 'Critical',
                'HIGH': 'High',
                'MEDIUM': 'Medium',
                'LOW': 'Low',
                'INFORMATIONAL': 'Informational'
            }

            severity = row.get('Severity', row.get('severity', 'Unknown')).upper()
            severity = severity_map.get(severity, severity.capitalize())

            # Parse dates
            date_found = None
            date_str = row.get('First Detected', row.get('firstDetected', row.get('createdAt')))
            if pd.notna(date_str):
                try:
                    date_found = pd.to_datetime(date_str)
                except:
                    date_found = datetime.utcnow()

            # Extract CVE
            cve_id = row.get('CVE', row.get('cve', row.get('vulnerabilityId', '')))
            if isinstance(cve_id, float):
                cve_id = None
            elif cve_id:
                cve_id = str(cve_id).strip()

            # Build vulnerability dictionary
            vulnerability = {
                'source': 'Wiz',
                'source_id': str(row.get('Issue ID', row.get('id', row.get('issueId', '')))),
                'title': row.get('Title', row.get('name', 'Unknown Vulnerability')),
                'description': row.get('Description', row.get('description', '')),
                'severity': severity,
                'cvss_score': float(row.get('CVSS', row.get('cvssScore', 0))) if pd.notna(row.get('CVSS', row.get('cvssScore'))) else None,
                'cve_id': cve_id,
                'asset_name': row.get('Resource', row.get('resource', row.get('assetName', 'Unknown'))),
                'asset_type': row.get('Resource Type', row.get('resourceType', 'Unknown')),
                'environment': WizParser._determine_environment(row),
                'status': WizParser._map_status(row.get('Status', row.get('status', 'OPEN'))),
                'date_found': date_found,
            }

            return vulnerability

        except Exception as e:
            print(f"Error parsing Wiz row: {str(e)}")
            return None

    @staticmethod
    def _determine_environment(row) -> str:
        """Determine environment from Wiz data"""
        # Try to extract from resource name or tags
        resource = str(row.get('Resource', row.get('resource', ''))).lower()
        tags = str(row.get('Tags', row.get('tags', ''))).lower()

        if 'prod' in resource or 'prod' in tags:
            return 'Production'
        elif 'stage' in resource or 'staging' in resource or 'stage' in tags:
            return 'Stage'
        elif 'test' in resource or 'test' in tags or 'qa' in resource:
            return 'Test'
        elif 'dev' in resource or 'dev' in tags:
            return 'Dev'
        else:
            return 'Unknown'

    @staticmethod
    def _map_status(status: str) -> str:
        """Map Wiz status to our internal status"""
        status_map = {
            'OPEN': 'open',
            'IN_PROGRESS': 'in-progress',
            'RESOLVED': 'resolved',
            'IGNORED': 'false-positive',
            'ACCEPTED': 'risk-accepted'
        }
        return status_map.get(status.upper(), 'open')

    @staticmethod
    def parse_api_response(api_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parse Wiz API response
        Based on Wiz GraphQL API structure
        """
        vulnerabilities = []

        try:
            # Wiz API returns issues in a data.issues.nodes structure
            issues = api_data.get('data', {}).get('issues', {}).get('nodes', [])

            for issue in issues:
                vuln = {
                    'source': 'Wiz',
                    'source_id': issue.get('id', ''),
                    'title': issue.get('title', 'Unknown Vulnerability'),
                    'description': issue.get('description', ''),
                    'severity': issue.get('severity', 'Unknown').capitalize(),
                    'cvss_score': issue.get('cvssScore'),
                    'cve_id': issue.get('vulnerabilityId'),
                    'asset_name': issue.get('entitySnapshot', {}).get('name', 'Unknown'),
                    'asset_type': issue.get('entitySnapshot', {}).get('type', 'Unknown'),
                    'environment': WizParser._determine_environment(issue.get('entitySnapshot', {})),
                    'status': WizParser._map_status(issue.get('status', 'OPEN')),
                    'date_found': datetime.fromisoformat(issue['createdAt'].replace('Z', '+00:00')) if issue.get('createdAt') else datetime.utcnow(),
                }
                vulnerabilities.append(vuln)

        except Exception as e:
            raise ValueError(f"Error parsing Wiz API response: {str(e)}")

        return vulnerabilities
