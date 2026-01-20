"""Parser for Arctic Wolf vulnerability data"""
import csv
import json
from datetime import datetime
from typing import List, Dict, Any
import pandas as pd


class ArcticWolfParser:
    """Parse Arctic Wolf vulnerability exports (CSV and API)"""

    @staticmethod
    def parse_csv(file_path: str) -> List[Dict[str, Any]]:
        """
        Parse Arctic Wolf CSV export
        Expected columns: Alert ID, Title, Severity, Status, Asset, CVE,
                         Created Date, Updated Date, Description
        """
        vulnerabilities = []

        try:
            df = pd.read_csv(file_path)

            for _, row in df.iterrows():
                vuln = ArcticWolfParser._parse_arctic_wolf_row(row)
                if vuln:
                    vulnerabilities.append(vuln)

        except Exception as e:
            raise ValueError(f"Error parsing Arctic Wolf CSV: {str(e)}")

        return vulnerabilities

    @staticmethod
    def _parse_arctic_wolf_row(row) -> Dict[str, Any]:
        """Parse a single Arctic Wolf row into vulnerability dictionary"""
        try:
            # Map severity to standard format
            severity_map = {
                'CRITICAL': 'Critical',
                'HIGH': 'High',
                'MEDIUM': 'Medium',
                'LOW': 'Low',
                'INFO': 'Informational',
                'INFORMATIONAL': 'Informational'
            }

            severity = row.get('Severity', row.get('severity', 'Unknown')).upper()
            severity = severity_map.get(severity, severity.capitalize())

            # Parse dates
            date_found = None
            date_str = row.get('Created Date', row.get('created_date', row.get('createdAt')))
            if pd.notna(date_str):
                try:
                    date_found = pd.to_datetime(date_str)
                except:
                    date_found = datetime.utcnow()

            # Extract CVE
            cve_id = row.get('CVE', row.get('cve', row.get('cve_id', '')))
            if isinstance(cve_id, float):
                cve_id = None
            elif cve_id:
                cve_id = str(cve_id).strip()

            # Build vulnerability dictionary
            vulnerability = {
                'source': 'Arctic Wolf',
                'source_id': str(row.get('Alert ID', row.get('id', row.get('alertId', '')))),
                'title': row.get('Title', row.get('name', row.get('title', 'Unknown Vulnerability'))),
                'description': row.get('Description', row.get('description', '')),
                'severity': severity,
                'cvss_score': float(row.get('CVSS Score', row.get('cvss_score', 0))) if pd.notna(row.get('CVSS Score', row.get('cvss_score'))) else None,
                'cve_id': cve_id,
                'asset_name': row.get('Asset', row.get('asset', row.get('hostname', 'Unknown'))),
                'asset_type': row.get('Asset Type', row.get('asset_type', 'Unknown')),
                'environment': ArcticWolfParser._determine_environment(row),
                'status': ArcticWolfParser._map_status(row.get('Status', row.get('status', 'Open'))),
                'date_found': date_found,
            }

            return vulnerability

        except Exception as e:
            print(f"Error parsing Arctic Wolf row: {str(e)}")
            return None

    @staticmethod
    def _determine_environment(row) -> str:
        """Determine environment from Arctic Wolf data"""
        # Try to extract from asset name or tags
        asset = str(row.get('Asset', row.get('asset', row.get('hostname', '')))).lower()
        tags = str(row.get('Tags', row.get('tags', ''))).lower()

        combined = f"{asset} {tags}"

        if 'prod' in combined:
            return 'Production'
        elif 'stage' in combined or 'staging' in combined:
            return 'Stage'
        elif 'test' in combined or 'qa' in combined:
            return 'Test'
        elif 'dev' in combined:
            return 'Dev'
        else:
            return 'Unknown'

    @staticmethod
    def _map_status(status: str) -> str:
        """Map Arctic Wolf status to our internal status"""
        status_map = {
            'OPEN': 'open',
            'IN PROGRESS': 'in-progress',
            'IN_PROGRESS': 'in-progress',
            'RESOLVED': 'resolved',
            'CLOSED': 'resolved',
            'FALSE POSITIVE': 'false-positive',
            'FALSE_POSITIVE': 'false-positive',
            'RISK ACCEPTED': 'risk-accepted',
            'RISK_ACCEPTED': 'risk-accepted'
        }
        return status_map.get(status.upper(), 'open')

    @staticmethod
    def parse_api_response(api_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parse Arctic Wolf API response
        Based on Arctic Wolf API structure
        """
        vulnerabilities = []

        try:
            # Arctic Wolf API returns vulnerabilities in a results array
            results = api_data.get('results', [])

            for item in results:
                vuln = {
                    'source': 'Arctic Wolf',
                    'source_id': item.get('id', ''),
                    'title': item.get('title', 'Unknown Vulnerability'),
                    'description': item.get('description', ''),
                    'severity': item.get('severity', 'Unknown').capitalize(),
                    'cvss_score': item.get('cvss_score'),
                    'cve_id': item.get('cve_id'),
                    'asset_name': item.get('affected_asset', {}).get('hostname', 'Unknown'),
                    'asset_type': item.get('affected_asset', {}).get('type', 'Unknown'),
                    'environment': ArcticWolfParser._determine_environment(item.get('affected_asset', {})),
                    'status': ArcticWolfParser._map_status(item.get('status', 'Open')),
                    'date_found': datetime.fromisoformat(item['created_at'].replace('Z', '+00:00')) if item.get('created_at') else datetime.utcnow(),
                }
                vulnerabilities.append(vuln)

        except Exception as e:
            raise ValueError(f"Error parsing Arctic Wolf API response: {str(e)}")

        return vulnerabilities
