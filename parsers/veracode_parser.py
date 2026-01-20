"""Parser for Veracode vulnerability data"""
import xml.etree.ElementTree as ET
import xmltodict
from datetime import datetime
from typing import List, Dict, Any


class VeracodeParser:
    """Parse Veracode vulnerability exports (XML detailed report)"""

    @staticmethod
    def parse_xml(file_path: str) -> List[Dict[str, Any]]:
        """
        Parse Veracode XML detailed report
        Based on detailedreport.xsd schema
        """
        vulnerabilities = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                xml_content = f.read()

            # Parse XML to dictionary
            doc = xmltodict.parse(xml_content)

            # Get report info
            detailed_report = doc.get('detailedreport', {})

            # Get static analysis section
            static_analysis = detailed_report.get('static-analysis', {})

            # Get severity info
            severity_info = detailed_report.get('severity', {})

            # Parse each flaw
            flaws = []
            modules = static_analysis.get('modules', {}).get('module', [])

            # Ensure modules is a list
            if not isinstance(modules, list):
                modules = [modules] if modules else []

            for module in modules:
                module_name = module.get('@name', 'Unknown Module')
                module_flaws = module.get('issues', {}).get('issue', [])

                # Ensure flaws is a list
                if not isinstance(module_flaws, list):
                    module_flaws = [module_flaws] if module_flaws else []

                for flaw in module_flaws:
                    vuln = VeracodeParser._parse_veracode_flaw(flaw, module_name, detailed_report)
                    if vuln:
                        vulnerabilities.append(vuln)

        except Exception as e:
            raise ValueError(f"Error parsing Veracode XML: {str(e)}")

        return vulnerabilities

    @staticmethod
    def _parse_veracode_flaw(flaw: Dict, module_name: str, report: Dict) -> Dict[str, Any]:
        """Parse a single Veracode flaw into vulnerability dictionary"""
        try:
            # Map severity (0-5 scale)
            severity_level = int(flaw.get('@severity', 0))
            severity_map = {
                5: 'Critical',
                4: 'High',
                3: 'Medium',
                2: 'Low',
                1: 'Informational',
                0: 'Informational'
            }
            severity = severity_map.get(severity_level, 'Unknown')

            # Parse CWE
            cwe_id = flaw.get('@cweid', '')
            if cwe_id:
                cwe_id = f"CWE-{cwe_id}"

            # Get application info
            app_name = report.get('@app_name', 'Unknown Application')

            # Build vulnerability dictionary
            vulnerability = {
                'source': 'Veracode',
                'source_id': f"veracode-{flaw.get('@issueid', flaw.get('@issue_id', ''))}",
                'title': flaw.get('@categoryname', 'Unknown Vulnerability'),
                'description': flaw.get('@description', ''),
                'severity': severity,
                'cvss_score': None,  # Veracode uses its own scoring
                'cve_id': None,  # CWE-based, not CVE
                'cwe_id': cwe_id,
                'asset_name': app_name,
                'asset_type': 'Application',
                'environment': VeracodeParser._determine_environment(report),
                'status': VeracodeParser._map_status(flaw.get('@remediation_status', 'New')),
                'date_found': VeracodeParser._parse_date(flaw.get('@date_first_occurrence', '')),
            }

            # Add source URL if possible
            if flaw.get('@issueid'):
                vulnerability['source_url'] = f"https://analysiscenter.veracode.com/auth/index.jsp#ViewIssuesDetail:{flaw['@issueid']}"

            return vulnerability

        except Exception as e:
            print(f"Error parsing Veracode flaw: {str(e)}")
            return None

    @staticmethod
    def _determine_environment(report: Dict) -> str:
        """Determine environment from Veracode report"""
        # Try to extract from sandbox name or app name
        sandbox_name = report.get('@sandbox_name', '').lower()
        app_name = report.get('@app_name', '').lower()

        combined = f"{sandbox_name} {app_name}"

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
        """Map Veracode status to our internal status"""
        status_map = {
            'New': 'open',
            'Open': 'open',
            'Fixed': 'resolved',
            'Cannot Reproduce': 'false-positive',
            'Approved Mitigation': 'risk-accepted',
            'Potential False Positive': 'false-positive',
            'Mitigation Proposed': 'in-progress',
            'Mitigation Accepted': 'risk-accepted',
            'Mitigation Rejected': 'open'
        }
        return status_map.get(status, 'open')

    @staticmethod
    def _parse_date(date_str: str) -> datetime:
        """Parse Veracode date string"""
        if not date_str:
            return datetime.utcnow()

        try:
            # Veracode uses format like: 2024-01-15 12:34:56 UTC
            return datetime.strptime(date_str.split('.')[0], '%Y-%m-%d %H:%M:%S')
        except:
            try:
                return datetime.strptime(date_str.split()[0], '%Y-%m-%d')
            except:
                return datetime.utcnow()

    @staticmethod
    def parse_api_response(api_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parse Veracode API response
        Based on Veracode REST API structure
        """
        vulnerabilities = []

        try:
            # Veracode API returns findings in _embedded.findings
            findings = api_data.get('_embedded', {}).get('findings', [])

            for finding in findings:
                vuln = {
                    'source': 'Veracode',
                    'source_id': f"veracode-{finding.get('issue_id', finding.get('id', ''))}",
                    'title': finding.get('finding_category', {}).get('name', 'Unknown Vulnerability'),
                    'description': finding.get('description', ''),
                    'severity': VeracodeParser._map_api_severity(finding.get('severity', 0)),
                    'cwe_id': f"CWE-{finding.get('cwe', {}).get('id', '')}" if finding.get('cwe') else None,
                    'asset_name': finding.get('app_name', 'Unknown Application'),
                    'asset_type': 'Application',
                    'environment': 'Unknown',
                    'status': VeracodeParser._map_status(finding.get('finding_status', {}).get('resolution_status', 'New')),
                    'date_found': datetime.fromisoformat(finding['found_date']) if finding.get('found_date') else datetime.utcnow(),
                }
                vulnerabilities.append(vuln)

        except Exception as e:
            raise ValueError(f"Error parsing Veracode API response: {str(e)}")

        return vulnerabilities

    @staticmethod
    def _map_api_severity(severity: int) -> str:
        """Map Veracode API severity to standard format"""
        severity_map = {
            5: 'Critical',
            4: 'High',
            3: 'Medium',
            2: 'Low',
            1: 'Informational',
            0: 'Informational'
        }
        return severity_map.get(severity, 'Unknown')
