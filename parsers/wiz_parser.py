"""Parser for Wiz vulnerability data with flexible column matching"""
import csv
import json
import hashlib
from datetime import datetime
from typing import List, Dict, Any
import pandas as pd


class WizParser:
    """Parse Wiz vulnerability exports (CSV and API) with flexible column matching"""

    # Define flexible column mappings (lowercase for case-insensitive matching)
    COLUMN_MAPPINGS = {
        'id': ['issue id', 'id', 'issueid', 'issue_id', 'vulnerability id', 'vuln id'],
        'title': ['title', 'name', 'issue name', 'vulnerability name', 'issue', 'summary'],
        'severity': ['severity', 'risk', 'priority', 'criticality'],
        'status': ['status', 'state', 'issue status'],
        'resource': ['resource', 'asset', 'asset name', 'hostname', 'host', 'affected resource'],
        'cve': ['cve', 'cve id', 'cve-id', 'vulnerability id', 'vulnerabilityid'],
        'cvss': ['cvss', 'cvss score', 'cvss_score', 'score'],
        'first_detected': ['first detected', 'first_detected', 'firstdetected', 'created at', 'createdat', 'date found', 'discovered'],
        'description': ['description', 'details', 'summary', 'remediation', 'recommendation'],
        'resource_type': ['resource type', 'resource_type', 'resourcetype', 'asset type', 'type']
    }

    @staticmethod
    def _find_column(df_columns: List[str], possible_names: List[str]) -> str:
        """Find matching column name (case-insensitive)"""
        df_columns_lower = {col.lower(): col for col in df_columns}

        for name in possible_names:
            if name.lower() in df_columns_lower:
                return df_columns_lower[name.lower()]
        return None

    @staticmethod
    def _get_column_mappings(df_columns: List[str]) -> Dict[str, str]:
        """Map expected columns to actual CSV columns"""
        mappings = {}
        for key, possible_names in WizParser.COLUMN_MAPPINGS.items():
            found_col = WizParser._find_column(df_columns, possible_names)
            if found_col:
                mappings[key] = found_col
        return mappings

    @staticmethod
    def parse_csv(file_path: str) -> List[Dict[str, Any]]:
        """
        Parse Wiz CSV export with flexible column matching
        """
        vulnerabilities = []
        skipped_rows = []
        errors = []

        try:
            df = pd.read_csv(file_path)

            # Get column mappings
            col_map = WizParser._get_column_mappings(df.columns.tolist())

            # Log which columns were found
            print(f"Wiz Parser - Found columns: {col_map}")
            print(f"Wiz Parser - CSV has {len(df)} rows")

            # Warn about missing critical columns
            if 'id' not in col_map:
                print("Wiz Parser WARNING: No ID column found. Will generate IDs from row hash.")
            if 'title' not in col_map:
                print("Wiz Parser WARNING: No title/name column found. Using generic titles.")

            for idx, row in df.iterrows():
                try:
                    vuln = WizParser._parse_wiz_row(row, col_map, idx)
                    if vuln:
                        vulnerabilities.append(vuln)
                    else:
                        skipped_rows.append(idx)
                except Exception as e:
                    errors.append(f"Row {idx}: {str(e)}")
                    skipped_rows.append(idx)

            # Report results
            print(f"Wiz Parser - Successfully parsed: {len(vulnerabilities)} vulnerabilities")
            print(f"Wiz Parser - Skipped: {len(skipped_rows)} rows")
            if errors:
                print(f"Wiz Parser - Errors encountered: {len(errors)}")
                for error in errors[:10]:  # Show first 10 errors
                    print(f"  - {error}")

        except Exception as e:
            raise ValueError(f"Error parsing Wiz CSV: {str(e)}")

        return vulnerabilities

    @staticmethod
    def _parse_wiz_row(row, col_map: Dict[str, str], row_idx: int) -> Dict[str, Any]:
        """Parse a single Wiz row into vulnerability dictionary"""
        try:
            # Map severity to standard format
            severity_map = {
                'CRITICAL': 'Critical',
                'HIGH': 'High',
                'MEDIUM': 'Medium',
                'LOW': 'Low',
                'INFORMATIONAL': 'Informational',
                'INFO': 'Informational'
            }

            # Get severity
            severity = 'Unknown'
            if 'severity' in col_map:
                sev_val = str(row.get(col_map['severity'], 'Unknown')).upper()
                severity = severity_map.get(sev_val, sev_val.capitalize())

            # Parse dates
            date_found = datetime.utcnow()
            if 'first_detected' in col_map:
                date_str = row.get(col_map['first_detected'])
                if pd.notna(date_str):
                    try:
                        date_found = pd.to_datetime(date_str)
                    except:
                        pass

            # Extract CVE
            cve_id = None
            if 'cve' in col_map:
                cve_val = row.get(col_map['cve'])
                if pd.notna(cve_val) and cve_val:
                    if not isinstance(cve_val, float):
                        cve_id = str(cve_val).strip()

            # Get title
            title = 'Unknown Vulnerability'
            if 'title' in col_map:
                title_val = row.get(col_map['title'])
                if pd.notna(title_val):
                    title = str(title_val)

            # Get or generate source_id
            source_id = None
            if 'id' in col_map:
                id_val = row.get(col_map['id'])
                if pd.notna(id_val):
                    source_id = str(id_val)

            # If no ID, generate one from row content hash
            if not source_id or source_id == '':
                # Create hash from title + resource + severity
                resource_val = row.get(col_map.get('resource', ''), 'unknown')
                hash_input = f"{title}_{resource_val}_{severity}_{row_idx}"
                source_id = f"wiz_{hashlib.md5(hash_input.encode()).hexdigest()[:12]}"

            # Get resource/asset
            asset_name = 'Unknown'
            if 'resource' in col_map:
                asset_val = row.get(col_map['resource'])
                if pd.notna(asset_val):
                    asset_name = str(asset_val)

            # Get resource type
            asset_type = 'Unknown'
            if 'resource_type' in col_map:
                type_val = row.get(col_map['resource_type'])
                if pd.notna(type_val):
                    asset_type = str(type_val)

            # Get CVSS score
            cvss_score = None
            if 'cvss' in col_map:
                cvss_val = row.get(col_map['cvss'])
                if pd.notna(cvss_val):
                    try:
                        cvss_score = float(cvss_val)
                    except:
                        pass

            # Get description
            description = ''
            if 'description' in col_map:
                desc_val = row.get(col_map['description'])
                if pd.notna(desc_val):
                    description = str(desc_val)

            # Get status
            status = 'open'
            if 'status' in col_map:
                status_val = row.get(col_map['status'])
                if pd.notna(status_val):
                    status = WizParser._map_status(str(status_val))

            # Build vulnerability dictionary
            vulnerability = {
                'source': 'Wiz',
                'source_id': source_id,
                'title': title,
                'description': description,
                'severity': severity,
                'cvss_score': cvss_score,
                'cve_id': cve_id,
                'asset_name': asset_name,
                'asset_type': asset_type,
                'environment': WizParser._determine_environment(row, col_map),
                'status': status,
                'date_found': date_found,
            }

            return vulnerability

        except Exception as e:
            print(f"Error parsing Wiz row {row_idx}: {str(e)}")
            return None

    @staticmethod
    def _determine_environment(row, col_map: Dict[str, str]) -> str:
        """Determine environment from Wiz data"""
        # Try to extract from resource name
        resource = ''
        if 'resource' in col_map:
            res_val = row.get(col_map['resource'])
            if pd.notna(res_val):
                resource = str(res_val).lower()

        if 'prod' in resource:
            return 'Production'
        elif 'stage' in resource or 'staging' in resource:
            return 'Stage'
        elif 'test' in resource or 'qa' in resource:
            return 'Test'
        elif 'dev' in resource:
            return 'Dev'
        else:
            return 'Unknown'

    @staticmethod
    def _map_status(status: str) -> str:
        """Map Wiz status to our internal status"""
        status_map = {
            'OPEN': 'open',
            'IN_PROGRESS': 'in-progress',
            'IN PROGRESS': 'in-progress',
            'RESOLVED': 'resolved',
            'CLOSED': 'resolved',
            'IGNORED': 'false-positive',
            'FALSE POSITIVE': 'false-positive',
            'ACCEPTED': 'risk-accepted',
            'RISK ACCEPTED': 'risk-accepted',
            'RISK_ACCEPTED': 'risk-accepted'
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
