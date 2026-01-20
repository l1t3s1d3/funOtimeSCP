"""Parser for Arctic Wolf vulnerability data with flexible column matching"""
import csv
import json
import hashlib
from datetime import datetime
from typing import List, Dict, Any
import pandas as pd


class ArcticWolfParser:
    """Parse Arctic Wolf vulnerability exports (CSV and API) with flexible column matching"""

    # Define flexible column mappings (lowercase for case-insensitive matching)
    COLUMN_MAPPINGS = {
        'id': ['alert id', 'id', 'alertid', 'alert_id', 'observation id', 'finding id'],
        'title': ['title', 'name', 'alert name', 'observation name', 'issue', 'summary', 'finding'],
        'severity': ['severity', 'risk', 'priority', 'criticality', 'level'],
        'status': ['status', 'state', 'alert status', 'observation status'],
        'asset': ['asset', 'hostname', 'host', 'device', 'server', 'endpoint'],
        'cve': ['cve', 'cve id', 'cve-id', 'vulnerability id', 'cve number'],
        'cvss': ['cvss score', 'cvss_score', 'cvss', 'score'],
        'created_date': ['created date', 'created_date', 'createddate', 'date created', 'first seen', 'detected'],
        'description': ['description', 'details', 'summary', 'recommendation', 'remediation'],
        'asset_type': ['asset type', 'asset_type', 'assettype', 'device type', 'type']
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
        for key, possible_names in ArcticWolfParser.COLUMN_MAPPINGS.items():
            found_col = ArcticWolfParser._find_column(df_columns, possible_names)
            if found_col:
                mappings[key] = found_col
        return mappings

    @staticmethod
    def parse_csv(file_path: str) -> List[Dict[str, Any]]:
        """
        Parse Arctic Wolf CSV export with flexible column matching
        """
        vulnerabilities = []
        skipped_rows = []
        errors = []

        try:
            df = pd.read_csv(file_path)

            # Get column mappings
            col_map = ArcticWolfParser._get_column_mappings(df.columns.tolist())

            # Log which columns were found
            print(f"Arctic Wolf Parser - Found columns: {col_map}")
            print(f"Arctic Wolf Parser - CSV has {len(df)} rows")

            # Warn about missing critical columns
            if 'id' not in col_map:
                print("Arctic Wolf Parser WARNING: No ID column found. Will generate IDs from row hash.")
            if 'title' not in col_map:
                print("Arctic Wolf Parser WARNING: No title/name column found. Using generic titles.")

            for idx, row in df.iterrows():
                try:
                    vuln = ArcticWolfParser._parse_arctic_wolf_row(row, col_map, idx)
                    if vuln:
                        vulnerabilities.append(vuln)
                    else:
                        skipped_rows.append(idx)
                except Exception as e:
                    errors.append(f"Row {idx}: {str(e)}")
                    skipped_rows.append(idx)

            # Report results
            print(f"Arctic Wolf Parser - Successfully parsed: {len(vulnerabilities)} vulnerabilities")
            print(f"Arctic Wolf Parser - Skipped: {len(skipped_rows)} rows")
            if errors:
                print(f"Arctic Wolf Parser - Errors encountered: {len(errors)}")
                for error in errors[:10]:  # Show first 10 errors
                    print(f"  - {error}")

        except Exception as e:
            raise ValueError(f"Error parsing Arctic Wolf CSV: {str(e)}")

        return vulnerabilities

    @staticmethod
    def _parse_arctic_wolf_row(row, col_map: Dict[str, str], row_idx: int) -> Dict[str, Any]:
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

            # Get severity
            severity = 'Unknown'
            if 'severity' in col_map:
                sev_val = str(row.get(col_map['severity'], 'Unknown')).upper()
                severity = severity_map.get(sev_val, sev_val.capitalize())

            # Parse dates
            date_found = datetime.utcnow()
            if 'created_date' in col_map:
                date_str = row.get(col_map['created_date'])
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
                # Create hash from title + asset + severity
                asset_val = row.get(col_map.get('asset', ''), 'unknown')
                hash_input = f"{title}_{asset_val}_{severity}_{row_idx}"
                source_id = f"aw_{hashlib.md5(hash_input.encode()).hexdigest()[:12]}"

            # Get asset
            asset_name = 'Unknown'
            if 'asset' in col_map:
                asset_val = row.get(col_map['asset'])
                if pd.notna(asset_val):
                    asset_name = str(asset_val)

            # Get asset type
            asset_type = 'Unknown'
            if 'asset_type' in col_map:
                type_val = row.get(col_map['asset_type'])
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
                    status = ArcticWolfParser._map_status(str(status_val))

            # Build vulnerability dictionary
            vulnerability = {
                'source': 'Arctic Wolf',
                'source_id': source_id,
                'title': title,
                'description': description,
                'severity': severity,
                'cvss_score': cvss_score,
                'cve_id': cve_id,
                'asset_name': asset_name,
                'asset_type': asset_type,
                'environment': ArcticWolfParser._determine_environment(row, col_map),
                'status': status,
                'date_found': date_found,
            }

            return vulnerability

        except Exception as e:
            print(f"Error parsing Arctic Wolf row {row_idx}: {str(e)}")
            return None

    @staticmethod
    def _determine_environment(row, col_map: Dict[str, str]) -> str:
        """Determine environment from Arctic Wolf data"""
        # Try to extract from asset name
        asset = ''
        if 'asset' in col_map:
            asset_val = row.get(col_map['asset'])
            if pd.notna(asset_val):
                asset = str(asset_val).lower()

        if 'prod' in asset:
            return 'Production'
        elif 'stage' in asset or 'staging' in asset:
            return 'Stage'
        elif 'test' in asset or 'qa' in asset:
            return 'Test'
        elif 'dev' in asset:
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
