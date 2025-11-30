"""
Zeek Log Parser for TSV format logs
Handles parsing of Zeek's tab-separated log files into structured Python dictionaries
"""

import os
import csv
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

# Set up logging
logger = logging.getLogger(__name__)

class ZeekLogParser:
    """Parser for Zeek TSV log files"""
    
    def __init__(self):
        self.log_schemas = {
            'conn': {
                'fields': ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
                          'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes',
                          'conn_state', 'local_orig', 'local_resp', 'missed_bytes',
                          'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes',
                          'tunnel_parents'],
                'types': {'ts': 'timestamp', 'orig_bytes': 'int', 'resp_bytes': 'int',
                         'duration': 'float', 'orig_pkts': 'int', 'resp_pkts': 'int',
                         'orig_ip_bytes': 'int', 'resp_ip_bytes': 'int'}
            },
            'http': {
                'fields': ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
                          'trans_depth', 'method', 'host', 'uri', 'referrer', 'version',
                          'user_agent', 'origin', 'request_body_len', 'response_body_len',
                          'status_code', 'status_msg', 'info_code', 'info_msg',
                          'tags', 'username', 'password', 'proxied', 'orig_fuids',
                          'orig_filenames', 'orig_mime_types', 'resp_fuids',
                          'resp_filenames', 'resp_mime_types'],
                'types': {'ts': 'timestamp', 'request_body_len': 'int', 'response_body_len': 'int',
                         'status_code': 'int', 'trans_depth': 'int'}
            },
            'dns': {
                'fields': ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
                          'proto', 'trans_id', 'rtt', 'query', 'qclass', 'qclass_name',
                          'qtype', 'qtype_name', 'rcode', 'rcode_name', 'AA', 'TC', 'RD',
                          'RA', 'Z', 'answers', 'TTLs', 'rejected'],
                'types': {'ts': 'timestamp', 'trans_id': 'int', 'rtt': 'float',
                         'qclass': 'int', 'qtype': 'int', 'rcode': 'int'}
            },
            'ssl': {
                'fields': ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
                          'version', 'cipher', 'curve', 'server_name', 'resumed',
                          'last_alert', 'next_protocol', 'established', 'cert_chain_fuids',
                          'client_cert_chain_fuids', 'subject', 'issuer', 'client_subject',
                          'client_issuer', 'validation_status'],
                'types': {'ts': 'timestamp'}
            },
            'weird': {
                'fields': ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
                          'name', 'addl', 'notice', 'peer'],
                'types': {'ts': 'timestamp'}
            },
            'files': {
                'fields': ['ts', 'fuid', 'tx_hosts', 'rx_hosts', 'conn_uids', 'source',
                          'depth', 'analyzers', 'mime_type', 'filename', 'duration',
                          'local_orig', 'is_orig', 'seen_bytes', 'total_bytes',
                          'missing_bytes', 'overflow_bytes', 'timedout', 'parent_fuid',
                          'md5', 'sha1', 'sha256', 'extracted', 'extracted_cutoff',
                          'extracted_size'],
                'types': {'ts': 'timestamp', 'depth': 'int', 'duration': 'float',
                         'seen_bytes': 'int', 'total_bytes': 'int', 'missing_bytes': 'int',
                         'overflow_bytes': 'int', 'extracted_size': 'int'}
            }
        }
    
    def parse_log_file(self, log_file: str, log_type: str = None) -> List[Dict[str, Any]]:
        """Parse a Zeek log file and return structured data"""
        try:
            if not os.path.exists(log_file):
                logger.warning(f"Log file does not exist: {log_file}")
                return []
            
            # Auto-detect log type from filename if not provided
            if not log_type:
                log_type = self._detect_log_type(log_file)
            
            if log_type not in self.log_schemas:
                logger.warning(f"Unknown log type: {log_type}")
                return self._parse_generic_tsv(log_file)
            
            return self._parse_structured_log(log_file, log_type)
            
        except Exception as e:
            logger.error(f"Error parsing log file {log_file}: {e}")
            return []
    
    def _detect_log_type(self, log_file: str) -> str:
        """Detect log type from filename"""
        filename = os.path.basename(log_file)
        
        # Remove common suffixes
        for suffix in ['.log', '.gz', '.bz2']:
            if filename.endswith(suffix):
                filename = filename[:-len(suffix)]
        
        # Check against known types
        for log_type in self.log_schemas.keys():
            if log_type in filename:
                return log_type
        
        return 'unknown'
    
    def _parse_structured_log(self, log_file: str, log_type: str) -> List[Dict[str, Any]]:
        """Parse a structured Zeek log file with known schema"""
        try:
            entries = []
            schema = self.log_schemas[log_type]
            
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                # Skip Zeek header comments
                line_num = 0
                fields = None
                
                for line in f:
                    line_num += 1
                    line = line.strip()
                    
                    # Skip empty lines
                    if not line:
                        continue
                    
                    # Handle Zeek header lines
                    if line.startswith('#'):
                        if line.startswith('#fields'):
                            # Extract field names from header
                            fields = line.split('\t')[1:]  # Remove '#fields' prefix
                            logger.debug(f"Found fields in {log_file}: {fields}")
                        continue
                    
                    # Parse data line
                    if fields:
                        entry = self._parse_data_line(line, fields, schema['types'])
                    else:
                        # Fallback to schema fields if no header found
                        entry = self._parse_data_line(line, schema['fields'], schema['types'])
                    
                    if entry:
                        entry['_log_type'] = log_type
                        entry['_source_file'] = log_file
                        entries.append(entry)
            
            logger.info(f"Parsed {len(entries)} entries from {log_file} ({log_type})")
            return entries
            
        except Exception as e:
            logger.error(f"Error parsing structured log {log_file}: {e}")
            return []
    
    def _parse_data_line(self, line: str, fields: List[str], types: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """Parse a single data line with given fields and types"""
        try:
            values = line.split('\t')
            
            # Handle field count mismatch
            if len(values) != len(fields):
                logger.debug(f"Field count mismatch: got {len(values)}, expected {len(fields)}")
                # Pad with empty values or truncate
                while len(values) < len(fields):
                    values.append('-')
                values = values[:len(fields)]
            
            entry = {}
            
            for i, (field, value) in enumerate(zip(fields, values)):
                # Convert Zeek's '-' to None for missing values
                if value == '-':
                    entry[field] = None
                else:
                    # Apply type conversion
                    field_type = types.get(field, 'string')
                    entry[field] = self._convert_value(value, field_type)
            
            return entry
            
        except Exception as e:
            logger.debug(f"Error parsing data line: {e}")
            return None
    
    def _convert_value(self, value: str, value_type: str) -> Any:
        """Convert string value to appropriate Python type"""
        try:
            if value_type == 'timestamp':
                # Zeek timestamps are Unix epoch with decimals
                return datetime.fromtimestamp(float(value))
            elif value_type == 'int':
                return int(float(value))  # Handle cases like "123.0"
            elif value_type == 'float':
                return float(value)
            elif value_type == 'bool':
                return value.lower() in ('t', 'true', '1', 'yes')
            else:
                return value
        except (ValueError, TypeError):
            # If conversion fails, return original string
            return value
    
    def _parse_generic_tsv(self, log_file: str) -> List[Dict[str, Any]]:
        """Parse a generic TSV file when schema is unknown"""
        try:
            entries = []
            
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f, delimiter='\t')
                
                for row_num, row in enumerate(reader):
                    # Skip header comments
                    if any(key.startswith('#') for key in row.keys()):
                        continue
                    
                    # Clean up the row
                    cleaned_row = {}
                    for key, value in row.items():
                        if key and not key.startswith('#'):
                            cleaned_row[key] = value if value != '-' else None
                    
                    if cleaned_row:
                        cleaned_row['_log_type'] = 'unknown'
                        cleaned_row['_source_file'] = log_file
                        entries.append(cleaned_row)
            
            logger.info(f"Parsed {len(entries)} entries from generic TSV: {log_file}")
            return entries
            
        except Exception as e:
            logger.error(f"Error parsing generic TSV {log_file}: {e}")
            return []
    
    def parse_log_directory(self, log_dir: str) -> Dict[str, List[Dict[str, Any]]]:
        """Parse all Zeek log files in a directory"""
        try:
            if not os.path.exists(log_dir):
                logger.warning(f"Log directory does not exist: {log_dir}")
                return {}
            
            results = {}
            log_files = []
            
            # Find all .log files
            for file_path in Path(log_dir).rglob('*.log'):
                log_files.append(str(file_path))
            
            # Also check for common Zeek log names without extension
            for log_type in self.log_schemas.keys():
                potential_file = os.path.join(log_dir, log_type)
                if os.path.exists(potential_file):
                    log_files.append(potential_file)
            
            logger.info(f"Found {len(log_files)} log files in {log_dir}")
            
            for log_file in log_files:
                log_type = self._detect_log_type(log_file)
                entries = self.parse_log_file(log_file, log_type)
                
                if entries:
                    if log_type not in results:
                        results[log_type] = []
                    results[log_type].extend(entries)
            
            return results
            
        except Exception as e:
            logger.error(f"Error parsing log directory {log_dir}: {e}")
            return {}
    
    def get_latest_entries(self, log_file: str, num_entries: int = 100) -> List[Dict[str, Any]]:
        """Get the latest N entries from a log file (useful for real-time monitoring)"""
        try:
            entries = self.parse_log_file(log_file)
            
            # Sort by timestamp if available
            if entries and 'ts' in entries[0]:
                entries.sort(key=lambda x: x['ts'] if x['ts'] else datetime.min, reverse=True)
            
            return entries[:num_entries]
            
        except Exception as e:
            logger.error(f"Error getting latest entries from {log_file}: {e}")
            return []
    
    def filter_entries_by_time(self, entries: List[Dict[str, Any]], 
                              start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Filter entries by time range"""
        try:
            filtered = []
            
            for entry in entries:
                if 'ts' in entry and entry['ts']:
                    if isinstance(entry['ts'], datetime):
                        if start_time <= entry['ts'] <= end_time:
                            filtered.append(entry)
            
            return filtered
            
        except Exception as e:
            logger.error(f"Error filtering entries by time: {e}")
            return entries
    
    def summarize_log_data(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics for log entries"""
        try:
            if not entries:
                return {}
            
            summary = {
                'total_entries': len(entries),
                'log_types': {},
                'time_range': {},
                'top_sources': {},
                'top_destinations': {},
                'protocols': {},
                'services': {}
            }
            
            timestamps = []
            
            for entry in entries:
                # Count by log type
                log_type = entry.get('_log_type', 'unknown')
                summary['log_types'][log_type] = summary['log_types'].get(log_type, 0) + 1
                
                # Collect timestamps
                if 'ts' in entry and entry['ts']:
                    timestamps.append(entry['ts'])
                
                # Count source IPs
                src_ip = entry.get('id.orig_h')
                if src_ip:
                    summary['top_sources'][src_ip] = summary['top_sources'].get(src_ip, 0) + 1
                
                # Count destination IPs
                dst_ip = entry.get('id.resp_h')
                if dst_ip:
                    summary['top_destinations'][dst_ip] = summary['top_destinations'].get(dst_ip, 0) + 1
                
                # Count protocols
                proto = entry.get('proto')
                if proto:
                    summary['protocols'][proto] = summary['protocols'].get(proto, 0) + 1
                
                # Count services
                service = entry.get('service')
                if service:
                    summary['services'][service] = summary['services'].get(service, 0) + 1
            
            # Calculate time range
            if timestamps:
                summary['time_range'] = {
                    'start': min(timestamps).isoformat(),
                    'end': max(timestamps).isoformat(),
                    'duration_seconds': (max(timestamps) - min(timestamps)).total_seconds()
                }
            
            # Sort top items
            for key in ['top_sources', 'top_destinations', 'protocols', 'services']:
                summary[key] = dict(sorted(summary[key].items(), 
                                         key=lambda x: x[1], reverse=True)[:10])
            
            return summary
            
        except Exception as e:
            logger.error(f"Error summarizing log data: {e}")
            return {}

# Convenience functions for common use cases
def parse_conn_log(log_file: str) -> List[Dict[str, Any]]:
    """Parse a Zeek connection log file"""
    parser = ZeekLogParser()
    return parser.parse_log_file(log_file, 'conn')

def parse_http_log(log_file: str) -> List[Dict[str, Any]]:
    """Parse a Zeek HTTP log file"""
    parser = ZeekLogParser()
    return parser.parse_log_file(log_file, 'http')

def parse_dns_log(log_file: str) -> List[Dict[str, Any]]:
    """Parse a Zeek DNS log file"""
    parser = ZeekLogParser()
    return parser.parse_log_file(log_file, 'dns')

def parse_ssl_log(log_file: str) -> List[Dict[str, Any]]:
    """Parse a Zeek SSL log file"""
    parser = ZeekLogParser()
    return parser.parse_log_file(log_file, 'ssl')

def parse_all_zeek_logs(log_dir: str) -> Dict[str, List[Dict[str, Any]]]:
    """Parse all Zeek logs in a directory"""
    parser = ZeekLogParser()
    return parser.parse_log_directory(log_dir)

if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) > 1:
        log_path = sys.argv[1]
        parser = ZeekLogParser()
        
        if os.path.isfile(log_path):
            # Parse single file
            entries = parser.parse_log_file(log_path)
            print(f"Parsed {len(entries)} entries from {log_path}")
            
            if entries:
                print("Sample entry:")
                print(json.dumps(entries[0], indent=2, default=str))
                
                summary = parser.summarize_log_data(entries)
                print("\nSummary:")
                print(json.dumps(summary, indent=2, default=str))
        
        elif os.path.isdir(log_path):
            # Parse directory
            all_logs = parser.parse_log_directory(log_path)
            
            for log_type, entries in all_logs.items():
                print(f"\n{log_type}: {len(entries)} entries")
                if entries:
                    summary = parser.summarize_log_data(entries)
                    print(json.dumps(summary, indent=2, default=str))
    else:
        print("Usage: python zeek_parser.py <log_file_or_directory>")