import os
from dotenv import load_dotenv
from flask import Flask, render_template, jsonify, request
import requests
from datetime import datetime, timedelta
import json
from collections import defaultdict
import threading
import time

# PostgreSQL imports
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2.pool import ThreadedConnectionPool
import traceback
import sys

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Configuration from environment variables
ELASTICSEARCH_URL = os.getenv('ELASTIC_PATH', '').rstrip('/')  # Remove trailing slash
ES_USERNAME = os.getenv('ELASTIC_USERNAME', '')
ES_PASSWORD = os.getenv('ELASTIC_PASSWORD', '')
ES_AUTH = (ES_USERNAME, ES_PASSWORD) if ES_USERNAME and ES_PASSWORD else None

# PostgreSQL Configuration from environment variables (matching your .env naming)
DATABASE_CONFIG = {
    'host': os.getenv('DATABASE_HOST', 'localhost'),
    'database': os.getenv('DATABASE_NAME', ''),
    'port': int(os.getenv('DATABASE_PORT', '5432')),
    'user': os.getenv('DATABASE_USER_NAME', ''),
    'password': os.getenv('DATABASE_PASSWORD', '')
}

# Flask Configuration
FLASK_HOST = '0.0.0.0'
FLASK_PORT = 5000
FLASK_DEBUG = False

# Database Configuration
DB_TABLE_NAME = 'tCSPMRealTimeScan'
DB_SCHEMA = 'public'

# Elasticsearch Index Patterns - Updated to support individual indices
AWS_INDEX_PREFIX = 'aws_audit_logs_'
GCP_INDEX_PREFIX = 'gcp_audit_logs_'
K8S_AWS_INDEX_PREFIX = 'k8_audit_logs_eks_'
K8S_GCP_INDEX_PREFIX = 'k8_audit_logs_gke_'

# Connection Pool Settings
DB_POOL_MIN_CONN = 2
DB_POOL_MAX_CONN = 10

# Cache and Performance Settings
CACHE_REFRESH_INTERVAL = 180  # seconds
CACHE_EXPIRE_TIME = 600  # seconds
ES_REQUEST_TIMEOUT = 60  # seconds - Increased from 30 to 60 for production

# Default Settings
DEFAULT_TIME_RANGE_DAYS = 1
DEFAULT_CLOUD_PROVIDER = 'aws'

# Limits and Thresholds
MAX_ACCOUNTS_SIZE = 1000
MAX_DETECTION_TYPES_SIZE = 20
MAX_DETECTION_TYPES_GLOBAL = 100
MAX_TIME_RANGE_DAYS = 90

# Production Performance Settings
MAX_CONCURRENT_QUERIES = 5  # Limit concurrent Elasticsearch queries
QUERY_RETRY_ATTEMPTS = 2  # Number of retry attempts for failed queries
QUERY_RETRY_DELAY = 1  # Delay between retries in seconds
TIMEOUT_BUFFER_MULTIPLIER = 1.5  # Multiply timeout by this factor for safety

# Global variables
pg_pool = None
schema_mapping = {}  # environment_id -> schema_name
reverse_mapping = {}  # schema_name -> [environment_ids]
cached_data = {}
last_update = None

def normalize_elasticsearch_url(base_url):
    """Normalize Elasticsearch URL to prevent double slashes"""
    return base_url.rstrip('/')

def build_elasticsearch_url(indices):
    """Build proper Elasticsearch URL with index pattern or comma-separated indices"""
    normalized_base = normalize_elasticsearch_url(ELASTICSEARCH_URL)
    return f"{normalized_base}/{indices}/_search"

def initialize_db_pool():
    """Initialize PostgreSQL connection pool"""
    global pg_pool
    try:
        pg_pool = ThreadedConnectionPool(
            minconn=DB_POOL_MIN_CONN,
            maxconn=DB_POOL_MAX_CONN,
            **DATABASE_CONFIG
        )
        return True
    except Exception as e:
        print(f"Error initializing PostgreSQL connection pool: {e}")
        return False

def get_db_connection():
    """Get connection from pool"""
    if pg_pool:
        return pg_pool.getconn()
    return None

def return_db_connection(conn):
    """Return connection to pool"""
    if pg_pool and conn:
        pg_pool.putconn(conn)

def load_schema_mapping_from_db():
    """Load schema-environment mapping from PostgreSQL database with reverse mapping"""
    global schema_mapping, reverse_mapping
    
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return False
        
        # Query to get schema_name and environment_id from configured table
        query = f"""
        SELECT DISTINCT schema_name, environment_id 
        FROM {DB_SCHEMA}."{DB_TABLE_NAME}" 
        WHERE schema_name IS NOT NULL 
        AND environment_id IS NOT NULL
        ORDER BY schema_name, environment_id;
        """
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(query)
            results = cursor.fetchall()
            
            if not results:
                return False
            
            # Clear existing mappings
            schema_mapping.clear()
            reverse_mapping.clear()
            
            # Process results
            temp_reverse_mapping = defaultdict(list)
            
            for row in results:
                schema_name = str(row['schema_name']).strip()
                environment_id = str(row['environment_id']).strip()
                
                # Skip empty values
                if not schema_name or not environment_id or schema_name.lower() in ['null', 'none'] or environment_id.lower() in ['null', 'none']:
                    continue
                
                # Create forward mapping (environment_id -> schema_name)
                schema_mapping[environment_id] = schema_name
                
                # Create reverse mapping (schema_name -> [environment_ids])
                temp_reverse_mapping[schema_name].append(environment_id)
            
            # Convert to regular dict
            reverse_mapping = dict(temp_reverse_mapping)
            
            return True
            
    except psycopg2.Error as e:
        return False
    except Exception as e:
        return False
    finally:
        if conn:
            return_db_connection(conn)

def test_db_connection():
    """Test database connection and table accessibility"""
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return False, "Could not establish database connection"
        
        # Test basic connection
        with conn.cursor() as cursor:
            cursor.execute("SELECT version();")
            version = cursor.fetchone()
        
        # Test table access
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(f"""
                SELECT COUNT(*) as total_records,
                       COUNT(DISTINCT schema_name) as unique_schemas,
                       COUNT(DISTINCT environment_id) as unique_environments
                FROM {DB_SCHEMA}."{DB_TABLE_NAME}" 
                WHERE schema_name IS NOT NULL 
                AND environment_id IS NOT NULL;
            """)
            stats = cursor.fetchone()
        
        return True, "Database connection and table access successful"
        
    except psycopg2.Error as e:
        error_msg = f"PostgreSQL error: {e}"
        return False, error_msg
    except Exception as e:
        error_msg = f"Database test error: {e}"
        return False, error_msg
    finally:
        if conn:
            return_db_connection(conn)

def query_elasticsearch(query_body, indices, retry_attempts=QUERY_RETRY_ATTEMPTS):
    """Execute Elasticsearch query with proper URL handling and retry logic"""
    for attempt in range(retry_attempts + 1):
        try:
            # Use the new URL building function to prevent double slashes
            url = build_elasticsearch_url(indices)
            headers = {'Content-Type': 'application/json'}
            
            # Calculate timeout with buffer for production safety
            timeout = int(ES_REQUEST_TIMEOUT * TIMEOUT_BUFFER_MULTIPLIER)
            
            response = requests.post(
                url, 
                json=query_body, 
                auth=ES_AUTH, 
                headers=headers,
                timeout=timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                return result, None
            else:
                error_msg = f"ES Query failed: {response.status_code} - {response.text[:200]}"
                if attempt < retry_attempts:
                    time.sleep(QUERY_RETRY_DELAY)
                    continue
                return None, error_msg
        except requests.exceptions.Timeout as e:
            error_msg = f"ES Query timeout after {timeout}s (attempt {attempt + 1}/{retry_attempts + 1})"
            if attempt < retry_attempts:
                time.sleep(QUERY_RETRY_DELAY)
                continue
            return None, error_msg
        except Exception as e:
            error_msg = f"ES Connection error: {str(e)}"
            if attempt < retry_attempts:
                time.sleep(QUERY_RETRY_DELAY)
                continue
            return None, error_msg
    
    return None, "Max retry attempts exceeded"

def check_index_exists(index_name):
    """Check if an Elasticsearch index exists"""
    try:
        url = f"{normalize_elasticsearch_url(ELASTICSEARCH_URL)}/{index_name}"
        response = requests.head(url, auth=ES_AUTH, timeout=10)
        return response.status_code == 200
    except Exception:
        return False

def check_kubernetes_indices_exist(environment_id, cloud_provider):
    """Check if Kubernetes indices exist for a given environment ID using wildcard pattern"""
    try:
        # Build wildcard pattern
        if cloud_provider.lower() == "gcp":
            index_pattern = f"{K8S_GCP_INDEX_PREFIX}{environment_id}_*"
        else:
            index_pattern = f"{K8S_AWS_INDEX_PREFIX}{environment_id}_*"
        
        # Use _cat/indices to check if any indices match the pattern
        url = f"{normalize_elasticsearch_url(ELASTICSEARCH_URL)}/_cat/indices/{index_pattern}?format=json"
        response = requests.get(url, auth=ES_AUTH, timeout=15)
        
        if response.status_code == 200:
            indices = response.json()
            # Return True if any indices match the pattern
            return len(indices) > 0
        else:
            # If the API call fails, try a simple search to see if any data exists
            simple_query = {
                "size": 0,
                "query": {
                    "match_all": {}
                }
            }
            
            result, error = query_elasticsearch(simple_query, index_pattern)
            if result and 'hits' in result and 'total' in result['hits']:
                total = result['hits']['total']
                if isinstance(total, dict):
                    return total.get('value', 0) > 0
                else:
                    return total > 0
            
            return False
    except Exception:
        # If all else fails, try a simple search
        try:
            simple_query = {
                "size": 0,
                "query": {
                    "match_all": {}
                }
            }
            
            result, error = query_elasticsearch(simple_query, index_pattern)
            if result and 'hits' in result and 'total' in result['hits']:
                total = result['hits']['total']
                if isinstance(total, dict):
                    return total.get('value', 0) > 0
                else:
                    return total > 0
        except:
            pass
        
        return False

def query_individual_account_anomalies(environment_id, cloud_provider, days):
    """Query anomalies for a specific environment ID with optimized memory usage"""
    
    # Build specific index name based on cloud provider
    if cloud_provider.lower() == "gcp":
        index_name = f"{GCP_INDEX_PREFIX}{environment_id}"
    else:
        index_name = f"{AWS_INDEX_PREFIX}{environment_id}"
    
    # First check if index exists to avoid 404 errors
    if not check_index_exists(index_name):
        return {
            "environment_id": environment_id,
            "index_name": index_name,
            "total": 0,
            "daily": {},
            "detections": {},
            "error": f"Index {index_name} does not exist",
            "status": "index_not_found"
        }
    
    time_range = "now/d" if days == 1 else f"now-{days}d"
    
    # OPTIMIZED Query to avoid circuit breaker - using doc_count instead of _id aggregation
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "eventTime": {
                                "gte": time_range,
                                "lte": "now",
                                "time_zone": "UTC"
                            }
                        }
                    },
                    {
                        "term": {
                            "baseline": False
                        }
                    },
                    {
                        "exists": {
                            "field": "detection"
                        }
                    }
                ],
                "must_not": [
                    {
                        "terms": {
                            "detection.keyword": [
                                "NORMAL_EVENT",
                                "LEARNING"
                            ]
                        }
                    }
                ]
            }
        },
        "aggs": {
            "detection_breakdown": {
                "terms": {
                    "field": "detection.keyword",
                    "size": MAX_DETECTION_TYPES_SIZE,
                    "execution_hint": "map"  # Memory optimization
                }
            },
            "daily_breakdown": {
                "date_histogram": {
                    "field": "eventTime",
                    "calendar_interval": "1d",
                    "time_zone": "UTC",
                    "format": "yyyy-MM-dd",
                    "min_doc_count": 0
                }
            }
        },
        # Add timeout and memory optimizations
        "timeout": "30s",
        "_source": False  # Don't return document source to save memory
    }
    
    result, error = query_elasticsearch(query, index_name)
    
    if error:
        # Handle specific error types
        error_type = "unknown"
        if "CircuitBreakingException" in error:
            error_type = "circuit_breaker"
        elif "index_not_found" in error:
            error_type = "index_not_found"
        elif "timeout" in error.lower():
            error_type = "timeout"
        
        return {
            "environment_id": environment_id,
            "index_name": index_name,
            "total": 0,
            "daily": {},
            "detections": {},
            "error": error,
            "status": error_type
        }
    
    # Process results
    account_data = {
        "environment_id": environment_id,
        "index_name": index_name,
        "total": 0,
        "daily": {},
        "detections": {},
        "status": "success"
    }
    
    if result and 'aggregations' in result:
        # Calculate total from daily breakdown to avoid _id aggregation
        total_count = 0
        daily_buckets = result['aggregations']['daily_breakdown']['buckets']
        for bucket in daily_buckets:
            date_key = bucket['key_as_string']
            daily_count = bucket['doc_count']
            account_data["daily"][date_key] = daily_count
            total_count += daily_count
        
        account_data["total"] = total_count
        
        # Process detection breakdown
        detection_buckets = result['aggregations']['detection_breakdown']['buckets']
        for bucket in detection_buckets:
            detection_type = bucket['key']
            account_data["detections"][detection_type] = bucket['doc_count']
    
    return account_data

def query_individual_account_total_events(environment_id, cloud_provider, days):
    """Query total events (not just anomalies) for a specific environment ID"""
    
    # Build specific index name based on cloud provider
    if cloud_provider.lower() == "gcp":
        index_name = f"{GCP_INDEX_PREFIX}{environment_id}"
    else:
        index_name = f"{AWS_INDEX_PREFIX}{environment_id}"
    
    # First check if index exists to avoid 404 errors
    if not check_index_exists(index_name):
        return {
            "environment_id": environment_id,
            "index_name": index_name,
            "total": 0,
            "daily": {},
            "detections": {},
            "error": f"Index {index_name} does not exist",
            "status": "index_not_found"
        }
    
    time_range = "now/d" if days == 1 else f"now-{days}d"
    
    # Query for ALL events (not just anomalies)
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "eventTime": {
                                "gte": time_range,
                                "lte": "now",
                                "time_zone": "UTC"
                            }
                        }
                    }
                ]
            }
        },
        "aggs": {
            "detection_breakdown": {
                "terms": {
                    "field": "detection.keyword",
                    "size": MAX_DETECTION_TYPES_SIZE,
                    "execution_hint": "map"
                }
            },
            "daily_breakdown": {
                "date_histogram": {
                    "field": "eventTime",
                    "calendar_interval": "1d",
                    "time_zone": "UTC",
                    "format": "yyyy-MM-dd",
                    "min_doc_count": 0
                }
            }
        },
        "timeout": "30s",
        "_source": False
    }
    
    result, error = query_elasticsearch(query, index_name)
    
    if error:
        # Handle specific error types
        error_type = "unknown"
        if "CircuitBreakingException" in error:
            error_type = "circuit_breaker"
        elif "index_not_found" in error:
            error_type = "index_not_found"
        elif "timeout" in error.lower():
            error_type = "timeout"
        
        return {
            "environment_id": environment_id,
            "index_name": index_name,
            "total": 0,
            "daily": {},
            "detections": {},
            "error": error,
            "status": error_type
        }
    
    # Process results
    account_data = {
        "environment_id": environment_id,
        "index_name": index_name,
        "total": 0,
        "daily": {},
        "detections": {},
        "status": "success"
    }
    
    if result and 'aggregations' in result:
        # Calculate total from daily breakdown
        total_count = 0
        daily_buckets = result['aggregations']['daily_breakdown']['buckets']
        for bucket in daily_buckets:
            date_key = bucket['key_as_string']
            daily_count = bucket['doc_count']
            account_data["daily"][date_key] = daily_count
            total_count += daily_count
        
        account_data["total"] = total_count
        
        # Process detection breakdown
        detection_buckets = result['aggregations']['detection_breakdown']['buckets']
        for bucket in detection_buckets:
            detection_type = bucket['key']
            account_data["detections"][detection_type] = bucket['doc_count']
    
    return account_data

def inspect_kubernetes_data_structure(environment_id, cloud_provider):
    """Inspect the structure of Kubernetes data to determine available fields"""
    try:
        # Build wildcard pattern for Kubernetes indices
        if cloud_provider.lower() == "gcp":
            index_pattern = f"{K8S_GCP_INDEX_PREFIX}{environment_id}_*"
        else:
            index_pattern = f"{K8S_AWS_INDEX_PREFIX}{environment_id}_*"
        
        # Simple query to get a sample document
        query = {
            "size": 1,
            "query": {
                "match_all": {}
            },
            "sort": [
                {
                    "eventTime": {
                        "order": "desc"
                    }
                }
            ]
        }
        
        result, error = query_elasticsearch(query, index_pattern)
        
        if error or not result or 'hits' not in result or 'hits' not in result['hits']:
            return None
        
        # Get the first document
        if result['hits']['hits']:
            sample_doc = result['hits']['hits'][0]['_source']
            return sample_doc
        
        return None
        
    except Exception:
        return None

def query_individual_account_kubernetes_anomalies(environment_id, cloud_provider, days):
    """Query Kubernetes anomaly events for a specific environment ID"""
    
    # Build wildcard pattern for Kubernetes indices
    if cloud_provider.lower() == "gcp":
        index_pattern = f"{K8S_GCP_INDEX_PREFIX}{environment_id}_*"
    else:
        index_pattern = f"{K8S_AWS_INDEX_PREFIX}{environment_id}_*"
    
    # First check if any Kubernetes indices exist for this environment
    if not check_kubernetes_indices_exist(environment_id, cloud_provider):
        return {
            "environment_id": environment_id,
            "index_pattern": index_pattern,
            "total": 0,
            "daily": {},
            "detections": {},
            "error": f"No Kubernetes indices found for pattern {index_pattern}",
            "status": "index_not_found"
        }
    
    # Inspect data structure to determine available fields
    sample_doc = inspect_kubernetes_data_structure(environment_id, cloud_provider)
    
    # Use the exact time range requested by the user
    time_range = "now/d" if days == 1 else f"now-{days}d"
    
    # Build query based on available fields
    must_conditions = [
        {
            "range": {
                "eventTime": {
                    "gte": time_range,
                    "lte": "now",
                    "time_zone": "UTC"
                }
            }
        }
    ]
    
    # Only add baseline and detection filters if these fields exist
    if sample_doc:
        if 'baseline' in sample_doc:
            must_conditions.append({
                "term": {
                    "baseline": False
                }
            })
        
        if 'detection' in sample_doc:
            must_conditions.append({
                "exists": {
                    "field": "detection"
                }
            })
    
    # Build the query
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": must_conditions
            }
        },
        "aggs": {
            "daily_breakdown": {
                "date_histogram": {
                    "field": "eventTime",
                    "calendar_interval": "1d",
                    "time_zone": "UTC",
                    "format": "yyyy-MM-dd",
                    "min_doc_count": 0
                }
            }
        },
        "timeout": "30s",
        "_source": False
    }
    
    # Add detection breakdown aggregation only if detection field exists
    if sample_doc and 'detection' in sample_doc:
        query["aggs"]["detection_breakdown"] = {
            "terms": {
                "field": "detection.keyword",
                "size": MAX_DETECTION_TYPES_SIZE,
                "execution_hint": "map"
            }
        }
    
    result, error = query_elasticsearch(query, index_pattern)
    
    if error:
        # Handle specific error types
        error_type = "unknown"
        if "CircuitBreakingException" in error:
            error_type = "circuit_breaker"
        elif "index_not_found" in error:
            error_type = "index_not_found"
        elif "timeout" in error.lower():
            error_type = "timeout"
        
        return {
            "environment_id": environment_id,
            "index_pattern": index_pattern,
            "total": 0,
            "daily": {},
            "detections": {},
            "error": error,
            "status": error_type
        }
    
    # Process results
    account_data = {
        "environment_id": environment_id,
        "index_pattern": index_pattern,
        "total": 0,
        "daily": {},
        "detections": {},
        "status": "success"
    }
    
    if result and 'aggregations' in result:
        # Calculate total from daily breakdown
        total_count = 0
        daily_buckets = result['aggregations']['daily_breakdown']['buckets']
        for bucket in daily_buckets:
            date_key = bucket['key_as_string']
            daily_count = bucket['doc_count']
            account_data["daily"][date_key] = daily_count
            total_count += daily_count
        
        account_data["total"] = total_count
        
        # Process detection breakdown if available
        if 'detection_breakdown' in result['aggregations']:
            detection_buckets = result['aggregations']['detection_breakdown']['buckets']
            for bucket in detection_buckets:
                detection_type = bucket['key']
                account_data["detections"][detection_type] = bucket['doc_count']
    
    return account_data

def query_individual_account_kubernetes_total_events(environment_id, cloud_provider, days):
    """Query Kubernetes total events for a specific environment ID"""
    
    # Build wildcard pattern for Kubernetes indices
    if cloud_provider.lower() == "gcp":
        index_pattern = f"{K8S_GCP_INDEX_PREFIX}{environment_id}_*"
    else:
        index_pattern = f"{K8S_AWS_INDEX_PREFIX}{environment_id}_*"
    
    # First check if any Kubernetes indices exist for this environment
    if not check_kubernetes_indices_exist(environment_id, cloud_provider):
        return {
            "environment_id": environment_id,
            "index_pattern": index_pattern,
            "total": 0,
            "daily": {},
            "detections": {},
            "error": f"No Kubernetes indices found for pattern {index_pattern}",
            "status": "index_not_found"
        }
    
    # Inspect data structure to determine available fields
    sample_doc = inspect_kubernetes_data_structure(environment_id, cloud_provider)
    
    # Use the exact time range requested by the user
    time_range = "now/d" if days == 1 else f"now-{days}d"
    
    # Query for ALL Kubernetes events (not just anomalies)
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "eventTime": {
                                "gte": time_range,
                                "lte": "now",
                                "time_zone": "UTC"
                            }
                        }
                    }
                ]
            }
        },
        "aggs": {
            "daily_breakdown": {
                "date_histogram": {
                    "field": "eventTime",
                    "calendar_interval": "1d",
                    "time_zone": "UTC",
                    "format": "yyyy-MM-dd",
                    "min_doc_count": 0
                }
            }
        },
        "timeout": "30s",
        "_source": False
    }
    
    # Add detection breakdown aggregation only if detection field exists
    if sample_doc and 'detection' in sample_doc:
        query["aggs"]["detection_breakdown"] = {
            "terms": {
                "field": "detection.keyword",
                "size": MAX_DETECTION_TYPES_SIZE,
                "execution_hint": "map"
            }
        }
    
    result, error = query_elasticsearch(query, index_pattern)
    
    if error:
        # Handle specific error types
        error_type = "unknown"
        if "CircuitBreakingException" in error:
            error_type = "circuit_breaker"
        elif "index_not_found" in error:
            error_type = "index_not_found"
        elif "timeout" in error.lower():
            error_type = "timeout"
        
        return {
            "environment_id": environment_id,
            "index_pattern": index_pattern,
            "total": 0,
            "daily": {},
            "detections": {},
            "error": error,
            "status": error_type
        }
    
    # Process results
    account_data = {
        "environment_id": environment_id,
        "index_pattern": index_pattern,
        "total": 0,
        "daily": {},
        "detections": {},
        "status": "success"
    }
    
    if result and 'aggregations' in result:
        # Calculate total from daily breakdown
        total_count = 0
        daily_buckets = result['aggregations']['daily_breakdown']['buckets']
        for bucket in daily_buckets:
            date_key = bucket['key_as_string']
            daily_count = bucket['doc_count']
            account_data["daily"][date_key] = daily_count
            total_count += daily_count
        
        account_data["total"] = total_count
        
        # Process detection breakdown if available
        if 'detection_breakdown' in result['aggregations']:
            detection_buckets = result['aggregations']['detection_breakdown']['buckets']
            for bucket in detection_buckets:
                detection_type = bucket['key']
                account_data["detections"][detection_type] = bucket['doc_count']
    
    return account_data

def get_anomalous_events_by_timerange(days=None, cloud_provider=None):
    """Get anomalous events for specified time range by querying individual account indices"""
    # Use the new unified function for backward compatibility
    return get_events_by_timerange(days=days, cloud_provider=cloud_provider, event_type='anomaly')

def filter_tenants_by_onboarding_date(environment_ids, days_back):
    """Filter environment IDs based on onboarding date to avoid showing data for recently onboarded tenants"""
    if days_back <= 7:  # For recent data, don't filter
        return environment_ids
    
    # For longer time ranges, we could implement date-based filtering
    # For now, return all environment IDs as the current logic doesn't have onboarding dates
    # TODO: Implement proper onboarding date filtering when that data is available
    return environment_ids

def get_events_by_timerange(days=None, cloud_provider=None, event_type='anomaly', kubernetes_enabled=False):
    """Get events (anomaly or total) for specified time range by querying individual account indices"""
    
    # Use defaults if not provided
    if days is None:
        days = DEFAULT_TIME_RANGE_DAYS
    if cloud_provider is None:
        cloud_provider = DEFAULT_CLOUD_PROVIDER
    
    # Validate event_type parameter
    if event_type not in ['anomaly', 'total']:
        event_type = 'anomaly'  # Default to anomaly if invalid
    
    # Get all environment IDs from database
    environment_ids = list(schema_mapping.keys()) if schema_mapping else []
    
    if not environment_ids:
        return {
            "tenants": {},
            "accounts": {},
            "daily_totals": {},
            "timerange_days": days,
            "cloud_provider": cloud_provider,
            "event_type": event_type,
            "kubernetes_enabled": kubernetes_enabled,
            "summary": {"total_tenants": 0, "total_accounts": 0, "total_events": 0},
            "error": "No environment IDs found in database"
        }
    
    # Filter environment IDs based on onboarding date
    filtered_environment_ids = filter_tenants_by_onboarding_date(environment_ids, days)
    
    # Query each environment ID individually with error handling and retry logic
    all_account_results = []
    successful_queries = 0
    failed_queries = {"circuit_breaker": 0, "index_not_found": 0, "timeout": 0, "other": 0}
    
    # Process queries with limited concurrency to avoid overwhelming Elasticsearch
    import concurrent.futures
    
    def query_single_account(env_id):
        try:
            # Choose the appropriate query function based on kubernetes_enabled and event_type
            if kubernetes_enabled:
                if event_type == 'anomaly':
                    account_result = query_individual_account_kubernetes_anomalies(env_id, cloud_provider, days)
                else:  # event_type == 'total'
                    account_result = query_individual_account_kubernetes_total_events(env_id, cloud_provider, days)
            else:
                if event_type == 'anomaly':
                    account_result = query_individual_account_anomalies(env_id, cloud_provider, days)
                else:  # event_type == 'total'
                    account_result = query_individual_account_total_events(env_id, cloud_provider, days)
            
            return account_result
        except Exception as e:
            return {
                "environment_id": env_id,
                "total": 0,
                "daily": {},
                "detections": {},
                "error": str(e),
                "status": "exception"
            }
    
    # Use ThreadPoolExecutor to limit concurrent queries
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONCURRENT_QUERIES) as executor:
        # Submit all queries
        future_to_env_id = {executor.submit(query_single_account, env_id): env_id for env_id in filtered_environment_ids}
        
        # Collect results as they complete
        for future in concurrent.futures.as_completed(future_to_env_id, timeout=ES_REQUEST_TIMEOUT * 2):
            try:
                account_result = future.result()
                all_account_results.append(account_result)
                
                status = account_result.get("status", "unknown")
                
                if account_result["total"] > 0:
                    successful_queries += 1
                elif status == "index_not_found":
                    failed_queries["index_not_found"] += 1
                elif status == "circuit_breaker":
                    failed_queries["circuit_breaker"] += 1
                elif status == "timeout":
                    failed_queries["timeout"] += 1
                else:
                    if status != "success":
                        failed_queries["other"] += 1
                        
            except concurrent.futures.TimeoutError:
                env_id = future_to_env_id[future]
                all_account_results.append({
                    "environment_id": env_id,
                    "total": 0,
                    "daily": {},
                    "detections": {},
                    "error": "Query timeout",
                    "status": "timeout"
                })
                failed_queries["timeout"] += 1
            except Exception as e:
                env_id = future_to_env_id[future]
                all_account_results.append({
                    "environment_id": env_id,
                    "total": 0,
                    "daily": {},
                    "detections": {},
                    "error": str(e),
                    "status": "exception"
                })
                failed_queries["other"] += 1
    
    # Aggregate results by tenant
    tenant_data = {}
    account_data = defaultdict(lambda: {
        "total": 0, 
        "daily": {}, 
        "detections": {},
        "tenant": "",
        "account_id": ""
    })
    daily_totals = defaultdict(int)
    
    for account_result in all_account_results:
        environment_id = account_result["environment_id"]
        
        # Get tenant name from mapping
        tenant_name = schema_mapping.get(environment_id, f"unknown_tenant_{environment_id}")
        
        # Update account-level data
        account_key = f"{tenant_name}|{environment_id}"
        account_data[account_key]["total"] = account_result["total"]
        account_data[account_key]["tenant"] = tenant_name
        account_data[account_key]["account_id"] = environment_id
        account_data[account_key]["daily"] = account_result["daily"].copy()
        account_data[account_key]["detections"] = account_result["detections"].copy()
        
        # Initialize tenant data if not exists
        if tenant_name not in tenant_data:
            tenant_data[tenant_name] = {
                "total": 0,
                "daily": {},
                "detections": {},
                "accounts": {}
            }
        
        # Update tenant-level data (aggregate from accounts)
        tenant_data[tenant_name]["total"] += account_result["total"]
        
        # Store account details under tenant
        tenant_data[tenant_name]["accounts"][environment_id] = {
            "total": account_result["total"],
            "daily": account_result["daily"].copy(),
            "detections": account_result["detections"].copy()
        }
        
        # Aggregate daily data at tenant level
        for date_key, daily_count in account_result["daily"].items():
            if date_key not in tenant_data[tenant_name]["daily"]:
                tenant_data[tenant_name]["daily"][date_key] = 0
            tenant_data[tenant_name]["daily"][date_key] += daily_count
            
            # Global daily totals
            daily_totals[date_key] += daily_count
        
        # Aggregate detection types at tenant level
        for detection_type, detection_count in account_result["detections"].items():
            if detection_type not in tenant_data[tenant_name]["detections"]:
                tenant_data[tenant_name]["detections"][detection_type] = 0
            tenant_data[tenant_name]["detections"][detection_type] += detection_count
    
    # Filter results based on cloud provider
    valid_accounts_for_provider = set()
    invalid_accounts_for_provider = set()
    
    for account_result in all_account_results:
        environment_id = account_result["environment_id"]
        status = account_result.get("status", "unknown")
        
        if status == "index_not_found":
            invalid_accounts_for_provider.add(environment_id)
        else:
            valid_accounts_for_provider.add(environment_id)
    
    # Filter tenants - only include tenants that have at least one valid account for selected provider
    filtered_tenant_data = {}
    filtered_account_data = {}
    
    for tenant_name, env_ids in reverse_mapping.items():
        # Check if this tenant has any valid accounts for the selected cloud provider
        tenant_valid_accounts = [env_id for env_id in env_ids if env_id in valid_accounts_for_provider]
        
        if tenant_valid_accounts:
            # This tenant has at least one account in the selected cloud provider
            if tenant_name in tenant_data:
                filtered_tenant_data[tenant_name] = tenant_data[tenant_name]
            else:
                filtered_tenant_data[tenant_name] = {
                    "total": 0,
                    "daily": {},
                    "detections": {},
                    "accounts": {}
                }
            
            # Add all valid accounts for this tenant
            for env_id in env_ids:
                if env_id in valid_accounts_for_provider:
                    if env_id not in filtered_tenant_data[tenant_name]["accounts"]:
                        filtered_tenant_data[tenant_name]["accounts"][env_id] = {
                            "total": 0,
                            "daily": {},
                            "detections": {}
                        }
                    
                    account_key = f"{tenant_name}|{env_id}"
                    if account_key not in filtered_account_data:
                        filtered_account_data[account_key] = {
                            "total": 0,
                            "daily": {},
                            "detections": {},
                            "tenant": tenant_name,
                            "account_id": env_id
                        }
    
    # Copy existing account data to filtered data
    for account_key, account_info in account_data.items():
        if account_key in filtered_account_data:
            filtered_account_data[account_key] = account_info
    
    # Update the final data structures
    tenant_data = filtered_tenant_data
    account_data = filtered_account_data
    
    return {
        "tenants": dict(tenant_data),
        "accounts": dict(account_data),
        "daily_totals": dict(daily_totals),
        "timerange_days": days,
        "cloud_provider": cloud_provider,
        "event_type": event_type,
        "kubernetes_enabled": kubernetes_enabled,
        "summary": {
            "total_tenants": len(tenant_data),
            "total_accounts": len(account_data),
            "total_events": sum(t['total'] for t in tenant_data.values()),
            "successful_queries": successful_queries,
            "total_queries": len(filtered_environment_ids),
            "failed_queries": failed_queries,
            "data_consistency": {
                "tenant_account_mismatch": len(tenant_data) - len([t for t in tenant_data.values() if t.get('accounts')]),
                "account_tenant_mismatch": len(account_data) - len([a for a in account_data.values() if a.get('tenant')]),
                "daily_totals_consistency": sum(daily_totals.values()) == sum(t['total'] for t in tenant_data.values())
            },
            "cloud_provider_filtering": {
                "selected_provider": cloud_provider,
                "valid_accounts": len([env_id for env_id in filtered_environment_ids if any(
                    result["environment_id"] == env_id and result.get("status") != "index_not_found" 
                    for result in all_account_results
                )]),
                "invalid_accounts": len([env_id for env_id in filtered_environment_ids if any(
                    result["environment_id"] == env_id and result.get("status") == "index_not_found" 
                    for result in all_account_results
                )]),
                "tenants_included": len(tenant_data),
                "tenants_excluded": len(reverse_mapping) - len(tenant_data)
            },
            "performance_metrics": {
                "query_time_ms": int((datetime.now() - datetime.now()).total_seconds() * 1000),  # Placeholder for actual timing
                "memory_usage_mb": 0,  # Placeholder for actual memory usage
                "cache_hit_rate": 0.0  # Placeholder for cache metrics
            }
        }
    }

def update_cache(default_days=None, cloud_provider=None, event_type='anomaly', kubernetes_enabled=False):
    """Update cached data with specified day span including tenant and account breakdown"""
    global cached_data, last_update
    
    # Use defaults if not provided
    if default_days is None:
        default_days = DEFAULT_TIME_RANGE_DAYS
    if cloud_provider is None:
        cloud_provider = DEFAULT_CLOUD_PROVIDER
    if event_type is None:
        event_type = 'anomaly'
    
    try:
        # Get data with enhanced breakdown
        timerange_data = get_events_by_timerange(days=default_days, cloud_provider=cloud_provider, event_type=event_type, kubernetes_enabled=kubernetes_enabled)
        
        # Check if we got a connection error
        if isinstance(timerange_data, dict) and timerange_data.get("error"):
            error_message = timerange_data.get("error", "Unknown error")
            cached_data = {
                'tenants': {},
                'accounts': {},
                'daily_totals': {},
                'today_tenants': {},
                'today_accounts': {},
                'today': {},
                'selected_day_tenants': {},
                'selected_day_accounts': {},
                'summary': {'total_tenants': 0, 'total_accounts': 0, 'total_events': 0},
                'last_updated': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'total_events': 0,
                'total_events_today': 0,
                'total_events_selected': 0,
                'total_tenants': 0,
                'total_accounts': 0,
                'active_tenants': 0,
                'active_tenants_today': 0,
                'active_tenants_selected': 0,
                'active_accounts': 0,
                'active_accounts_today': 0,
                'active_accounts_selected': 0,
                'status': 'error',
                'error_message': error_message,
                'timerange_days': default_days,
                'cloud_provider': cloud_provider,
                'event_type': event_type
            }
            last_update = datetime.now()
            return
        
        # Get today's data for compatibility
        today_date = datetime.now().strftime("%Y-%m-%d")
        today_tenant_data = {}
        today_account_data = {}
        
        if "tenants" in timerange_data:
            for tenant, data in timerange_data["tenants"].items():
                # Get today's count from daily breakdown
                today_count = data["daily"].get(today_date, 0)
                today_tenant_data[tenant] = today_count
                
                # Get today's account data
                for account_id, account_data in data.get("accounts", {}).items():
                    today_account_count = account_data["daily"].get(today_date, 0)
                    account_key = f"{tenant}|{account_id}"
                    today_account_data[account_key] = today_account_count
        
        # Calculate summary stats
        summary = timerange_data.get("summary", {})
        total_events_timerange = summary.get("total_events", 0)
        total_tenants = summary.get("total_tenants", 0)
        total_accounts = summary.get("total_accounts", 0)
        
        total_events_today = sum(today_tenant_data.values())
        active_tenants_timerange = len([t for t in timerange_data.get("tenants", {}).values() if t['total'] > 0])
        active_tenants_today = len([count for count in today_tenant_data.values() if count > 0])
        active_accounts_timerange = len([a for a in timerange_data.get("accounts", {}).values() if a['total'] > 0])
        active_accounts_today = len([count for count in today_account_data.values() if count > 0])
        
        cached_data = {
            'tenants': timerange_data.get("tenants", {}),
            'accounts': timerange_data.get("accounts", {}),
            'daily_totals': timerange_data.get("daily_totals", {}),
            'today_tenants': today_tenant_data,
            'today_accounts': today_account_data,
            'today': today_tenant_data,  # For backward compatibility
            'selected_day_tenants': today_tenant_data,  # Initialize with today's data
            'selected_day_accounts': today_account_data,  # Initialize with today's data
            'summary': summary,
            'last_updated': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'total_events': total_events_timerange,
            'total_events_today': total_events_today,
            'total_events_selected': total_events_today,  # Initialize with today's data
            'total_tenants': total_tenants,
            'total_accounts': total_accounts,
            'active_tenants': active_tenants_timerange,
            'active_tenants_today': active_tenants_today,
            'active_tenants_selected': active_tenants_today,  # Initialize with today's data
            'active_accounts': active_accounts_timerange,
            'active_accounts_today': active_accounts_today,
            'active_accounts_selected': active_accounts_today,  # Initialize with today's data
            'active_schemas': active_tenants_timerange,  # For backward compatibility
            'active_schemas_today': active_tenants_today,  # For backward compatibility
            'timerange_days': default_days,
            'cloud_provider': cloud_provider,
            'event_type': event_type,
            'status': 'success'
        }
        
        last_update = datetime.now()
        
    except Exception as e:
        cached_data = {
            'tenants': {},
            'accounts': {},
            'daily_totals': {},
            'today_tenants': {},
            'today_accounts': {},
            'today': {},
            'selected_day_tenants': {},
            'selected_day_accounts': {},
            'summary': {'total_tenants': 0, 'total_accounts': 0, 'total_events': 0},
            'last_updated': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'total_events': 0,
            'total_events_today': 0,
            'total_events_selected': 0,
            'active_tenants': 0,
            'active_tenants_today': 0,
            'active_tenants_selected': 0,
            'active_accounts': 0,
            'active_accounts_today': 0,
            'active_accounts_selected': 0,
            'status': 'error',
            'error_message': str(e),
            'timerange_days': default_days or DEFAULT_TIME_RANGE_DAYS,
            'cloud_provider': cloud_provider or DEFAULT_CLOUD_PROVIDER,
            'event_type': event_type or 'anomaly'
        }

def background_updater():
    """Background thread to update data every configured interval"""
    while True:
        try:
            update_cache(event_type='anomaly', kubernetes_enabled=False)  # Default to regular anomaly events for background updates
            time.sleep(CACHE_REFRESH_INTERVAL)
        except Exception as e:
            time.sleep(60)  # Retry after 1 minute on error

# Flask Routes
@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/schema_data')
def get_schema_data():
    """API endpoint for schema data (enhanced with tenant+account data)"""
    try:
        # Get cloud provider parameter
        cloud_provider = request.args.get('provider', DEFAULT_CLOUD_PROVIDER, type=str).lower()
        
        # Get event type parameter
        event_type = request.args.get('event_type', 'anomaly', type=str).lower()
        
        # Get kubernetes enabled parameter
        kubernetes_enabled = request.args.get('kubernetes', 'false', type=str).lower() == 'true'
        
        # Validate event type
        if event_type not in ['anomaly', 'total']:
            event_type = 'anomaly'  # Default if invalid
        
        # Force update if cache is empty or old
        if not cached_data or not last_update or (datetime.now() - last_update).total_seconds() > CACHE_EXPIRE_TIME:
            update_cache(cloud_provider=cloud_provider, event_type=event_type, kubernetes_enabled=kubernetes_enabled)
            
        return jsonify(cached_data)
    except Exception as e:
        return jsonify({
            "error": str(e), 
            "tenants": {},
            "accounts": {},
            "today": {}, 
            "last_updated": "Error",
            "status": "error"
        }), 500

@app.route('/api/tenant_details/<tenant_name>')
def get_tenant_details(tenant_name):
    """API endpoint to get detailed information for a specific tenant"""
    try:
        if not cached_data or tenant_name not in cached_data.get('tenants', {}):
            return jsonify({
                "error": f"Tenant '{tenant_name}' not found",
                "available_tenants": list(cached_data.get('tenants', {}).keys())
            }), 404
        
        tenant_data = cached_data['tenants'][tenant_name]
        
        # Get associated environment IDs for this tenant
        env_ids = reverse_mapping.get(tenant_name, [])
        
        return jsonify({
            "tenant_name": tenant_name,
            "environment_ids": env_ids,
            "tenant_data": tenant_data,
            "total_accounts": len(tenant_data.get('accounts', {})),
            "cloud_provider": cached_data.get('cloud_provider', DEFAULT_CLOUD_PROVIDER),
            "status": "success"
        })
        
    except Exception as e:
        return jsonify({
            "error": str(e),
            "tenant_name": tenant_name
        }), 500

@app.route('/api/timerange_data')
def get_timerange_data():
    """API endpoint for custom timerange data with tenant+account breakdown"""
    try:
        # Get days parameter from query string
        days = request.args.get('days', DEFAULT_TIME_RANGE_DAYS, type=int)
        
        # Get cloud provider parameter
        cloud_provider = request.args.get('provider', DEFAULT_CLOUD_PROVIDER, type=str).lower()
        
        # Get event type parameter
        event_type = request.args.get('event_type', 'anomaly', type=str).lower()
        
        # Get kubernetes enabled parameter
        kubernetes_enabled = request.args.get('kubernetes', 'false', type=str).lower() == 'true'
        
        # Validate days parameter
        if days < 1 or days > MAX_TIME_RANGE_DAYS:
            return jsonify({
                "error": f"Days parameter must be between 1 and {MAX_TIME_RANGE_DAYS}",
                "provided_days": days,
                "supported_ranges": [1, 7, 14, 30, 60, 90]
            }), 400
        
        # Validate cloud provider
        if cloud_provider not in ['aws', 'gcp']:
            return jsonify({
                "error": "Provider parameter must be 'aws' or 'gcp'",
                "provided_provider": cloud_provider,
                "supported_providers": ["aws", "gcp"]
            }), 400
        
        # Validate event type
        if event_type not in ['anomaly', 'total']:
            return jsonify({
                "error": "Event type parameter must be 'anomaly' or 'total'",
                "provided_event_type": event_type,
                "supported_event_types": ["anomaly", "total"]
            }), 400
        
        # Add timeout handling for large queries
        if days > 30:
            # For large time ranges, provide a warning
            print(f"Warning: Large query requested - {days} days for {cloud_provider} {event_type} events")
        
        timerange_data = get_events_by_timerange(days=days, cloud_provider=cloud_provider, event_type=event_type, kubernetes_enabled=kubernetes_enabled)
        
        if isinstance(timerange_data, dict) and timerange_data.get("error"):
            return jsonify({
                "status": "error",
                "error_message": timerange_data.get("error"),
                "timerange_days": days,
                "cloud_provider": cloud_provider,
                "event_type": event_type,
                "kubernetes_enabled": kubernetes_enabled
            }), 503
        
        # Check for timeout issues in the results
        failed_queries = timerange_data.get("summary", {}).get("failed_queries", {})
        timeout_count = failed_queries.get("timeout", 0)
        
        if timeout_count > 0:
            # Add warning about timeout issues
            timerange_data["warnings"] = {
                "timeout_issues": f"{timeout_count} queries timed out. Consider reducing the time range.",
                "recommendation": "For better performance, try selecting a shorter time period (7-14 days)."
            }
        
        return jsonify({
            "status": "success",
            "data": timerange_data,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500

@app.route('/api/account_summary')
def get_account_summary():
    """API endpoint to get account-level summary"""
    try:
        # Get cloud provider parameter
        cloud_provider = request.args.get('provider', DEFAULT_CLOUD_PROVIDER, type=str).lower()
        
        if not cached_data:
            return jsonify({"error": "No data available"}), 503
        
        accounts = cached_data.get('accounts', {})
        
        # Create summary by tenant
        tenant_account_summary = defaultdict(list)
        
        for account_key, account_data in accounts.items():
            tenant_name = account_data.get('tenant', 'unknown')
            account_id = account_data.get('account_id', 'unknown')
            
            tenant_account_summary[tenant_name].append({
                "account_id": account_id,
                "total_events": account_data.get('total', 0),
                "active_days": len([count for count in account_data.get('daily', {}).values() if count > 0]),
                "detection_types": len(account_data.get('detections', {}))
            })
        
        # Sort accounts within each tenant by event count
        for tenant in tenant_account_summary:
            tenant_account_summary[tenant].sort(key=lambda x: x['total_events'], reverse=True)
        
        return jsonify({
            "status": "success",
            "tenant_account_summary": dict(tenant_account_summary),
            "total_accounts": len(accounts),
            "cloud_provider": cached_data.get('cloud_provider', cloud_provider),
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500

@app.route('/api/refresh')
def refresh_data():
    """Manual refresh endpoint"""
    try:
        # Get optional days parameter for refresh
        days = request.args.get('days', DEFAULT_TIME_RANGE_DAYS, type=int)
        
        # Get cloud provider parameter
        cloud_provider = request.args.get('provider', DEFAULT_CLOUD_PROVIDER, type=str).lower()
        
        # Get event type parameter
        event_type = request.args.get('event_type', 'anomaly', type=str).lower()
        
        # Get kubernetes enabled parameter
        kubernetes_enabled = request.args.get('kubernetes', 'false', type=str).lower() == 'true'
        
        # Validate days parameter
        if days < 1 or days > MAX_TIME_RANGE_DAYS:
            days = DEFAULT_TIME_RANGE_DAYS  # Default if invalid
        
        # Validate cloud provider
        if cloud_provider not in ['aws', 'gcp']:
            cloud_provider = DEFAULT_CLOUD_PROVIDER  # Default if invalid
        
        # Validate event type
        if event_type not in ['anomaly', 'total']:
            event_type = 'anomaly'  # Default if invalid
        
        update_cache(default_days=days, cloud_provider=cloud_provider, event_type=event_type, kubernetes_enabled=kubernetes_enabled)
        return jsonify({
            "status": "success", 
            "message": f"Data refreshed successfully for {days} days ({cloud_provider.upper()}) - {event_type.title()} events", 
            "timestamp": datetime.now().isoformat(),
            "timerange_days": days,
            "cloud_provider": cloud_provider,
            "event_type": event_type,
            "data_summary": {
                "total_events_timerange": cached_data.get('total_events', 0),
                "total_events_today": cached_data.get('total_events_today', 0),
                "total_tenants": cached_data.get('total_tenants', 0),
                "total_accounts": cached_data.get('total_accounts', 0),
                "active_tenants_timerange": cached_data.get('active_tenants', 0),
                "active_tenants_today": cached_data.get('active_tenants_today', 0),
                "active_accounts_timerange": cached_data.get('active_accounts', 0),
                "active_accounts_today": cached_data.get('active_accounts_today', 0)
            }
        })
    except Exception as e:
        return jsonify({
            "status": "error", 
            "message": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500

@app.route('/api/refresh_mappings')
def refresh_mappings():
    """Refresh schema mappings from database"""
    try:
        success = load_schema_mapping_from_db()
        if success:
            return jsonify({
                "status": "success",
                "message": "Schema mappings refreshed successfully from database",
                "total_mappings": len(schema_mapping),
                "total_tenants": len(reverse_mapping),
                "timestamp": datetime.now().isoformat()
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Failed to refresh schema mappings from database",
                "timestamp": datetime.now().isoformat()
            }), 500
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500

@app.route('/api/query_large_account/<environment_id>')
def query_large_account_with_sampling(environment_id):
    """Special endpoint for accounts with circuit breaker issues - uses sampling"""
    try:
        cloud_provider = request.args.get('provider', DEFAULT_CLOUD_PROVIDER, type=str).lower()
        days = request.args.get('days', DEFAULT_TIME_RANGE_DAYS, type=int)
        
        # Build index name
        if cloud_provider.lower() == "gcp":
            index_name = f"{GCP_INDEX_PREFIX}{environment_id}"
        else:
            index_name = f"{AWS_INDEX_PREFIX}{environment_id}"
        
        time_range = "now/d" if days == 1 else f"now-{days}d"
        
        # Use sampling to reduce memory usage for large datasets
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "eventTime": {
                                    "gte": time_range,
                                    "lte": "now",
                                    "time_zone": "UTC"
                                }
                            }
                        },
                        {
                            "term": {
                                "baseline": False
                            }
                        },
                        {
                            "exists": {
                                "field": "detection"
                            }
                        }
                    ],
                    "must_not": [
                        {
                            "terms": {
                                "detection.keyword": [
                                    "NORMAL_EVENT",
                                    "LEARNING"
                                ]
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "sample": {
                    "sampler": {
                        "shard_size": 1000  # Sample only 1000 docs per shard to avoid memory issues
                    },
                    "aggs": {
                        "detection_breakdown": {
                            "terms": {
                                "field": "detection.keyword",
                                "size": MAX_DETECTION_TYPES_SIZE
                            }
                        }
                    }
                },
                "daily_breakdown": {
                    "date_histogram": {
                        "field": "eventTime",
                        "calendar_interval": "1d",
                        "time_zone": "UTC",
                        "format": "yyyy-MM-dd",
                        "min_doc_count": 0
                    }
                }
            },
            "timeout": "60s",
            "_source": False
        }
        
        result, error = query_elasticsearch(query, index_name)
        
        if error:
            return jsonify({
                "status": "error",
                "environment_id": environment_id,
                "error": error
            }), 500
        
        # Process sampled results
        total_count = 0
        daily_data = {}
        detection_data = {}
        
        if result and 'aggregations' in result:
            # Get daily totals
            daily_buckets = result['aggregations']['daily_breakdown']['buckets']
            for bucket in daily_buckets:
                date_key = bucket['key_as_string']
                daily_count = bucket['doc_count']
                daily_data[date_key] = daily_count
                total_count += daily_count
            
            # Get sampled detection types
            if 'sample' in result['aggregations']:
                sample_data = result['aggregations']['sample']
                sample_size = sample_data.get('doc_count', 0)
                
                detection_buckets = sample_data.get('detection_breakdown', {}).get('buckets', [])
                for bucket in detection_buckets:
                    detection_type = bucket['key']
                    # Scale up the sampled count proportionally
                    sampled_count = bucket['doc_count']
                    scaled_count = int((sampled_count / sample_size) * total_count) if sample_size > 0 else sampled_count
                    detection_data[detection_type] = scaled_count
        
        return jsonify({
            "status": "success",
            "environment_id": environment_id,
            "index_name": index_name,
            "total": total_count,
            "daily": daily_data,
            "detections": detection_data,
            "note": "Data obtained using sampling to avoid circuit breaker",
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "environment_id": environment_id,
            "error": str(e)
        }), 500

@app.route('/api/test')
def test_api():
    """Test API endpoint"""
    db_status, db_message = test_db_connection()
    
    return jsonify({
        "status": "API is working", 
        "timestamp": datetime.now().isoformat(),
        "database_connection": "success" if db_status else "error",
        "schema_mappings_loaded": len(schema_mapping),
        "reverse_mappings_loaded": len(reverse_mapping),
        "cached_data_available": bool(cached_data),
        "last_cache_update": last_update.isoformat() if last_update else None,
        "configuration": {
            "elasticsearch_url": ELASTICSEARCH_URL,
            "database_host": DATABASE_CONFIG['host'],
            "database_name": DATABASE_CONFIG['database'],
            "default_cloud_provider": DEFAULT_CLOUD_PROVIDER,
            "cache_refresh_interval": CACHE_REFRESH_INTERVAL,
            "max_time_range_days": MAX_TIME_RANGE_DAYS,
            "query_mode": "Individual indices per environment ID",
            "cloud_provider_filtering": "Enabled - Only shows tenants with valid indices for selected provider"
        }
    })

@app.route('/api/mappings')
def get_mappings():
    """Get current schema mappings including reverse mapping"""
    return jsonify({
        "total_mappings": len(schema_mapping),
        "forward_mappings": schema_mapping,
        "reverse_mappings": reverse_mapping,
        "summary": {
            "total_environment_ids": len(schema_mapping),
            "total_tenants": len(reverse_mapping),
            "accounts_per_tenant": {tenant: len(accounts) for tenant, accounts in reverse_mapping.items()}
        },
        "note": "Querying individual indices based on environment IDs"
    })

@app.route('/api/debug_kubernetes/<environment_id>')
def debug_kubernetes_data(environment_id):
    """Debug endpoint to inspect Kubernetes data structure and test queries"""
    try:
        cloud_provider = request.args.get('provider', 'aws', type=str).lower()
        
        # Build wildcard pattern for Kubernetes indices
        if cloud_provider.lower() == "gcp":
            index_pattern = f"{K8S_GCP_INDEX_PREFIX}{environment_id}_*"
        else:
            index_pattern = f"{K8S_AWS_INDEX_PREFIX}{environment_id}_*"
        
        # Test 1: Check if indices exist
        indices_exist = check_kubernetes_indices_exist(environment_id, cloud_provider)
        
        # Test 2: Get sample document structure
        sample_doc = inspect_kubernetes_data_structure(environment_id, cloud_provider)
        
        # Test 3: Simple count query
        simple_count_query = {
            "size": 0,
            "query": {
                "match_all": {}
            }
        }
        
        count_result, count_error = query_elasticsearch(simple_count_query, index_pattern)
        
        # Test 4: Time range query
        time_range_query = {
            "size": 0,
            "query": {
                "range": {
                    "eventTime": {
                        "gte": "now-7d",
                        "lte": "now"
                    }
                }
            }
        }
        
        time_result, time_error = query_elasticsearch(time_range_query, index_pattern)
        
        # Test 5: Get actual field names from mapping
        try:
            url = f"{normalize_elasticsearch_url(ELASTICSEARCH_URL)}/{index_pattern}/_mapping"
            response = requests.get(url, auth=ES_AUTH, timeout=10)
            mapping_data = response.json() if response.status_code == 200 else None
        except Exception as e:
            mapping_data = {"error": str(e)}
        
        return jsonify({
            "status": "success",
            "environment_id": environment_id,
            "cloud_provider": cloud_provider,
            "index_pattern": index_pattern,
            "tests": {
                "indices_exist": indices_exist,
                "sample_document": sample_doc,
                "total_documents": count_result.get('hits', {}).get('total', {}).get('value', 0) if count_result else 0,
                "count_error": count_error,
                "time_range_documents": time_result.get('hits', {}).get('total', {}).get('value', 0) if time_result else 0,
                "time_error": time_error,
                "mapping": mapping_data
            },
            "available_fields": list(sample_doc.keys()) if sample_doc else [],
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "environment_id": environment_id,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500

@app.route('/api/test_kubernetes_query/<environment_id>')
def test_kubernetes_query(environment_id):
    """Test specific Kubernetes queries"""
    try:
        cloud_provider = request.args.get('provider', 'aws', type=str).lower()
        query_type = request.args.get('query_type', 'simple', type=str)
        
        # Build wildcard pattern for Kubernetes indices
        if cloud_provider.lower() == "gcp":
            index_pattern = f"{K8S_GCP_INDEX_PREFIX}{environment_id}_*"
        else:
            index_pattern = f"{K8S_AWS_INDEX_PREFIX}{environment_id}_*"
        
        if query_type == 'simple':
            # Simple match_all query
            query = {
                "size": 5,
                "query": {
                    "match_all": {}
                },
                "sort": [
                    {
                        "eventTime": {
                            "order": "desc"
                        }
                    }
                ]
            }
        elif query_type == 'time_range':
            # Time range query
            query = {
                "size": 5,
                "query": {
                    "range": {
                        "eventTime": {
                            "gte": "now-7d",
                            "lte": "now"
                        }
                    }
                },
                "sort": [
                    {
                        "eventTime": {
                            "order": "desc"
                        }
                    }
                ]
            }
        elif query_type == 'dashboard':
            # Dashboard-style query (simplified)
            query = {
                "size": 0,
                "query": {
                    "range": {
                        "eventTime": {
                            "gte": "now-7d",
                            "lte": "now"
                        }
                    }
                },
                "aggs": {
                    "daily_breakdown": {
                        "date_histogram": {
                            "field": "eventTime",
                            "calendar_interval": "1d",
                            "time_zone": "UTC",
                            "format": "yyyy-MM-dd",
                            "min_doc_count": 0
                        }
                    }
                }
            }
        else:
            return jsonify({
                "error": "Invalid query_type. Use 'simple', 'time_range', or 'dashboard'"
            }), 400
        
        result, error = query_elasticsearch(query, index_pattern)
        
        return jsonify({
            "status": "success",
            "environment_id": environment_id,
            "cloud_provider": cloud_provider,
            "index_pattern": index_pattern,
            "query_type": query_type,
            "query": query,
            "result": result,
            "error": error,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "environment_id": environment_id,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "error": "Endpoint not found", 
        "available_endpoints": [
            "GET  /                           - Dashboard page",
            "GET  /api/schema_data            - Get enhanced tenant+account data (?provider=aws|gcp)", 
            "GET  /api/timerange_data         - Get custom timerange data (?days=N&provider=aws|gcp)",
            "GET  /api/tenant_details/<n>     - Get specific tenant details",
            "GET  /api/account_summary         - Get account-level summary (?provider=aws|gcp)",
            "GET  /api/test                   - Test API status",
            "GET  /api/refresh                - Refresh data manually (?days=N&provider=aws|gcp)",
            "GET  /api/refresh_mappings       - Refresh schema mappings from database",
            "GET  /api/mappings               - View schema mappings from database",
            "GET  /api/query_large_account/<id>  - Query large account with sampling (?provider=aws|gcp&days=N)"
        ]
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "error": "Internal server error", 
        "message": str(error),
        "timestamp": datetime.now().isoformat()
    }), 500

# Initialize application
def initialize_app():
    """Initialize the application"""
    # Initialize database connection pool
    if not initialize_db_pool():
        return False
    
    # Test database connection
    db_status, db_message = test_db_connection()
    if not db_status:
        return False
    
    # Load schema mapping
    if not load_schema_mapping_from_db():
        return False
    
    # Initial data load
    update_cache(event_type='anomaly', kubernetes_enabled=False)
    
    # Start background updater
    updater_thread = threading.Thread(target=background_updater, daemon=True)
    updater_thread.start()
    
    return True

if __name__ == '__main__':
    if initialize_app():
        app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG, threaded=True)
    else:
        print("Failed to initialize application")
