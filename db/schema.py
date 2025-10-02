"""
Database schema for KDM management system.

This module defines the complete database schema for managing:
- Tenants and organizations
- Certificate chains (root > signer > device)
- Self-signed certificates
- DKDM (Distribution Key Delivery Messages)
- CPL (Composition Playlists)
- Generated KDMs

All tables follow SMPTE standards and digital cinema workflows.
"""

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Optional, Dict, Any

from utils.logger import get_logger
from utils.utils import get_current_path

log = get_logger()

class KDMDatabase:
    """Database manager for KDM system with comprehensive schema."""

    def __init__(self, db_path: Optional[str] = None):
        """Initialize database connection and create schema if needed."""
        if db_path is None:
            db_path = f"{get_current_path()}/db/genkdmdb.sql"

        self.db_path = db_path
        # Ensure db directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        # Initialize schema
        self.init_database()

    @contextmanager
    def get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Enable dict-like access
        conn.execute("PRAGMA foreign_keys = ON")  # Enable foreign key constraints
        try:
            yield conn
        finally:
            conn.close()

    def init_database(self):
        """Create all tables if they don't exist."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Create all tables
            self._create_tenants_table(cursor)
            self._create_self_signed_certificates_table(cursor)
            self._create_certificate_chains_table(cursor)
            self._create_cpl_table(cursor)
            self._create_dkdm_table(cursor)
            self._create_kdm_generated_table(cursor)

            # Create indexes for performance
            self._create_indexes(cursor)

            conn.commit()
            log.info("Database schema initialized successfully")

    def _create_tenants_table(self, cursor):
        """Create tenants table for organizations/labels."""
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tenants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT NOT NULL UNIQUE,
                description TEXT,
                organization TEXT,
                contact_email TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1
            )
        ''')

    def _create_self_signed_certificates_table(self, cursor):
        """Create self-signed certificates table with SMPTE compliance."""
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS self_signed_certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                certificate_name TEXT NOT NULL,
                certificate_path TEXT NOT NULL,
                private_key_path TEXT NOT NULL,
                certificate_pem TEXT,
                private_key_pem TEXT,

                -- Certificate metadata
                subject_name TEXT NOT NULL,
                issuer_name TEXT NOT NULL,
                serial_number TEXT NOT NULL,
                thumbprint TEXT NOT NULL,

                -- Validity period
                not_valid_before TIMESTAMP NOT NULL,
                not_valid_after TIMESTAMP NOT NULL,

                -- SMPTE compliance
                is_smpte_compliant BOOLEAN DEFAULT 1,
                certificate_role TEXT, -- ROOT, INTERMEDIATE, LEAF
                key_usage TEXT, -- digitalSignature, keyEncipherment, etc.

                -- Metadata
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,

                UNIQUE(certificate_path),
                UNIQUE(thumbprint)
            )
        ''')

    def _create_certificate_chains_table(self, cursor):
        """Create certificate chains table (root > signer > device) - global, shared by all tenants."""
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS certificate_chains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain_name TEXT NOT NULL UNIQUE,

                -- Certificate chain paths
                root_cert_path TEXT NOT NULL,
                signer_cert_path TEXT NOT NULL,
                device_cert_path TEXT NOT NULL,

                -- Certificate chain PEM data
                root_cert_pem TEXT NOT NULL,
                signer_cert_pem TEXT NOT NULL,
                device_cert_pem TEXT NOT NULL,

                -- Private keys
                root_key_path TEXT,
                signer_key_path TEXT,
                device_key_path TEXT,

                -- Chain metadata
                root_thumbprint TEXT NOT NULL,
                signer_thumbprint TEXT NOT NULL,
                device_thumbprint TEXT NOT NULL UNIQUE,

                -- Chain validity (based on shortest cert validity)
                chain_valid_from TIMESTAMP NOT NULL,
                chain_valid_until TIMESTAMP NOT NULL,

                -- SMPTE compliance
                is_smpte_compliant BOOLEAN DEFAULT 1,
                smpte_role TEXT, -- CINEMA, DISTRIBUTOR, etc.

                -- Metadata
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1
            )
        ''')

    def _create_cpl_table(self, cursor):
        """Create CPL (Composition Playlist) table with content metadata."""
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cpl (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id INTEGER NOT NULL,

                -- CPL identifiers
                cpl_uuid TEXT NOT NULL UNIQUE,
                cpl_file_path TEXT NOT NULL,

                -- CPL content
                annotation_text TEXT,
                content_title_text TEXT NOT NULL,
                content_kind TEXT, -- feature, trailer, advertisement, etc.
                content_version_id TEXT,
                content_version_label TEXT,

                -- Issue information
                issue_date TIMESTAMP NOT NULL,
                issuer TEXT,
                creator TEXT,

                -- Technical metadata
                total_duration INTEGER, -- in frames
                edit_rate_numerator INTEGER,
                edit_rate_denominator INTEGER,
                reel_count INTEGER DEFAULT 0,

                -- Key information (JSON array of key IDs and types)
                key_ids_json TEXT, -- JSON: [{"key_id": "uuid", "key_type": "MDIK|MDAK", "reel_id": "uuid"}]

                -- Content metadata
                screen_aspect_ratio TEXT,
                language_codes TEXT, -- JSON array of language codes

                -- Metadata
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,

                FOREIGN KEY (tenant_id) REFERENCES tenants(id)
            )
        ''')

    def _create_dkdm_table(self, cursor):
        """Create DKDM (Distribution KDM) table with keys and validity."""
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dkdm (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id INTEGER NOT NULL,
                cpl_id INTEGER NOT NULL,

                -- DKDM identifiers
                dkdm_uuid TEXT NOT NULL UNIQUE,
                dkdm_file_path TEXT NOT NULL,

                -- DKDM content
                message_id TEXT NOT NULL,
                annotation_text TEXT,
                content_title_text TEXT NOT NULL,

                -- Linked CPL
                composition_playlist_id TEXT NOT NULL, -- Should match cpl.cpl_uuid

                -- Validity period
                content_keys_not_valid_before TIMESTAMP NOT NULL,
                content_keys_not_valid_after TIMESTAMP NOT NULL,
                issue_date TIMESTAMP NOT NULL,

                -- Signer information
                signer_issuer_name TEXT NOT NULL,
                signer_serial_number TEXT NOT NULL,

                -- Recipient information
                recipient_issuer_name TEXT,
                recipient_serial_number TEXT,
                recipient_subject_name TEXT,

                -- Device authorization
                device_list_identifier TEXT,
                device_thumbprints_json TEXT, -- JSON array of authorized device thumbprints

                -- Content keys (JSON array)
                key_ids_json TEXT NOT NULL, -- JSON: [{"key_id": "uuid", "key_type": "MDIK|MDAK", "encrypted_key": "base64"}]

                -- Metadata
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,

                FOREIGN KEY (tenant_id) REFERENCES tenants(id),
                FOREIGN KEY (cpl_id) REFERENCES cpl(id)
            )
        ''')

    def _create_kdm_generated_table(self, cursor):
        """Create KDM generated table linking all entities."""
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS kdm_generated (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id INTEGER NOT NULL,
                cpl_id INTEGER NOT NULL,
                dkdm_id INTEGER NOT NULL,
                certificate_chain_id INTEGER NOT NULL,

                -- Generated KDM identifiers
                kdm_uuid TEXT NOT NULL UNIQUE,
                kdm_file_path TEXT NOT NULL,
                signed_kdm_file_path TEXT, -- Path to signed version

                -- KDM content
                message_id TEXT NOT NULL,
                annotation_text TEXT,
                content_title_text TEXT NOT NULL,

                -- Target information (from certificate chain)
                target_device_thumbprint TEXT NOT NULL,
                target_issuer_name TEXT NOT NULL,
                target_serial_number TEXT NOT NULL,
                target_subject_name TEXT NOT NULL,

                -- Validity period (can be subset of DKDM period)
                content_keys_not_valid_before TIMESTAMP NOT NULL,
                content_keys_not_valid_after TIMESTAMP NOT NULL,
                issue_date TIMESTAMP NOT NULL,

                -- Signing information
                signer_certificate_id INTEGER, -- Reference to self_signed_certificates
                is_signed BOOLEAN DEFAULT 0,
                signature_algorithm TEXT, -- RSA-SHA256, etc.

                -- Generation metadata
                generation_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                generator_version TEXT,
                generation_parameters_json TEXT, -- JSON of generation parameters

                -- Validation status
                is_valid BOOLEAN DEFAULT 1,
                validation_errors_json TEXT, -- JSON array of validation errors
                last_validated_at TIMESTAMP,

                -- Metadata
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,

                FOREIGN KEY (tenant_id) REFERENCES tenants(id),
                FOREIGN KEY (cpl_id) REFERENCES cpl(id),
                FOREIGN KEY (dkdm_id) REFERENCES dkdm(id),
                FOREIGN KEY (certificate_chain_id) REFERENCES certificate_chains(id),
                FOREIGN KEY (signer_certificate_id) REFERENCES self_signed_certificates(id)
            )
        ''')

    def _create_indexes(self, cursor):
        """Create database indexes for performance."""
        indexes = [
            # Tenants
            "CREATE INDEX IF NOT EXISTS idx_tenants_label ON tenants(label)",
            "CREATE INDEX IF NOT EXISTS idx_tenants_active ON tenants(is_active)",

            # Self-signed certificates
            "CREATE INDEX IF NOT EXISTS idx_self_certs_thumbprint ON self_signed_certificates(thumbprint)",
            "CREATE INDEX IF NOT EXISTS idx_self_certs_validity ON self_signed_certificates(not_valid_before, not_valid_after)",
            "CREATE INDEX IF NOT EXISTS idx_self_certs_active ON self_signed_certificates(is_active)",

            # Certificate chains (global)
            "CREATE INDEX IF NOT EXISTS idx_cert_chains_name ON certificate_chains(chain_name)",
            "CREATE INDEX IF NOT EXISTS idx_cert_chains_thumbprint ON certificate_chains(device_thumbprint)",
            "CREATE INDEX IF NOT EXISTS idx_cert_chains_validity ON certificate_chains(chain_valid_from, chain_valid_until)",
            "CREATE INDEX IF NOT EXISTS idx_cert_chains_active ON certificate_chains(is_active)",

            # CPL
            "CREATE INDEX IF NOT EXISTS idx_cpl_tenant ON cpl(tenant_id)",
            "CREATE INDEX IF NOT EXISTS idx_cpl_uuid ON cpl(cpl_uuid)",
            "CREATE INDEX IF NOT EXISTS idx_cpl_title ON cpl(content_title_text)",
            "CREATE INDEX IF NOT EXISTS idx_cpl_active ON cpl(is_active)",

            # DKDM
            "CREATE INDEX IF NOT EXISTS idx_dkdm_tenant ON dkdm(tenant_id)",
            "CREATE INDEX IF NOT EXISTS idx_dkdm_cpl ON dkdm(cpl_id)",
            "CREATE INDEX IF NOT EXISTS idx_dkdm_uuid ON dkdm(dkdm_uuid)",
            "CREATE INDEX IF NOT EXISTS idx_dkdm_cpl_uuid ON dkdm(composition_playlist_id)",
            "CREATE INDEX IF NOT EXISTS idx_dkdm_validity ON dkdm(content_keys_not_valid_before, content_keys_not_valid_after)",
            "CREATE INDEX IF NOT EXISTS idx_dkdm_active ON dkdm(is_active)",

            # KDM Generated
            "CREATE INDEX IF NOT EXISTS idx_kdm_gen_tenant ON kdm_generated(tenant_id)",
            "CREATE INDEX IF NOT EXISTS idx_kdm_gen_cpl ON kdm_generated(cpl_id)",
            "CREATE INDEX IF NOT EXISTS idx_kdm_gen_dkdm ON kdm_generated(dkdm_id)",
            "CREATE INDEX IF NOT EXISTS idx_kdm_gen_cert_chain ON kdm_generated(certificate_chain_id)",
            "CREATE INDEX IF NOT EXISTS idx_kdm_gen_uuid ON kdm_generated(kdm_uuid)",
            "CREATE INDEX IF NOT EXISTS idx_kdm_gen_validity ON kdm_generated(content_keys_not_valid_before, content_keys_not_valid_after)",
            "CREATE INDEX IF NOT EXISTS idx_kdm_gen_signed ON kdm_generated(is_signed)",
            "CREATE INDEX IF NOT EXISTS idx_kdm_gen_valid ON kdm_generated(is_valid)",
            "CREATE INDEX IF NOT EXISTS idx_kdm_gen_active ON kdm_generated(is_active)"
        ]

        for index_sql in indexes:
            cursor.execute(index_sql)

    def get_schema_info(self) -> Dict[str, Any]:
        """Get comprehensive schema information."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Get table information
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]

            schema_info = {
                "database_path": self.db_path,
                "tables": {},
                "total_tables": len(tables)
            }

            for table in tables:
                cursor.execute(f"PRAGMA table_info({table})")
                columns = cursor.fetchall()

                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                row_count = cursor.fetchone()[0]

                schema_info["tables"][table] = {
                    "columns": [{"name": col[1], "type": col[2], "nullable": not col[3], "default": col[4], "pk": col[5]} for col in columns],
                    "row_count": row_count
                }

            return schema_info


# Convenience functions for database operations
def get_database() -> KDMDatabase:
    """Get database instance with default configuration."""
    return KDMDatabase()


def reset_database(db_path: Optional[str] = None) -> KDMDatabase:
    """Reset database by removing file and recreating schema."""
    if db_path is None:
        db_path = f"{get_current_path()}/db/genkdmdb.sql"

    # Remove existing database
    db_file = Path(db_path)
    if db_file.exists():
        db_file.unlink()
        log.info(f"Removed existing database: {db_path}")

    # Create new database with schema
    db = KDMDatabase(db_path)
    log.info(f"Created new database: {db_path}")
    return db


if __name__ == "__main__":
    # Example usage
    log.info("KDM Database Schema Manager")

    # Initialize database
    db = get_database()

    # Show schema information
    schema = db.get_schema_info()
    log.info(f"Database: {schema['database_path']}")
    log.info(f"Total tables: {schema['total_tables']}")

    for table_name, table_info in schema["tables"].items():
        log.info(f"Table: {table_name} ({table_info['row_count']} rows)")
        for col in table_info["columns"]:
            pk_marker = " [PK]" if col["pk"] else ""
            nullable = "NULL" if col["nullable"] else "NOT NULL"
            default = f" DEFAULT {col['default']}" if col["default"] else ""
            log.info(f"  - {col['name']}: {col['type']} {nullable}{default}{pk_marker}")