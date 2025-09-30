"""
CLI commands for KDM database management.

Provides command-line interface for:
- Database initialization and management
- Tenant management
- Certificate import and management
- DKDM and CPL import
- KDM generation tracking
- Database statistics and reporting

Usage:
    python -m db.cli init                    # Initialize database
    python -m db.cli tenant add "Cinema1"   # Add tenant
    python -m db.cli import-cpl tenant1 /path/to/cpl.xml
    python -m db.cli import-dkdm tenant1 /path/to/dkdm.xml
    python -m db.cli stats                   # Show statistics
"""

import argparse
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import List

from db.schema import get_database, reset_database
from db.dao import get_dao, TenantRecord


def init_database(args):
    """Initialize database with schema."""
    print("🔄 Initializing KDM database...")

    if args.reset:
        db = reset_database()
    else:
        db = get_database()

    schema_info = db.get_schema_info()
    print(f"✅ Database initialized: {schema_info['database_path']}")
    print(f"📊 Total tables: {schema_info['total_tables']}")

    # Show table structure
    for table_name, table_info in schema_info["tables"].items():
        print(f"  📋 {table_name}: {table_info['row_count']} rows")


def add_tenant(args):
    """Add a new tenant."""
    dao = get_dao()

    tenant = TenantRecord(
        label=args.label,
        description=args.description or "",
        organization=args.organization or "",
        contact_email=args.email or ""
    )

    try:
        tenant_id = dao.create_tenant(tenant)
        print(f"✅ Added tenant '{args.label}' with ID: {tenant_id}")
    except Exception as e:
        print(f"❌ Failed to add tenant: {e}")
        sys.exit(1)


def list_tenants(args):
    """List all tenants."""
    dao = get_dao()
    tenants = dao.list_tenants(active_only=not args.all)

    if not tenants:
        print("📋 No tenants found")
        return

    print(f"📋 Found {len(tenants)} tenant(s):")
    print(f"{'ID':<4} {'Label':<20} {'Organization':<30} {'Active':<8}")
    print("-" * 65)

    for tenant in tenants:
        active = "✅" if tenant.is_active else "❌"
        print(f"{tenant.id:<4} {tenant.label:<20} {tenant.organization:<30} {active:<8}")


def remove_tenant(args):
    """Remove (deactivate) a tenant."""
    dao = get_dao()

    if dao.delete_tenant(args.tenant_id):
        print(f"✅ Deactivated tenant ID: {args.tenant_id}")
    else:
        print(f"❌ Failed to deactivate tenant ID: {args.tenant_id}")
        sys.exit(1)


def import_certificate(args):
    """Import a certificate from PEM files."""
    dao = get_dao()

    if not Path(args.cert_path).exists():
        print(f"❌ Certificate file not found: {args.cert_path}")
        sys.exit(1)

    if not Path(args.key_path).exists():
        print(f"❌ Private key file not found: {args.key_path}")
        sys.exit(1)

    try:
        cert_id = dao.import_certificate_from_file(args.cert_path, args.key_path, args.name)
        print(f"✅ Imported certificate '{args.name}' with ID: {cert_id}")
    except Exception as e:
        print(f"❌ Failed to import certificate: {e}")
        sys.exit(1)


def import_cpl(args):
    """Import a CPL from XML file."""
    dao = get_dao()

    # Get tenant
    tenant = dao.get_tenant_by_label(args.tenant_label)
    if not tenant:
        print(f"❌ Tenant '{args.tenant_label}' not found")
        sys.exit(1)

    if not Path(args.cpl_path).exists():
        print(f"❌ CPL file not found: {args.cpl_path}")
        sys.exit(1)

    try:
        cpl_id = dao.import_cpl_from_file(tenant.id, args.cpl_path)
        print(f"✅ Imported CPL with ID: {cpl_id}")
    except Exception as e:
        print(f"❌ Failed to import CPL: {e}")
        sys.exit(1)


def import_dkdm(args):
    """Import a DKDM from XML file."""
    dao = get_dao()

    # Get tenant
    tenant = dao.get_tenant_by_label(args.tenant_label)
    if not tenant:
        print(f"❌ Tenant '{args.tenant_label}' not found")
        sys.exit(1)

    if not Path(args.dkdm_path).exists():
        print(f"❌ DKDM file not found: {args.dkdm_path}")
        sys.exit(1)

    try:
        dkdm_id = dao.import_dkdm_from_file(tenant.id, args.dkdm_path)
        print(f"✅ Imported DKDM with ID: {dkdm_id}")
    except Exception as e:
        print(f"❌ Failed to import DKDM: {e}")
        sys.exit(1)


def show_statistics(args):
    """Show database statistics."""
    dao = get_dao()
    stats = dao.get_statistics()

    print("📊 KDM Database Statistics")
    print("=" * 50)

    categories = [
        ("Tenants", "tenants"),
        ("Certificates", "self_signed_certificates"),
        ("Certificate Chains", "certificate_chains"),
        ("CPLs", "cpl"),
        ("DKDMs", "dkdm"),
        ("Generated KDMs", "kdm_generated")
    ]

    for category, table in categories:
        active = stats.get(f'active_{table}', 0)
        total = stats.get(f'total_{table}', 0)
        print(f"{category:<20}: {active:>3} active / {total:>3} total")


def bulk_import(args):
    """Bulk import CPLs and DKDMs from directories."""
    dao = get_dao()

    # Get tenant
    tenant = dao.get_tenant_by_label(args.tenant_label)
    if not tenant:
        print(f"❌ Tenant '{args.tenant_label}' not found")
        sys.exit(1)

    imported_cpls = 0
    imported_dkdms = 0

    # Import CPLs
    if args.cpl_dir:
        cpl_dir = Path(args.cpl_dir)
        if cpl_dir.exists():
            print(f"🔄 Importing CPLs from {cpl_dir}...")
            for cpl_file in cpl_dir.glob("*.xml"):
                try:
                    dao.import_cpl_from_file(tenant.id, str(cpl_file))
                    imported_cpls += 1
                    print(f"  ✅ Imported: {cpl_file.name}")
                except Exception as e:
                    print(f"  ❌ Failed to import {cpl_file.name}: {e}")
        else:
            print(f"❌ CPL directory not found: {cpl_dir}")

    # Import DKDMs
    if args.dkdm_dir:
        dkdm_dir = Path(args.dkdm_dir)
        if dkdm_dir.exists():
            print(f"🔄 Importing DKDMs from {dkdm_dir}...")
            for dkdm_file in dkdm_dir.glob("*.xml"):
                try:
                    dao.import_dkdm_from_file(tenant.id, str(dkdm_file))
                    imported_dkdms += 1
                    print(f"  ✅ Imported: {dkdm_file.name}")
                except Exception as e:
                    print(f"  ❌ Failed to import {dkdm_file.name}: {e}")
        else:
            print(f"❌ DKDM directory not found: {dkdm_dir}")

    print(f"📊 Bulk import completed: {imported_cpls} CPLs, {imported_dkdms} DKDMs")


def export_data(args):
    """Export database data to JSON."""
    dao = get_dao()

    export_data = {
        "export_timestamp": datetime.now().isoformat(),
        "tenants": [tenant.__dict__ for tenant in dao.list_tenants(active_only=False)],
        "statistics": dao.get_statistics()
    }

    with open(args.output_file, 'w') as f:
        json.dump(export_data, f, indent=2, default=str)

    print(f"✅ Database data exported to: {args.output_file}")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(description="KDM Database Management CLI")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Database initialization
    init_parser = subparsers.add_parser('init', help='Initialize database')
    init_parser.add_argument('--reset', action='store_true', help='Reset existing database')

    # Tenant management
    tenant_parser = subparsers.add_parser('tenant', help='Tenant management')
    tenant_subparsers = tenant_parser.add_subparsers(dest='tenant_action')

    # Add tenant
    add_tenant_parser = tenant_subparsers.add_parser('add', help='Add new tenant')
    add_tenant_parser.add_argument('label', help='Tenant label/name')
    add_tenant_parser.add_argument('--description', help='Tenant description')
    add_tenant_parser.add_argument('--organization', help='Organization name')
    add_tenant_parser.add_argument('--email', help='Contact email')

    # List tenants
    list_tenant_parser = tenant_subparsers.add_parser('list', help='List tenants')
    list_tenant_parser.add_argument('--all', action='store_true', help='Include inactive tenants')

    # Remove tenant
    remove_tenant_parser = tenant_subparsers.add_parser('remove', help='Remove tenant')
    remove_tenant_parser.add_argument('tenant_id', type=int, help='Tenant ID to remove')

    # Certificate import
    cert_parser = subparsers.add_parser('import-cert', help='Import certificate')
    cert_parser.add_argument('name', help='Certificate name')
    cert_parser.add_argument('cert_path', help='Path to certificate PEM file')
    cert_parser.add_argument('key_path', help='Path to private key PEM file')

    # CPL import
    cpl_parser = subparsers.add_parser('import-cpl', help='Import CPL')
    cpl_parser.add_argument('tenant_label', help='Tenant label')
    cpl_parser.add_argument('cpl_path', help='Path to CPL XML file')

    # DKDM import
    dkdm_parser = subparsers.add_parser('import-dkdm', help='Import DKDM')
    dkdm_parser.add_argument('tenant_label', help='Tenant label')
    dkdm_parser.add_argument('dkdm_path', help='Path to DKDM XML file')

    # Bulk import
    bulk_parser = subparsers.add_parser('bulk-import', help='Bulk import files')
    bulk_parser.add_argument('tenant_label', help='Tenant label')
    bulk_parser.add_argument('--cpl-dir', help='Directory containing CPL files')
    bulk_parser.add_argument('--dkdm-dir', help='Directory containing DKDM files')

    # Statistics
    stats_parser = subparsers.add_parser('stats', help='Show database statistics')

    # Export
    export_parser = subparsers.add_parser('export', help='Export database data')
    export_parser.add_argument('output_file', help='Output JSON file path')

    # Parse arguments
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Route to appropriate handler
    if args.command == 'init':
        init_database(args)
    elif args.command == 'tenant':
        if args.tenant_action == 'add':
            add_tenant(args)
        elif args.tenant_action == 'list':
            list_tenants(args)
        elif args.tenant_action == 'remove':
            remove_tenant(args)
        else:
            tenant_parser.print_help()
    elif args.command == 'import-cert':
        import_certificate(args)
    elif args.command == 'import-cpl':
        import_cpl(args)
    elif args.command == 'import-dkdm':
        import_dkdm(args)
    elif args.command == 'bulk-import':
        bulk_import(args)
    elif args.command == 'stats':
        show_statistics(args)
    elif args.command == 'export':
        export_data(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()