"""
KDM Management Commands

This module provides high-level commands for KDM management with database persistence.
All operations are tracked in the database for audit and management purposes.
"""

from db.dao import get_dao, TenantRecord
from db.schema import get_database
from pathlib import Path


def add_self_signed_certificate(cert_path: str, key_path: str, name: str):
    """
    Generate and register a self-signed certificate.

    The certificate will be used to sign generated KDMs.
    This operation can only be performed once per certificate.

    Args:
        cert_path (str): Path to certificate PEM file
        key_path (str): Path to private key PEM file
        name (str): Name/identifier for the certificate

    Returns:
        int: Certificate ID in database
    """
    dao = get_dao()

    try:
        cert_id = dao.import_certificate_from_file(cert_path, key_path, name)
        print(f"✅ Self-signed certificate '{name}' registered with ID: {cert_id}")
        return cert_id
    except Exception as e:
        print(f"❌ Failed to register certificate: {e}")
        raise


def add_tenant(label: str, description: str = "", organization: str = "", contact_email: str = ""):
    """
    Add a new tenant (organization/label) to the system.

    Args:
        label (str): Unique tenant label/name
        description (str): Optional description
        organization (str): Organization name
        contact_email (str): Contact email

    Returns:
        int: Tenant ID in database
    """
    dao = get_dao()

    tenant = TenantRecord(
        label=label,
        description=description,
        organization=organization,
        contact_email=contact_email
    )

    try:
        tenant_id = dao.create_tenant(tenant)
        print(f"✅ Tenant '{label}' added with ID: {tenant_id}")
        return tenant_id
    except Exception as e:
        print(f"❌ Failed to add tenant: {e}")
        raise


def remove_tenant(tenant_id: int):
    """
    Remove (deactivate) a tenant from the system.

    Args:
        tenant_id (int): Tenant ID to remove

    Returns:
        bool: True if successful
    """
    dao = get_dao()

    if dao.delete_tenant(tenant_id):
        print(f"✅ Tenant ID {tenant_id} deactivated")
        return True
    else:
        print(f"❌ Failed to deactivate tenant ID {tenant_id}")
        return False


def edit_tenant(tenant_id: int, **kwargs):
    """
    Edit tenant information.

    Args:
        tenant_id (int): Tenant ID to edit
        **kwargs: Fields to update (label, description, organization, contact_email)

    Returns:
        bool: True if successful
    """
    dao = get_dao()

    tenant = dao.get_tenant(tenant_id)
    if not tenant:
        print(f"❌ Tenant ID {tenant_id} not found")
        return False

    # Update fields
    for key, value in kwargs.items():
        if hasattr(tenant, key):
            setattr(tenant, key, value)

    if dao.update_tenant(tenant):
        print(f"✅ Tenant ID {tenant_id} updated")
        return True
    else:
        print(f"❌ Failed to update tenant ID {tenant_id}")
        return False


def list_tenant(active_only: bool = True):
    """
    List all tenants in the system.

    Args:
        active_only (bool): If True, only show active tenants

    Returns:
        list: List of tenant records
    """
    dao = get_dao()

    tenants = dao.list_tenants(active_only=active_only)

    if not tenants:
        print("📋 No tenants found")
        return []

    print(f"📋 Found {len(tenants)} tenant(s):")
    print(f"{'ID':<4} {'Label':<20} {'Organization':<30} {'Active':<8}")
    print("-" * 65)

    for tenant in tenants:
        active = "✅" if tenant.is_active else "❌"
        print(f"{tenant.id:<4} {tenant.label:<20} {tenant.organization:<30} {active:<8}")

    return tenants


def add_dkdm(tenant_label: str, dkdm_file_path: str):
    """
    Import and register a DKDM file.

    Args:
        tenant_label (str): Tenant label that owns this DKDM
        dkdm_file_path (str): Path to DKDM XML file

    Returns:
        int: DKDM ID in database
    """
    dao = get_dao()

    # Get tenant
    tenant = dao.get_tenant_by_label(tenant_label)
    if not tenant:
        print(f"❌ Tenant '{tenant_label}' not found")
        raise ValueError(f"Tenant '{tenant_label}' not found")

    if not Path(dkdm_file_path).exists():
        print(f"❌ DKDM file not found: {dkdm_file_path}")
        raise FileNotFoundError(f"DKDM file not found: {dkdm_file_path}")

    try:
        dkdm_id = dao.import_dkdm_from_file(tenant.id, dkdm_file_path)
        print(f"✅ DKDM imported with ID: {dkdm_id}")
        return dkdm_id
    except Exception as e:
        print(f"❌ Failed to import DKDM: {e}")
        raise


def remove_dkdm(dkdm_id: int):
    """
    Remove (deactivate) a DKDM from the system.

    Args:
        dkdm_id (int): DKDM ID to remove

    Returns:
        bool: True if successful
    """
    # TODO: Implement DKDM removal in DAO
    print(f"🔄 DKDM removal not yet implemented for ID: {dkdm_id}")
    return False


def list_dkdm(tenant_label: str = None, active_only: bool = True):
    """
    List all DKDMs in the system.

    Args:
        tenant_label (str): Optional filter by tenant label
        active_only (bool): If True, only show active DKDMs

    Returns:
        list: List of DKDM records
    """
    # TODO: Implement DKDM listing in DAO
    print("🔄 DKDM listing not yet implemented")
    return []


def add_cpl(tenant_label: str, cpl_file_path: str):
    """
    Import and register a CPL file.

    Args:
        tenant_label (str): Tenant label that owns this CPL
        cpl_file_path (str): Path to CPL XML file

    Returns:
        int: CPL ID in database
    """
    dao = get_dao()

    # Get tenant
    tenant = dao.get_tenant_by_label(tenant_label)
    if not tenant:
        print(f"❌ Tenant '{tenant_label}' not found")
        raise ValueError(f"Tenant '{tenant_label}' not found")

    if not Path(cpl_file_path).exists():
        print(f"❌ CPL file not found: {cpl_file_path}")
        raise FileNotFoundError(f"CPL file not found: {cpl_file_path}")

    try:
        cpl_id = dao.import_cpl_from_file(tenant.id, cpl_file_path)
        print(f"✅ CPL imported with ID: {cpl_id}")
        return cpl_id
    except Exception as e:
        print(f"❌ Failed to import CPL: {e}")
        raise


def remove_cpl(cpl_id: int):
    """
    Remove (deactivate) a CPL from the system.

    Args:
        cpl_id (int): CPL ID to remove

    Returns:
        bool: True if successful
    """
    # TODO: Implement CPL removal in DAO
    print(f"🔄 CPL removal not yet implemented for ID: {cpl_id}")
    return False


def list_cpl(tenant_label: str = None, active_only: bool = True):
    """
    List all CPLs in the system.

    Args:
        tenant_label (str): Optional filter by tenant label
        active_only (bool): If True, only show active CPLs

    Returns:
        list: List of CPL records
    """
    # TODO: Implement CPL listing in DAO
    print("🔄 CPL listing not yet implemented")
    return []


def add_certificate(cert_path: str, key_path: str, name: str):
    """
    Import and register a certificate (alias for add_self_signed_certificate).

    Args:
        cert_path (str): Path to certificate PEM file
        key_path (str): Path to private key PEM file
        name (str): Certificate name/identifier

    Returns:
        int: Certificate ID in database
    """
    return add_self_signed_certificate(cert_path, key_path, name)


def remove_certificate(cert_id: int):
    """
    Remove (deactivate) a certificate from the system.

    Args:
        cert_id (int): Certificate ID to remove

    Returns:
        bool: True if successful
    """
    # TODO: Implement certificate removal in DAO
    print(f"🔄 Certificate removal not yet implemented for ID: {cert_id}")
    return False


def list_certificate(active_only: bool = True):
    """
    List all certificates in the system.

    Args:
        active_only (bool): If True, only show active certificates

    Returns:
        list: List of certificate records
    """
    # TODO: Implement certificate listing in DAO
    print("🔄 Certificate listing not yet implemented")
    return []


def show_database_stats():
    """
    Show comprehensive database statistics.

    Returns:
        dict: Database statistics
    """
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

    return stats


def init_database(reset: bool = False):
    """
    Initialize the KDM database.

    Args:
        reset (bool): If True, reset existing database

    Returns:
        bool: True if successful
    """
    try:
        if reset:
            from db.schema import reset_database
            db = reset_database()
        else:
            db = get_database()

        schema_info = db.get_schema_info()
        print(f"✅ Database initialized: {schema_info['database_path']}")
        print(f"📊 Total tables: {schema_info['total_tables']}")
        return True
    except Exception as e:
        print(f"❌ Failed to initialize database: {e}")
        return False
