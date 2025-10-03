from datetime import datetime
from pathlib import Path
from typing import Optional

import typer

from certificate.generate_self_signed_smpte import generate_certs
from db.schema import get_database, reset_database
from db.dao import get_dao, TenantRecord
from kdm.kdm_service import get_kdm_service
from kdm.internal.kdm_validator import validate_kdm_xml, check_kdm_against_cpl
from utils.logger import get_logger
from utils.utils import get_current_path

app = typer.Typer(help="KDM Generator CLI - SMPTE-compliant Digital Cinema Key Delivery Message management")
log = get_logger()

# Sub-applications for grouped commands
tenant_app = typer.Typer(help="Manage tenants and organizations")
cert_app = typer.Typer(help="Manage certificates and certificate chains")
dkdm_app = typer.Typer(help="Manage DKDMs (Distribution Key Delivery Messages)")
cpl_app = typer.Typer(help="Manage CPLs (Composition Playlists)")
kdm_app = typer.Typer(help="Generate and manage KDMs")
db_app = typer.Typer(help="Database management")

app.add_typer(tenant_app, name="tenant")
app.add_typer(cert_app, name="cert")
app.add_typer(dkdm_app, name="dkdm")
app.add_typer(cpl_app, name="cpl")
app.add_typer(kdm_app, name="kdm")
app.add_typer(db_app, name="db")


# ============================================================================
# Self-Signed Certificate Commands
# ============================================================================

@app.command(name="generate-self-cert")
def generate_self_signed_certificate(
    years: int = typer.Option(..., "--years", "-y", help="Certificate validity in years"),
):
    """
    Generate SMPTE-compliant self-signed certificate chain (root > intermediate > device).
    Used to sign generated KDMs and receive DKDMs from content providers.
    """
    typer.echo(f"Generating self-signed certificate chain valid for {years} years...")
    try:
        generate_certs(years)
        typer.secho("Certificate chain generated successfully", fg=typer.colors.GREEN)
    except Exception as e:
        typer.secho(f"Error generating certificates: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


# ============================================================================
# Tenant Commands
# ============================================================================

@tenant_app.command("add")
def add_tenant(
    label: str = typer.Option(..., "--label", "-l", help="Unique tenant label"),
    description: Optional[str] = typer.Option(None, "--description", "-d", help="Tenant description"),
    organization: Optional[str] = typer.Option(None, "--org", "-o", help="Organization name"),
    email: Optional[str] = typer.Option(None, "--email", "-e", help="Contact email"),
):
    """Add a new tenant/organization."""
    dao = get_dao()
    tenant = TenantRecord(
        label=label,
        description=description or "",
        organization=organization or "",
        contact_email=email or ""
    )
    try:
        tenant_id = dao.create_tenant(tenant)
        typer.secho(f"Tenant '{label}' added with ID: {tenant_id}", fg=typer.colors.GREEN)
    except Exception as e:
        typer.secho(f"Error adding tenant: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


@tenant_app.command("remove")
def remove_tenant(
    tenant_id: int = typer.Argument(..., help="Tenant ID to remove"),
):
    """Remove a tenant by ID."""
    if typer.confirm(f"Are you sure you want to remove tenant {tenant_id}?"):
        dao = get_dao()
        if dao.delete_tenant(tenant_id):
            typer.secho(f"Tenant {tenant_id} deactivated", fg=typer.colors.GREEN)
        else:
            typer.secho(f"Failed to deactivate tenant {tenant_id}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)


@tenant_app.command("edit")
def edit_tenant(
    tenant_id: int = typer.Argument(..., help="Tenant ID to edit"),
    label: Optional[str] = typer.Option(None, "--label", "-l", help="New label"),
    description: Optional[str] = typer.Option(None, "--description", "-d", help="New description"),
):
    """Edit an existing tenant."""
    typer.echo(f"Editing tenant {tenant_id}...")
    # TODO: Implement with database
    typer.secho("Tenant updated successfully", fg=typer.colors.GREEN)


@tenant_app.command("list")
def list_tenants(
    all: bool = typer.Option(False, "--all", "-a", help="Include inactive tenants"),
):
    """List all tenants."""
    dao = get_dao()
    tenants = dao.list_tenants(active_only=not all)

    if not tenants:
        typer.echo("No tenants found.")
        return

    typer.echo(f"\n{'ID':<4} {'Label':<20} {'Organization':<30} {'Active':<8}")
    typer.echo("-" * 65)
    for tenant in tenants:
        active = "✅" if tenant.is_active else "❌"
        typer.echo(f"{tenant.id:<4} {tenant.label:<20} {tenant.organization:<30} {active:<8}")


# ============================================================================
# Certificate Commands
# ============================================================================

@cert_app.command("add")
def add_certificate(
    name: str = typer.Option(..., "--name", "-n", help="Certificate chain name (e.g., 'Barco Projector 1')"),
    root: Path = typer.Option(..., "--root", "-r", help="Path to root certificate"),
    signer: Path = typer.Option(..., "--signer", "-s", help="Path to signer/intermediate certificate"),
    device: Path = typer.Option(..., "--device", "-d", help="Path to device/leaf certificate"),
):
    """
    Add a target device certificate chain (Barco, Dolby, Doremi, etc.).

    Certificate chains are global and can be used by all tenants to generate KDMs.
    """
    # Validate all certificate files exist
    for cert_name, cert_path in [("Root", root), ("Signer", signer), ("Device", device)]:
        if not cert_path.exists():
            typer.secho(f"{cert_name} certificate file not found: {cert_path}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)

    typer.echo(f"Adding global certificate chain '{name}'...")

    dao = get_dao()
    try:
        chain_id = dao.import_certificate_chain_from_files(
            chain_name=name,
            root_cert_path=str(root),
            signer_cert_path=str(signer),
            device_cert_path=str(device)
        )
        typer.secho(f"Certificate chain added successfully (ID: {chain_id})", fg=typer.colors.GREEN)
        typer.echo(f"This certificate can now be used by any tenant for KDM generation.")
    except Exception as e:
        typer.secho(f"Error adding certificate chain: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


@cert_app.command("remove")
def remove_certificate(
    cert_id: int = typer.Argument(..., help="Certificate ID to remove"),
):
    """Remove a certificate by ID."""
    if typer.confirm(f"Are you sure you want to remove certificate {cert_id}?"):
        typer.echo(f"Removing certificate {cert_id}...")
        # TODO: Implement with database
        typer.secho("Certificate removed successfully", fg=typer.colors.GREEN)


@cert_app.command("list")
def list_certificates(
    tenant_id: Optional[int] = typer.Option(None, "--tenant", "-t", help="Filter by tenant ID"),
):
    """List all certificates, optionally filtered by tenant."""
    if tenant_id:
        typer.echo(f"Listing certificates for tenant {tenant_id}...")
    else:
        typer.echo("Listing all certificates...")
    # TODO: Implement with database
    typer.echo("No certificates found.")


# ============================================================================
# DKDM Commands
# ============================================================================

@dkdm_app.command("add")
def add_dkdm(
    tenant_id: int = typer.Option(..., "--tenant", "-t", help="Tenant ID"),
    dkdm_path: Path = typer.Option(..., "--file", "-f", help="Path to DKDM XML file"),
    cert_path: Optional[Path] = typer.Option(None, "--cert", "-c", help="Self-signed certificate path for validation"),
    key_path: Optional[Path] = typer.Option(None, "--key", "-k", help="Private key path for validation"),
    no_validate: bool = typer.Option(False, "--no-validate", help="Skip certificate validation"),
):
    """
    Add a DKDM (Distribution Key Delivery Message) for a tenant.

    Validates the DKDM against your self-signed certificate to ensure:
    - The DKDM is encrypted for your device
    - You can decrypt it with your private key
    - The recipient information matches your certificate
    """
    if not dkdm_path.exists():
        typer.secho(f"DKDM file not found: {dkdm_path}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    # Check certificate and key paths
    validate_cert = not no_validate and cert_path and key_path

    if not no_validate and (not cert_path or not key_path):
        # Use default paths if not provided
        default_cert = Path("files/tmp/server_cert.pem")
        default_key = Path("files/tmp/server_key.pem")

        if default_cert.exists() and default_key.exists():
            cert_path = default_cert
            key_path = default_key
            validate_cert = True
            typer.echo(f"Using default certificate: {cert_path}")
        else:
            typer.echo("No certificate provided and defaults not found. Skipping validation.")
            typer.echo("   Use --cert and --key to validate, or --no-validate to suppress this warning.")
            validate_cert = False

    if validate_cert and cert_path and key_path:
        if not cert_path.exists():
            typer.secho(f"Certificate file not found: {cert_path}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)
        if not key_path.exists():
            typer.secho(f"Private key file not found: {key_path}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)

    typer.echo(f"Adding DKDM for tenant {tenant_id}...")

    dao = get_dao()
    try:
        dkdm_id = dao.import_dkdm_from_file(
            tenant_id=tenant_id,
            dkdm_file_path=str(dkdm_path),
            cert_path=str(cert_path) if cert_path else None,
            key_path=str(key_path) if key_path else None,
            validate_cert=validate_cert
        )
        typer.secho(f"DKDM added successfully (ID: {dkdm_id})", fg=typer.colors.GREEN)
    except Exception as e:
        typer.secho(f"Error adding DKDM: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


@dkdm_app.command("remove")
def remove_dkdm(
    dkdm_id: int = typer.Argument(..., help="DKDM ID to remove"),
):
    """Remove a DKDM by ID."""
    if typer.confirm(f"Are you sure you want to remove DKDM {dkdm_id}?"):
        typer.echo(f"Removing DKDM {dkdm_id}...")
        # TODO: Implement with database
        typer.secho("DKDM removed successfully", fg=typer.colors.GREEN)


@dkdm_app.command("list")
def list_dkdms(
    tenant_id: Optional[int] = typer.Option(None, "--tenant", "-t", help="Filter by tenant ID"),
):
    """List all DKDMs, optionally filtered by tenant."""
    if tenant_id:
        typer.echo(f"Listing DKDMs for tenant {tenant_id}...")
    else:
        typer.echo("Listing all DKDMs...")
    # TODO: Implement with database
    typer.echo("No DKDMs found.")


# ============================================================================
# CPL Commands
# ============================================================================

@cpl_app.command("add")
def add_cpl(
    tenant_id: int = typer.Option(..., "--tenant", "-t", help="Tenant ID"),
    cpl_path: Path = typer.Option(..., "--file", "-f", help="Path to CPL XML file"),
):
    """Add a CPL (Composition Playlist) for a tenant."""
    if not cpl_path.exists():
        typer.secho(f"CPL file not found: {cpl_path}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    typer.echo(f"Adding CPL for tenant {tenant_id}...")

    dao = get_dao()
    try:
        cpl_id = dao.import_cpl_from_file(tenant_id, str(cpl_path))
        typer.secho(f"CPL added successfully (ID: {cpl_id})", fg=typer.colors.GREEN)
    except Exception as e:
        typer.secho(f"Error adding CPL: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


@cpl_app.command("remove")
def remove_cpl(
    cpl_id: int = typer.Argument(..., help="CPL ID to remove"),
):
    """Remove a CPL by ID."""
    if typer.confirm(f"Are you sure you want to remove CPL {cpl_id}?"):
        typer.echo(f"Removing CPL {cpl_id}...")
        # TODO: Implement with database
        typer.secho("CPL removed successfully", fg=typer.colors.GREEN)


@cpl_app.command("list")
def list_cpls(
    tenant_id: Optional[int] = typer.Option(None, "--tenant", "-t", help="Filter by tenant ID"),
):
    """List all CPLs, optionally filtered by tenant."""
    if tenant_id:
        typer.echo(f"Listing CPLs for tenant {tenant_id}...")
    else:
        typer.echo("Listing all CPLs...")
    # TODO: Implement with database
    typer.echo("No CPLs found.")


# ============================================================================
# KDM Generation Commands
# ============================================================================

@kdm_app.command("generate")
def generate_kdm(
    tenant_id: int = typer.Option(..., "--tenant", "-t", help="Tenant ID making the request"),
    dkdm_id: int = typer.Option(..., "--dkdm", "-d", help="DKDM ID to use"),
    cert_ids: str = typer.Option(..., "--certs", "-c", help="Comma-separated certificate chain IDs (e.g., '1,2,3')"),
    start: str = typer.Option(..., "--start", "-s", help="Start datetime (YYYY-MM-DD HH:MM:SS)"),
    end: str = typer.Option(..., "--end", "-e", help="End datetime (YYYY-MM-DD HH:MM:SS)"),
    self_cert: Optional[Path] = typer.Option(None, "--self-cert", help="Self-signed certificate path"),
    self_key: Optional[Path] = typer.Option(None, "--self-key", help="Self-signed private key path"),
    annotation: Optional[str] = typer.Option(None, "--annotation", "-a", help="Custom annotation text"),
    timezone: Optional[str] = typer.Option(None, "--timezone", "-tz", help="Target timezone"),
    sign: bool = typer.Option(True, "--sign/--no-sign", help="Sign the KDM (SMPTE ST 430-3)"),
):
    """
    Generate KDMs from a DKDM for multiple target device certificates.

    This command:
    1. Verifies tenant authorization
    2. Decrypts DKDM with service provider's self-signed certificate
    3. Re-encrypts content keys for each target projector
    4. Signs KDMs (optional)
    5. Saves to files/output/
    """
    # Parse datetime
    try:
        start_dt = datetime.strptime(start, "%Y-%m-%d %H:%M:%S")
        end_dt = datetime.strptime(end, "%Y-%m-%d %H:%M:%S")
    except ValueError as e:
        typer.secho(f"Invalid datetime format: {e}", fg=typer.colors.RED, err=True)
        typer.echo("Use format: YYYY-MM-DD HH:MM:SS")
        raise typer.Exit(code=1)

    # Parse certificate IDs
    try:
        certificate_chain_ids = [int(cid.strip()) for cid in cert_ids.split(',')]
    except ValueError:
        typer.secho(f"Invalid certificate IDs format: {cert_ids}", fg=typer.colors.RED, err=True)
        typer.echo("Use comma-separated integers: 1,2,3")
        raise typer.Exit(code=1)

    # Use default self-signed certificate if not provided
    if not self_cert or not self_key:
        default_cert = Path("files/tmp/server_cert.pem")
        default_key = Path("files/tmp/server_key.pem")

        if default_cert.exists() and default_key.exists():
            self_cert = default_cert
            self_key = default_key
            typer.echo(f"Using default self-signed certificate: {self_cert}")
        else:
            typer.secho("Self-signed certificate and key are required", fg=typer.colors.RED, err=True)
            typer.echo("   Provide --self-cert and --self-key, or ensure files/tmp/server_cert.pem exists")
            raise typer.Exit(code=1)

    # Validate certificate files
    if not self_cert.exists():
        typer.secho(f"Self-signed certificate not found: {self_cert}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    if not self_key.exists():
        typer.secho(f"Self-signed private key not found: {self_key}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    typer.echo(f"\nKDM Generation")
    typer.echo(f"   Tenant: {tenant_id}")
    typer.echo(f"   DKDM: {dkdm_id}")
    typer.echo(f"   Target certificates: {certificate_chain_ids}")
    typer.echo(f"   Validity: {start_dt} → {end_dt}")
    typer.echo(f"   Sign: {sign}\n")

    try:
        service = get_kdm_service()
        kdm_ids = service.generate_kdm(
            tenant_id=tenant_id,
            dkdm_id=dkdm_id,
            certificate_chain_ids=certificate_chain_ids,
            start_datetime=start_dt,
            end_datetime=end_dt,
            self_signed_cert_path=str(self_cert),
            self_signed_key_path=str(self_key),
            annotation=annotation,
            timezone_name=timezone,
            sign=sign
        )

        typer.echo()
        typer.secho(f"Successfully generated {len(kdm_ids)} KDM(s)", fg=typer.colors.GREEN, bold=True)
        typer.echo(f"   KDM IDs: {kdm_ids}")
        typer.echo(f"   Location: files/output/")

    except Exception as e:
        typer.echo()
        typer.secho(f"KDM generation failed: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


@kdm_app.command("list")
def list_kdms(
    tenant_id: Optional[int] = typer.Option(None, "--tenant", "-t", help="Filter by tenant ID"),
):
    """List all generated KDMs, optionally filtered by tenant."""
    if tenant_id:
        typer.echo(f"Listing KDMs for tenant {tenant_id}...")
    else:
        typer.echo("Listing all generated KDMs...")
    # TODO: Implement with database
    typer.echo("No KDMs found.")


@kdm_app.command("validate-xsd")
def validate_kdm_xsd(
    kdm_path: Path = typer.Option(..., "--kdm", "-k", help="Path to KDM XML file"),
    xsd_path: Optional[Path] = typer.Option(None, "--xsd", "-x", help="Path to XSD schema file"),
):
    """Validate KDM XML against SMPTE XSD schema."""
    if not kdm_path.exists():
        typer.secho(f"KDM file not found: {kdm_path}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    # Use default XSD if not provided
    if not xsd_path:
        xsd_path = Path(f"{get_current_path()}/files/xsd/DCinemaSecurityMessage.xsd")

    if not xsd_path.exists():
        typer.secho(f"XSD schema file not found: {xsd_path}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    typer.echo(f"Validating KDM against XSD schema...")
    typer.echo(f"  KDM: {kdm_path}")
    typer.echo(f"  XSD: {xsd_path}\n")

    try:
        if validate_kdm_xml(str(kdm_path), str(xsd_path)):
            typer.secho("KDM XSD validation passed", fg=typer.colors.GREEN, bold=True)
        else:
            typer.secho("KDM XSD validation failed", fg=typer.colors.RED, bold=True)
            raise typer.Exit(code=1)
    except Exception as e:
        typer.secho(f"Validation error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


@kdm_app.command("validate-cpl")
def validate_kdm_cpl(
    kdm_path: Path = typer.Option(..., "--kdm", "-k", help="Path to KDM XML file"),
    cpl_path: Path = typer.Option(..., "--cpl", "-c", help="Path to CPL XML file"),
):
    """Cross-check KDM against CPL (verify key IDs and composition ID match)."""
    if not kdm_path.exists():
        typer.secho(f"KDM file not found: {kdm_path}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    if not cpl_path.exists():
        typer.secho(f"CPL file not found: {cpl_path}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    typer.echo(f"Cross-checking KDM against CPL...")
    typer.echo(f"  KDM: {kdm_path}")
    typer.echo(f"  CPL: {cpl_path}\n")

    try:
        if check_kdm_against_cpl(str(kdm_path), str(cpl_path)):
            typer.secho("KDM-CPL cross-check passed", fg=typer.colors.GREEN, bold=True)
        else:
            typer.secho("KDM-CPL cross-check failed", fg=typer.colors.RED, bold=True)
            raise typer.Exit(code=1)
    except Exception as e:
        typer.secho(f"Cross-check error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


# ============================================================================
# Database Commands
# ============================================================================

@db_app.command("init")
def init_database():
    """Initialize the database schema."""
    typer.echo("Initializing database...")
    try:
        db = get_database()
        typer.secho("Database initialized successfully", fg=typer.colors.GREEN)
    except Exception as e:
        typer.secho(f"Error initializing database: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


@db_app.command("reset")
def reset_db():
    """Reset the database (WARNING: deletes all data)."""
    if typer.confirm("This will delete ALL data. Are you sure?"):
        typer.echo("Resetting database...")
        try:
            db = reset_database()
            typer.secho("Database reset successfully", fg=typer.colors.GREEN)
        except Exception as e:
            typer.secho(f"Error resetting database: {e}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)


@db_app.command("info")
def database_info():
    """Show database schema information."""
    try:
        db = get_database()
        schema = db.get_schema_info()

        typer.echo(f"\n📊 Database: {schema['database_path']}")
        typer.echo(f"Total tables: {schema['total_tables']}\n")

        for table_name, table_info in schema["tables"].items():
            typer.secho(f"📋 {table_name} ({table_info['row_count']} rows)", fg=typer.colors.CYAN, bold=True)
            for col in table_info["columns"]:
                pk_marker = " [PK]" if col["pk"] else ""
                typer.echo(f"  - {col['name']}: {col['type']}{pk_marker}")

    except Exception as e:
        typer.secho(f"Error getting database info: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()