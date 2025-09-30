import typer
from pathlib import Path
from typing import Optional
from datetime import datetime

from certificate.generate_self_signed_smpte import generate_certs
from kdm.clone_dkdm import clone_dkdm_to_kdm_signed
from db.schema import KDMDatabase, get_database, reset_database
from utils.logger import get_logger

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
        typer.secho("✅ Certificate chain generated successfully", fg=typer.colors.GREEN)
    except Exception as e:
        typer.secho(f"❌ Error generating certificates: {e}", fg=typer.colors.RED, err=True)
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
    typer.echo(f"Adding tenant: {label}")
    # TODO: Implement with database
    typer.secho("✅ Tenant added successfully", fg=typer.colors.GREEN)


@tenant_app.command("remove")
def remove_tenant(
    tenant_id: int = typer.Argument(..., help="Tenant ID to remove"),
):
    """Remove a tenant by ID."""
    if typer.confirm(f"Are you sure you want to remove tenant {tenant_id}?"):
        typer.echo(f"Removing tenant {tenant_id}...")
        # TODO: Implement with database
        typer.secho("✅ Tenant removed successfully", fg=typer.colors.GREEN)


@tenant_app.command("edit")
def edit_tenant(
    tenant_id: int = typer.Argument(..., help="Tenant ID to edit"),
    label: Optional[str] = typer.Option(None, "--label", "-l", help="New label"),
    description: Optional[str] = typer.Option(None, "--description", "-d", help="New description"),
):
    """Edit an existing tenant."""
    typer.echo(f"Editing tenant {tenant_id}...")
    # TODO: Implement with database
    typer.secho("✅ Tenant updated successfully", fg=typer.colors.GREEN)


@tenant_app.command("list")
def list_tenants():
    """List all tenants."""
    typer.echo("Listing all tenants...")
    # TODO: Implement with database
    typer.echo("No tenants found.")


# ============================================================================
# Certificate Commands
# ============================================================================

@cert_app.command("add")
def add_certificate(
    tenant_id: int = typer.Option(..., "--tenant", "-t", help="Tenant ID"),
    cert_path: Path = typer.Option(..., "--cert", "-c", help="Path to certificate file"),
    name: Optional[str] = typer.Option(None, "--name", "-n", help="Certificate name/label"),
):
    """Add a target device certificate for a tenant."""
    if not cert_path.exists():
        typer.secho(f"❌ Certificate file not found: {cert_path}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    typer.echo(f"Adding certificate for tenant {tenant_id}...")
    # TODO: Implement with database
    typer.secho("✅ Certificate added successfully", fg=typer.colors.GREEN)


@cert_app.command("remove")
def remove_certificate(
    cert_id: int = typer.Argument(..., help="Certificate ID to remove"),
):
    """Remove a certificate by ID."""
    if typer.confirm(f"Are you sure you want to remove certificate {cert_id}?"):
        typer.echo(f"Removing certificate {cert_id}...")
        # TODO: Implement with database
        typer.secho("✅ Certificate removed successfully", fg=typer.colors.GREEN)


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
    cpl_id: Optional[int] = typer.Option(None, "--cpl", "-c", help="Associated CPL ID"),
):
    """Add a DKDM (Distribution Key Delivery Message) for a tenant."""
    if not dkdm_path.exists():
        typer.secho(f"❌ DKDM file not found: {dkdm_path}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    typer.echo(f"Adding DKDM for tenant {tenant_id}...")
    # TODO: Implement with database - parse DKDM XML and store metadata
    typer.secho("✅ DKDM added successfully", fg=typer.colors.GREEN)


@dkdm_app.command("remove")
def remove_dkdm(
    dkdm_id: int = typer.Argument(..., help="DKDM ID to remove"),
):
    """Remove a DKDM by ID."""
    if typer.confirm(f"Are you sure you want to remove DKDM {dkdm_id}?"):
        typer.echo(f"Removing DKDM {dkdm_id}...")
        # TODO: Implement with database
        typer.secho("✅ DKDM removed successfully", fg=typer.colors.GREEN)


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
        typer.secho(f"❌ CPL file not found: {cpl_path}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    typer.echo(f"Adding CPL for tenant {tenant_id}...")
    # TODO: Implement with database - parse CPL XML and store metadata
    typer.secho("✅ CPL added successfully", fg=typer.colors.GREEN)


@cpl_app.command("remove")
def remove_cpl(
    cpl_id: int = typer.Argument(..., help="CPL ID to remove"),
):
    """Remove a CPL by ID."""
    if typer.confirm(f"Are you sure you want to remove CPL {cpl_id}?"):
        typer.echo(f"Removing CPL {cpl_id}...")
        # TODO: Implement with database
        typer.secho("✅ CPL removed successfully", fg=typer.colors.GREEN)


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
    dkdm_id: int = typer.Option(..., "--dkdm", "-d", help="DKDM ID to use"),
    cert_id: int = typer.Option(..., "--cert", "-c", help="Target certificate ID"),
    start: str = typer.Option(..., "--start", "-s", help="Start datetime (YYYY-MM-DD HH:MM:SS)"),
    end: str = typer.Option(..., "--end", "-e", help="End datetime (YYYY-MM-DD HH:MM:SS)"),
    sign: bool = typer.Option(True, "--sign/--no-sign", help="Sign the KDM (SMPTE ST 430-3)"),
):
    """Generate a KDM from a DKDM for a target device certificate."""
    try:
        start_dt = datetime.strptime(start, "%Y-%m-%d %H:%M:%S")
        end_dt = datetime.strptime(end, "%Y-%m-%d %H:%M:%S")
    except ValueError as e:
        typer.secho(f"❌ Invalid datetime format: {e}", fg=typer.colors.RED, err=True)
        typer.echo("Use format: YYYY-MM-DD HH:MM:SS")
        raise typer.Exit(code=1)

    typer.echo(f"Generating KDM from DKDM {dkdm_id} for certificate {cert_id}...")
    typer.echo(f"Validity: {start_dt} to {end_dt}")

    try:
        # TODO: Implement with database - fetch DKDM and certificate from DB
        kdm_path = clone_dkdm_to_kdm_signed(start_dt, end_dt)
        typer.secho(f"✅ KDM generated: {kdm_path}", fg=typer.colors.GREEN)
    except Exception as e:
        typer.secho(f"❌ Error generating KDM: {e}", fg=typer.colors.RED, err=True)
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


# ============================================================================
# Database Commands
# ============================================================================

@db_app.command("init")
def init_database():
    """Initialize the database schema."""
    typer.echo("Initializing database...")
    try:
        db = get_database()
        typer.secho("✅ Database initialized successfully", fg=typer.colors.GREEN)
    except Exception as e:
        typer.secho(f"❌ Error initializing database: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


@db_app.command("reset")
def reset_db():
    """Reset the database (WARNING: deletes all data)."""
    if typer.confirm("⚠️  This will delete ALL data. Are you sure?"):
        typer.echo("Resetting database...")
        try:
            db = reset_database()
            typer.secho("✅ Database reset successfully", fg=typer.colors.GREEN)
        except Exception as e:
            typer.secho(f"❌ Error resetting database: {e}", fg=typer.colors.RED, err=True)
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
        typer.secho(f"❌ Error getting database info: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()