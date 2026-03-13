"""
certmesh.cli
==============

Command-line interface for the certmesh package.

Installed as the ``certmesh`` console script via ``pyproject.toml``.

Usage::

    certmesh [OPTIONS] COMMAND [ARGS]...

    # DigiCert full lifecycle
    certmesh digicert list
    certmesh digicert search --cn api.example.com
    certmesh digicert describe --order-id 12345
    certmesh digicert order --cn api.example.com --san api2.example.com
    certmesh digicert download --order-id 12345 --cert-id 67890
    certmesh digicert revoke --cert-id 67890 --reason key_compromise
    certmesh digicert duplicate --order-id 12345 --cn new.example.com

    # Venafi full lifecycle
    certmesh venafi list --policy-dn "\\VED\\Policy\\Certificates"
    certmesh venafi search --cn api.example.com
    certmesh venafi describe --guid "{...}"
    certmesh venafi request --policy-dn "\\VED\\Policy\\Certs" --cn api.example.com
    certmesh venafi renew --guid "{...}"
    certmesh venafi renew-bulk --guid-file guids.txt
    certmesh venafi revoke --dn "\\VED\\Policy\\Certs\\api.example.com"
    certmesh venafi download --guid "{...}"

    # Vault PKI full lifecycle
    certmesh vault-pki issue --cn myservice.example.com --ttl 720h
    certmesh vault-pki sign --cn myservice.example.com --csr-file req.pem
    certmesh vault-pki list
    certmesh vault-pki read --serial 39:dd:2e:...
    certmesh vault-pki revoke --serial 39:dd:2e:...

    # AWS ACM full lifecycle
    certmesh acm request --cn myapp.example.com --validation dns
    certmesh acm list
    certmesh acm describe --arn arn:aws:acm:...
    certmesh acm export --arn arn:aws:acm:... --passphrase mysecret
    certmesh acm renew --arn arn:aws:acm:...
    certmesh acm delete --arn arn:aws:acm:...
    certmesh acm validation-records --arn arn:aws:acm:...
    certmesh acm wait --arn arn:aws:acm:...

    # AWS ACM Private CA
    certmesh acm-pca issue --ca-arn arn:aws:acm-pca:... --cn internal.example.com
    certmesh acm-pca get --ca-arn arn:aws:acm-pca:... --cert-arn arn:aws:acm-pca:...
    certmesh acm-pca revoke --ca-arn arn:aws:acm-pca:... --cert-serial 1234 --reason KEY_COMPROMISE
    certmesh acm-pca list --ca-arn arn:aws:acm-pca:...

    # Config management
    certmesh config show
    certmesh config validate

Exit codes: 0=success, 1=config/auth error, 2=cert operation error, 3=unexpected.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

import click

from certmesh import __version__
from certmesh.exceptions import (
    ACMError,
    CertificateError,
    CertMeshError,
    ConfigurationError,
    DigiCertError,
    VaultError,
    VaultPKIError,
    VenafiError,
)
from certmesh.settings import build_config, configure_logging, validate_config

logger = logging.getLogger(__name__)

JsonDict = dict[str, Any]


# =============================================================================
# Root group
# =============================================================================


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="certmesh")
@click.option(
    "--config",
    "config_file",
    type=click.Path(exists=False),
    default=None,
    help="Path to YAML config file.",
)
@click.option(
    "--env-file",
    type=click.Path(exists=True),
    default=None,
    help="Path to .env file to load before config evaluation.",
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    default=None,
    help="Override log level.",
)
@click.pass_context
def cli(
    ctx: click.Context,
    config_file: str | None,
    env_file: str | None,
    log_level: str | None,
) -> None:
    """certmesh — Automated TLS certificate lifecycle management."""
    ctx.ensure_object(dict)

    if env_file:
        from dotenv import load_dotenv

        load_dotenv(env_file, override=True)

    import os

    if log_level:
        os.environ["CM_LOG_LEVEL"] = log_level

    cfg = build_config(config_file=config_file)
    configure_logging(cfg["logging"])
    ctx.obj["cfg"] = cfg


# =============================================================================
# Helpers
# =============================================================================


def _get_vault_client(cfg: JsonDict) -> Any:
    """Lazily build and authenticate a Vault client if needed."""
    from certmesh import vault_client as vc
    from certmesh.credentials import vault_required

    if not vault_required(cfg):
        return None
    return vc.get_authenticated_client(cfg["vault"])


def _handle_error(exc: Exception) -> None:
    """Map exceptions to exit codes and print user-friendly messages."""
    # Check VaultPKIError before VaultError (VaultPKIError is a subclass of VaultError).
    if isinstance(exc, (DigiCertError, VenafiError, ACMError, VaultPKIError, CertificateError)):
        click.echo(f"Certificate operation error: {exc}", err=True)
        sys.exit(2)
    elif isinstance(exc, (ConfigurationError, VaultError)):
        click.echo(f"Configuration/Auth error: {exc}", err=True)
        sys.exit(1)
    elif isinstance(exc, CertMeshError):
        click.echo(f"Error: {exc}", err=True)
        sys.exit(2)
    else:
        click.echo(f"Unexpected error: {exc}", err=True)
        logger.exception("Unhandled exception")
        sys.exit(3)


def _json_output(data: Any) -> None:
    """Print JSON to stdout."""
    click.echo(json.dumps(data, indent=2, default=str))


# =============================================================================
# DigiCert commands
# =============================================================================


@cli.group()
def digicert() -> None:
    """DigiCert CertCentral certificate lifecycle management."""


@digicert.command("list")
@click.option("--status", default="issued", help="Filter by status (issued, pending, etc.).")
@click.option("--limit", default=100, type=int, help="Max results per page (page_size).")
@click.pass_context
def digicert_list(ctx: click.Context, status: str, limit: int) -> None:
    """List certificates from DigiCert CertCentral."""
    try:
        from certmesh import digicert_client as dc

        cfg = ctx.obj["cfg"]
        vault_cl = _get_vault_client(cfg)
        results = dc.list_issued_certificates(
            cfg["digicert"],
            cfg["vault"],
            vault_cl,
            page_size=limit,
            status=status,
        )
        _json_output([vars(r) for r in results])
    except Exception as exc:
        _handle_error(exc)


@digicert.command("search")
@click.option("--cn", default=None, help="Common Name substring filter.")
@click.option("--serial", default=None, help="Serial number filter.")
@click.option("--status", default=None, help="Status filter.")
@click.option("--product", default=None, help="Product name_id filter.")
@click.pass_context
def digicert_search(
    ctx: click.Context,
    cn: str | None,
    serial: str | None,
    status: str | None,
    product: str | None,
) -> None:
    """Search certificates in DigiCert CertCentral."""
    try:
        from certmesh import digicert_client as dc

        cfg = ctx.obj["cfg"]
        vault_cl = _get_vault_client(cfg)
        results = dc.search_certificates(
            cfg["digicert"],
            cfg["vault"],
            vault_cl,
            common_name=cn,
            serial_number=serial,
            status=status,
            product_name_id=product,
        )
        _json_output([vars(r) for r in results])
    except Exception as exc:
        _handle_error(exc)


@digicert.command("describe")
@click.option("--cert-id", required=True, type=int, help="DigiCert certificate ID.")
@click.pass_context
def digicert_describe(ctx: click.Context, cert_id: int) -> None:
    """Get full detail for a DigiCert certificate."""
    try:
        from certmesh import digicert_client as dc

        cfg = ctx.obj["cfg"]
        vault_cl = _get_vault_client(cfg)
        detail = dc.describe_certificate(cfg["digicert"], cfg["vault"], vault_cl, cert_id)
        _json_output(vars(detail))
    except Exception as exc:
        _handle_error(exc)


@digicert.command("order")
@click.option("--cn", required=True, help="Common Name.")
@click.option("--san", multiple=True, help="Subject Alternative Name(s).")
@click.pass_context
def digicert_order(ctx: click.Context, cn: str, san: tuple[str, ...]) -> None:
    """Order a new certificate from DigiCert CertCentral.

    A private key and CSR are generated internally by the client.
    """
    try:
        from certmesh import digicert_client as dc

        cfg = ctx.obj["cfg"]
        vault_cl = _get_vault_client(cfg)
        req = dc.OrderRequest(common_name=cn, san_dns_names=list(san))
        bundle = dc.order_and_await_certificate(cfg["digicert"], cfg["vault"], vault_cl, req)
        click.echo(f"Certificate issued: CN={bundle.common_name}, serial={bundle.serial_number}")
        click.echo(f"Expires: {bundle.not_after.isoformat()}")
    except Exception as exc:
        _handle_error(exc)


@digicert.command("download")
@click.option("--cert-id", required=True, type=int, help="Certificate ID.")
@click.option(
    "--key-file",
    required=True,
    type=click.Path(exists=True),
    help="Path to the PEM-encoded private key file.",
)
@click.pass_context
def digicert_download(ctx: click.Context, cert_id: int, key_file: str) -> None:
    """Download an issued certificate from DigiCert.

    Requires the private key PEM file that was generated when the certificate
    was ordered.
    """
    try:
        from certmesh import digicert_client as dc

        cfg = ctx.obj["cfg"]
        vault_cl = _get_vault_client(cfg)
        with open(key_file) as f:
            private_key_pem = f.read()
        bundle = dc.download_issued_certificate(
            cfg["digicert"],
            cfg["vault"],
            vault_cl,
            cert_id,
            private_key_pem,
        )
        click.echo(f"Downloaded: CN={bundle.common_name}, serial={bundle.serial_number}")
    except Exception as exc:
        _handle_error(exc)


@digicert.command("revoke")
@click.option("--cert-id", default=None, type=int, help="Certificate ID to revoke.")
@click.option("--order-id", default=None, type=int, help="Order ID (used to resolve cert ID).")
@click.option(
    "--reason",
    default="unspecified",
    type=click.Choice(
        [
            "unspecified",
            "key_compromise",
            "ca_compromise",
            "affiliation_changed",
            "superseded",
            "cessation_of_operation",
        ]
    ),
    help="Revocation reason.",
)
@click.option("--comments", default="", help="Revocation comments.")
@click.pass_context
def digicert_revoke(
    ctx: click.Context,
    cert_id: int | None,
    order_id: int | None,
    reason: str,
    comments: str,
) -> None:
    """Revoke a DigiCert certificate."""
    if not cert_id and not order_id:
        click.echo("Error: either --cert-id or --order-id is required.", err=True)
        sys.exit(1)
    try:
        from certmesh import digicert_client as dc

        cfg = ctx.obj["cfg"]
        vault_cl = _get_vault_client(cfg)
        dc.revoke_certificate(
            cfg["digicert"],
            cfg["vault"],
            vault_cl,
            certificate_id=cert_id,
            order_id=order_id,
            reason=reason,
            comments=comments,
        )
        identifier = cert_id or order_id
        click.echo(f"Certificate {identifier} revoked (reason={reason}).")
    except Exception as exc:
        _handle_error(exc)


@digicert.command("duplicate")
@click.option("--order-id", required=True, type=int, help="Order ID to duplicate.")
@click.option("--csr-file", required=True, type=click.Path(exists=True), help="CSR PEM file.")
@click.option("--cn", default=None, help="Common Name for the duplicate (optional).")
@click.option("--san", multiple=True, help="Subject Alternative Name(s).")
@click.pass_context
def digicert_duplicate(
    ctx: click.Context,
    order_id: int,
    csr_file: str,
    cn: str | None,
    san: tuple[str, ...],
) -> None:
    """Request a duplicate certificate from DigiCert."""
    try:
        from certmesh import digicert_client as dc

        cfg = ctx.obj["cfg"]
        vault_cl = _get_vault_client(cfg)
        with open(csr_file) as f:
            csr_pem = f.read()
        result = dc.duplicate_certificate(
            cfg["digicert"],
            cfg["vault"],
            vault_cl,
            order_id,
            csr_pem,
            common_name=cn,
            san_dns_names=list(san) if san else None,
        )
        _json_output(result)
    except Exception as exc:
        _handle_error(exc)


# =============================================================================
# Venafi commands
# =============================================================================


@cli.group()
def venafi() -> None:
    """Venafi TPP certificate lifecycle management."""


@venafi.command("list")
@click.option("--limit", default=100, type=int, help="Max results.")
@click.option("--offset", default=0, type=int, help="Pagination offset.")
@click.pass_context
def venafi_list(ctx: click.Context, limit: int, offset: int) -> None:
    """List certificates in Venafi TPP."""
    try:
        from certmesh import venafi_client as vn

        cfg = ctx.obj["cfg"]
        vault_cl = _get_vault_client(cfg)
        session = vn.authenticate(cfg["venafi"], cfg["vault"], vault_cl)
        results = vn.list_certificates(
            session,
            cfg["venafi"],
            limit=limit,
            offset=offset,
        )
        _json_output([vars(r) for r in results])
    except Exception as exc:
        _handle_error(exc)


@venafi.command("search")
@click.option("--cn", default=None, help="Common Name filter.")
@click.option("--san", default=None, help="SAN DNS filter.")
@click.pass_context
def venafi_search(
    ctx: click.Context,
    cn: str | None,
    san: str | None,
) -> None:
    """Search certificates in Venafi TPP."""
    try:
        from certmesh import venafi_client as vn

        cfg = ctx.obj["cfg"]
        vault_cl = _get_vault_client(cfg)
        session = vn.authenticate(cfg["venafi"], cfg["vault"], vault_cl)
        results = vn.search_certificates(
            session,
            cfg["venafi"],
            common_name=cn,
            san_dns=san,
        )
        _json_output([vars(r) for r in results])
    except Exception as exc:
        _handle_error(exc)


@venafi.command("describe")
@click.option("--guid", required=True, help="Certificate GUID.")
@click.pass_context
def venafi_describe(ctx: click.Context, guid: str) -> None:
    """Get full detail for a Venafi certificate."""
    try:
        from certmesh import venafi_client as vn

        cfg = ctx.obj["cfg"]
        vault_cl = _get_vault_client(cfg)
        session = vn.authenticate(cfg["venafi"], cfg["vault"], vault_cl)
        detail = vn.describe_certificate(session, cfg["venafi"], certificate_guid=guid)
        _json_output(vars(detail))
    except Exception as exc:
        _handle_error(exc)


@venafi.command("request")
@click.option("--policy-dn", required=True, help="Venafi Policy DN.")
@click.option("--cn", required=True, help="Common Name.")
@click.option("--san", multiple=True, help="Subject Alternative Name(s).")
@click.option("--client-csr", is_flag=True, help="Generate CSR client-side.")
@click.pass_context
def venafi_request(
    ctx: click.Context,
    policy_dn: str,
    cn: str,
    san: tuple[str, ...],
    client_csr: bool,
) -> None:
    """Request a new certificate in Venafi TPP."""
    try:
        from certmesh import venafi_client as vn
        from certmesh.certificate_utils import SubjectInfo

        cfg = ctx.obj["cfg"]
        vault_cl = _get_vault_client(cfg)
        session = vn.authenticate(cfg["venafi"], cfg["vault"], vault_cl)
        subject = SubjectInfo(common_name=cn, san_dns_names=list(san))
        bundle = vn.request_certificate(
            session,
            cfg["venafi"],
            cfg["vault"],
            vault_cl,
            policy_dn=policy_dn,
            subject=subject,
            use_csr=client_csr,
        )
        click.echo(f"Certificate issued: CN={bundle.common_name}, serial={bundle.serial_number}")
    except Exception as exc:
        _handle_error(exc)


@venafi.command("renew")
@click.option("--guid", required=True, help="Certificate GUID.")
@click.pass_context
def venafi_renew(ctx: click.Context, guid: str) -> None:
    """Renew a certificate in Venafi TPP."""
    try:
        from certmesh import venafi_client as vn

        cfg = ctx.obj["cfg"]
        vault_cl = _get_vault_client(cfg)
        session = vn.authenticate(cfg["venafi"], cfg["vault"], vault_cl)
        bundle = vn.renew_and_download_certificate(
            session,
            cfg["venafi"],
            cfg["vault"],
            vault_cl,
            certificate_guid=guid,
        )
        click.echo(f"Renewed: CN={bundle.common_name}, serial={bundle.serial_number}")
        click.echo(f"Expires: {bundle.not_after.isoformat()}")
    except Exception as exc:
        _handle_error(exc)


@venafi.command("renew-bulk")
@click.option("--guid-file", required=True, type=click.Path(exists=True), help="File with GUIDs.")
@click.pass_context
def venafi_renew_bulk(ctx: click.Context, guid_file: str) -> None:
    """Renew multiple certificates from a GUID file."""
    try:
        from certmesh import venafi_client as vn

        cfg = ctx.obj["cfg"]
        vault_cl = _get_vault_client(cfg)
        session = vn.authenticate(cfg["venafi"], cfg["vault"], vault_cl)

        with open(guid_file) as f:
            guids = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        click.echo(f"Renewing {len(guids)} certificate(s)...")
        for i, guid in enumerate(guids, 1):
            try:
                bundle = vn.renew_and_download_certificate(
                    session,
                    cfg["venafi"],
                    cfg["vault"],
                    vault_cl,
                    certificate_guid=guid,
                )
                click.echo(f"  [{i}/{len(guids)}] OK: {guid} -> CN={bundle.common_name}")
            except VenafiError as exc:
                click.echo(f"  [{i}/{len(guids)}] FAIL: {guid} -> {exc}", err=True)
    except Exception as exc:
        _handle_error(exc)


@venafi.command("revoke")
@click.option("--dn", default=None, help="Certificate DN.")
@click.option("--thumbprint", default=None, help="Certificate thumbprint.")
@click.option("--reason", default=0, type=int, help="Revocation reason code (0-5).")
@click.option("--comments", default="", help="Revocation comments.")
@click.option("--disable", is_flag=True, help="Also disable the certificate object in TPP.")
@click.pass_context
def venafi_revoke(
    ctx: click.Context,
    dn: str | None,
    thumbprint: str | None,
    reason: int,
    comments: str,
    disable: bool,
) -> None:
    """Revoke a certificate in Venafi TPP."""
    if not dn and not thumbprint:
        click.echo("Error: either --dn or --thumbprint is required.", err=True)
        sys.exit(1)
    try:
        from certmesh import venafi_client as vn

        cfg = ctx.obj["cfg"]
        vault_cl = _get_vault_client(cfg)
        session = vn.authenticate(cfg["venafi"], cfg["vault"], vault_cl)
        vn.revoke_certificate(
            session,
            cfg["venafi"],
            certificate_dn=dn,
            thumbprint=thumbprint,
            reason=reason,
            comments=comments,
            disable=disable,
        )
        click.echo("Certificate revoked.")
    except Exception as exc:
        _handle_error(exc)


@venafi.command("download")
@click.option("--guid", required=True, help="Certificate GUID.")
@click.pass_context
def venafi_download(ctx: click.Context, guid: str) -> None:
    """Download a certificate from Venafi TPP.

    Uses renew_and_download_certificate to retrieve the certificate material.
    """
    try:
        from certmesh import venafi_client as vn

        cfg = ctx.obj["cfg"]
        vault_cl = _get_vault_client(cfg)
        session = vn.authenticate(cfg["venafi"], cfg["vault"], vault_cl)
        bundle = vn.renew_and_download_certificate(
            session,
            cfg["venafi"],
            cfg["vault"],
            vault_cl,
            certificate_guid=guid,
        )
        click.echo(f"Downloaded: CN={bundle.common_name}, serial={bundle.serial_number}")
    except Exception as exc:
        _handle_error(exc)


# =============================================================================
# Vault PKI commands
# =============================================================================


@cli.group("vault-pki")
def vault_pki() -> None:
    """HashiCorp Vault PKI engine certificate lifecycle management."""


@vault_pki.command("issue")
@click.option("--cn", required=True, help="Common Name.")
@click.option("--san", multiple=True, help="Subject Alternative Name(s).")
@click.option("--ip-san", multiple=True, help="IP SAN(s).")
@click.option("--ttl", default=None, help="Certificate TTL (e.g. 720h).")
@click.option("--output-dir", default=None, help="Directory to write PEM files.")
@click.pass_context
def vault_pki_issue(
    ctx: click.Context,
    cn: str,
    san: tuple[str, ...],
    ip_san: tuple[str, ...],
    ttl: str | None,
    output_dir: str | None,
) -> None:
    """Issue a certificate from Vault PKI engine."""
    try:
        from certmesh import vault_client as vc

        cfg = ctx.obj["cfg"]
        client = vc.get_authenticated_client(cfg["vault"])
        pki_cfg = cfg["vault"].get("pki", {})
        result = vc.issue_pki_certificate(
            client,
            pki_cfg,
            cn,
            alt_names=list(san) if san else None,
            ttl=ttl,
            ip_sans=list(ip_san) if ip_san else None,
        )

        if output_dir:
            from pathlib import Path

            out = Path(output_dir)
            out.mkdir(parents=True, exist_ok=True)
            (out / f"{cn}_cert.pem").write_text(result["certificate"])
            if result.get("private_key"):
                key_path = out / f"{cn}_key.pem"
                key_path.write_text(result["private_key"])
                import os

                os.chmod(key_path, 0o600)
            if result.get("ca_chain"):
                chain = result["ca_chain"]
                if isinstance(chain, list):
                    chain = "\n".join(chain)
                (out / f"{cn}_chain.pem").write_text(chain)
            click.echo(f"Files written to {out}/")
        else:
            _json_output(result)
    except Exception as exc:
        _handle_error(exc)


@vault_pki.command("sign")
@click.option("--cn", required=True, help="Common Name.")
@click.option("--csr-file", required=True, type=click.Path(exists=True), help="CSR PEM file.")
@click.option("--san", multiple=True, help="Subject Alternative Name(s).")
@click.option("--ttl", default=None, help="Certificate TTL (e.g. 720h).")
@click.option("--output-dir", default=None, help="Directory to write PEM files.")
@click.pass_context
def vault_pki_sign(
    ctx: click.Context,
    cn: str,
    csr_file: str,
    san: tuple[str, ...],
    ttl: str | None,
    output_dir: str | None,
) -> None:
    """Sign a CSR using Vault PKI engine."""
    try:
        from certmesh import vault_client as vc

        with open(csr_file) as f:
            csr_pem = f.read()

        cfg = ctx.obj["cfg"]
        client = vc.get_authenticated_client(cfg["vault"])
        pki_cfg = cfg["vault"].get("pki", {})
        result = vc.sign_pki_certificate(
            client,
            pki_cfg,
            cn,
            csr_pem,
            alt_names=list(san) if san else None,
            ttl=ttl,
        )

        if output_dir:
            from pathlib import Path

            out = Path(output_dir)
            out.mkdir(parents=True, exist_ok=True)
            (out / f"{cn}_cert.pem").write_text(result["certificate"])
            if result.get("ca_chain"):
                chain = result["ca_chain"]
                if isinstance(chain, list):
                    chain = "\n".join(chain)
                (out / f"{cn}_chain.pem").write_text(chain)
            click.echo(f"Signed certificate written to {out}/")
        else:
            _json_output(result)
    except Exception as exc:
        _handle_error(exc)


@vault_pki.command("list")
@click.pass_context
def vault_pki_list(ctx: click.Context) -> None:
    """List all certificates in Vault PKI engine."""
    try:
        from certmesh import vault_client as vc

        cfg = ctx.obj["cfg"]
        client = vc.get_authenticated_client(cfg["vault"])
        pki_cfg = cfg["vault"].get("pki", {})
        serials = vc.list_pki_certificates(client, pki_cfg)
        _json_output({"serial_numbers": serials, "count": len(serials)})
    except Exception as exc:
        _handle_error(exc)


@vault_pki.command("read")
@click.option("--serial", required=True, help="Certificate serial number.")
@click.pass_context
def vault_pki_read(ctx: click.Context, serial: str) -> None:
    """Read a certificate from Vault PKI engine by serial number."""
    try:
        from certmesh import vault_client as vc

        cfg = ctx.obj["cfg"]
        client = vc.get_authenticated_client(cfg["vault"])
        pki_cfg = cfg["vault"].get("pki", {})
        data = vc.read_pki_certificate(client, pki_cfg, serial)
        _json_output(data)
    except Exception as exc:
        _handle_error(exc)


@vault_pki.command("revoke")
@click.option("--serial", required=True, help="Certificate serial number to revoke.")
@click.pass_context
def vault_pki_revoke(ctx: click.Context, serial: str) -> None:
    """Revoke a certificate in Vault PKI engine."""
    try:
        from certmesh import vault_client as vc

        cfg = ctx.obj["cfg"]
        client = vc.get_authenticated_client(cfg["vault"])
        pki_cfg = cfg["vault"].get("pki", {})
        vc.revoke_pki_certificate(client, pki_cfg, serial)
        click.echo(f"Certificate {serial} revoked.")
    except Exception as exc:
        _handle_error(exc)


# =============================================================================
# AWS ACM commands
# =============================================================================


@cli.group()
def acm() -> None:
    """AWS ACM public certificate lifecycle management."""


@acm.command("request")
@click.option("--cn", required=True, help="Common Name (domain).")
@click.option("--san", multiple=True, help="Subject Alternative Name(s).")
@click.option(
    "--validation",
    default="DNS",
    type=click.Choice(["DNS", "EMAIL"], case_sensitive=False),
    help="Validation method.",
)
@click.option("--key-algorithm", default=None, help="Key algorithm (e.g. RSA_2048).")
@click.option("--region", default=None, help="AWS region override.")
@click.pass_context
def acm_request(
    ctx: click.Context,
    cn: str,
    san: tuple[str, ...],
    validation: str,
    key_algorithm: str | None,
    region: str | None,
) -> None:
    """Request a public TLS certificate from AWS ACM."""
    try:
        from certmesh import acm_client

        cfg = ctx.obj["cfg"]
        acm_cfg = cfg["acm"]
        if region:
            acm_cfg = {**acm_cfg, "region": region}
        arn = acm_client.request_certificate(
            acm_cfg,
            cn,
            subject_alternative_names=list(san) if san else None,
            validation_method=validation.upper(),
            key_algorithm=key_algorithm,
        )
        click.echo(f"Certificate requested: {arn}")
        click.echo("Run 'certmesh acm validation-records --arn ...' to see DNS records.")
    except Exception as exc:
        _handle_error(exc)


@acm.command("list")
@click.option("--status", multiple=True, help="Filter by status(es).")
@click.option("--region", default=None, help="AWS region override.")
@click.pass_context
def acm_list(ctx: click.Context, status: tuple[str, ...], region: str | None) -> None:
    """List certificates in AWS ACM."""
    try:
        from certmesh import acm_client

        cfg = ctx.obj["cfg"]
        acm_cfg = cfg["acm"]
        if region:
            acm_cfg = {**acm_cfg, "region": region}
        results = acm_client.list_certificates(
            acm_cfg,
            statuses=list(status) if status else None,
        )
        _json_output([vars(r) for r in results])
    except Exception as exc:
        _handle_error(exc)


@acm.command("describe")
@click.option("--arn", required=True, help="Certificate ARN.")
@click.option("--region", default=None, help="AWS region override.")
@click.pass_context
def acm_describe(ctx: click.Context, arn: str, region: str | None) -> None:
    """Describe an ACM certificate."""
    try:
        from certmesh import acm_client

        cfg = ctx.obj["cfg"]
        acm_cfg = cfg["acm"]
        if region:
            acm_cfg = {**acm_cfg, "region": region}
        detail = acm_client.describe_certificate(acm_cfg, arn)
        _json_output(vars(detail))
    except Exception as exc:
        _handle_error(exc)


@acm.command("export")
@click.option("--arn", required=True, help="Certificate ARN.")
@click.option("--passphrase", required=True, help="Passphrase for private key export.")
@click.option("--output-dir", default=None, help="Directory to write PEM files.")
@click.option("--region", default=None, help="AWS region override.")
@click.pass_context
def acm_export(
    ctx: click.Context,
    arn: str,
    passphrase: str,
    output_dir: str | None,
    region: str | None,
) -> None:
    """Export certificate and private key from ACM."""
    try:
        from certmesh import acm_client

        cfg = ctx.obj["cfg"]
        acm_cfg = cfg["acm"]
        if region:
            acm_cfg = {**acm_cfg, "region": region}
        bundle = acm_client.export_certificate(acm_cfg, arn, passphrase.encode("utf-8"))

        if output_dir:
            from pathlib import Path

            out = Path(output_dir)
            out.mkdir(parents=True, exist_ok=True)
            sid = acm_client.arn_short_id(arn)
            (out / f"{sid}_cert.pem").write_text(bundle.certificate_pem)
            key_path = out / f"{sid}_key.pem"
            key_path.write_text(bundle.private_key_pem)
            import os

            os.chmod(key_path, 0o600)
            if bundle.chain_pem:
                (out / f"{sid}_chain.pem").write_text(bundle.chain_pem)
            click.echo(f"Exported to {out}/")
        else:
            click.echo(f"Exported: CN={bundle.common_name}, serial={bundle.serial_number}")
    except Exception as exc:
        _handle_error(exc)


@acm.command("renew")
@click.option("--arn", required=True, help="Certificate ARN.")
@click.option("--region", default=None, help="AWS region override.")
@click.pass_context
def acm_renew(ctx: click.Context, arn: str, region: str | None) -> None:
    """Trigger renewal of an eligible ACM managed certificate."""
    try:
        from certmesh import acm_client

        cfg = ctx.obj["cfg"]
        acm_cfg = cfg["acm"]
        if region:
            acm_cfg = {**acm_cfg, "region": region}
        acm_client.renew_certificate(acm_cfg, arn)
        click.echo(f"Renewal triggered for {arn}")
    except Exception as exc:
        _handle_error(exc)


@acm.command("delete")
@click.option("--arn", required=True, help="Certificate ARN.")
@click.option("--region", default=None, help="AWS region override.")
@click.pass_context
def acm_delete(ctx: click.Context, arn: str, region: str | None) -> None:
    """Delete a certificate from AWS ACM."""
    try:
        from certmesh import acm_client

        cfg = ctx.obj["cfg"]
        acm_cfg = cfg["acm"]
        if region:
            acm_cfg = {**acm_cfg, "region": region}
        acm_client.delete_certificate(acm_cfg, arn)
        click.echo(f"Deleted certificate {arn}")
    except Exception as exc:
        _handle_error(exc)


@acm.command("validation-records")
@click.option("--arn", required=True, help="Certificate ARN.")
@click.option("--region", default=None, help="AWS region override.")
@click.pass_context
def acm_validation_records(ctx: click.Context, arn: str, region: str | None) -> None:
    """Get DNS/email validation records for a pending ACM certificate."""
    try:
        from certmesh import acm_client

        cfg = ctx.obj["cfg"]
        acm_cfg = cfg["acm"]
        if region:
            acm_cfg = {**acm_cfg, "region": region}
        records = acm_client.get_validation_records(acm_cfg, arn)
        _json_output([vars(r) for r in records])
    except Exception as exc:
        _handle_error(exc)


@acm.command("wait")
@click.option("--arn", required=True, help="Certificate ARN.")
@click.option("--region", default=None, help="AWS region override.")
@click.pass_context
def acm_wait(ctx: click.Context, arn: str, region: str | None) -> None:
    """Wait for an ACM certificate to be issued."""
    try:
        from certmesh import acm_client

        cfg = ctx.obj["cfg"]
        acm_cfg = cfg["acm"]
        if region:
            acm_cfg = {**acm_cfg, "region": region}
        acm_client.wait_for_issuance(acm_cfg, arn)
        click.echo(f"Certificate {arn} is now issued.")
    except Exception as exc:
        _handle_error(exc)


# =============================================================================
# AWS ACM Private CA commands
# =============================================================================


@cli.group("acm-pca")
def acm_pca() -> None:
    """AWS ACM Private CA certificate lifecycle management."""


@acm_pca.command("issue")
@click.option("--ca-arn", required=True, help="Private CA ARN.")
@click.option("--csr-file", required=True, type=click.Path(exists=True), help="CSR PEM file.")
@click.option("--validity-days", default=None, type=int, help="Certificate validity in days.")
@click.option("--signing-algorithm", default=None, help="Signing algorithm.")
@click.option("--region", default=None, help="AWS region override.")
@click.pass_context
def acm_pca_issue(
    ctx: click.Context,
    ca_arn: str,
    csr_file: str,
    validity_days: int | None,
    signing_algorithm: str | None,
    region: str | None,
) -> None:
    """Issue a certificate from AWS Private CA."""
    try:
        from certmesh import acm_client

        cfg = ctx.obj["cfg"]
        acm_cfg = cfg["acm"]
        if region:
            acm_cfg = {**acm_cfg, "region": region}
        with open(csr_file) as f:
            csr_pem = f.read()
        cert_arn = acm_client.issue_private_certificate(
            acm_cfg,
            csr_pem,
            ca_arn=ca_arn,
            validity_days=validity_days,
            signing_algorithm=signing_algorithm,
        )
        click.echo(f"Issued private CA certificate: {cert_arn}")
    except Exception as exc:
        _handle_error(exc)


@acm_pca.command("get")
@click.option("--ca-arn", required=True, help="Private CA ARN.")
@click.option("--cert-arn", required=True, help="Certificate ARN.")
@click.option("--region", default=None, help="AWS region override.")
@click.pass_context
def acm_pca_get(ctx: click.Context, ca_arn: str, cert_arn: str, region: str | None) -> None:
    """Retrieve a certificate issued by AWS Private CA."""
    try:
        from certmesh import acm_client

        cfg = ctx.obj["cfg"]
        acm_cfg = cfg["acm"]
        if region:
            acm_cfg = {**acm_cfg, "region": region}
        data = acm_client.get_private_certificate(acm_cfg, cert_arn, ca_arn=ca_arn)
        _json_output(data)
    except Exception as exc:
        _handle_error(exc)


@acm_pca.command("revoke")
@click.option("--ca-arn", required=True, help="Private CA ARN.")
@click.option("--cert-arn", required=True, help="Certificate ARN.")
@click.option("--cert-serial", required=True, help="Certificate serial number.")
@click.option(
    "--reason",
    default="UNSPECIFIED",
    type=click.Choice(
        [
            "UNSPECIFIED",
            "KEY_COMPROMISE",
            "CERTIFICATE_AUTHORITY_COMPROMISE",
            "AFFILIATION_CHANGED",
            "SUPERSEDED",
            "CESSATION_OF_OPERATION",
            "PRIVILEGE_WITHDRAWN",
            "A_A_COMPROMISE",
        ]
    ),
    help="Revocation reason.",
)
@click.option("--region", default=None, help="AWS region override.")
@click.pass_context
def acm_pca_revoke(
    ctx: click.Context,
    ca_arn: str,
    cert_arn: str,
    cert_serial: str,
    reason: str,
    region: str | None,
) -> None:
    """Revoke a certificate issued by AWS Private CA."""
    try:
        from certmesh import acm_client

        cfg = ctx.obj["cfg"]
        acm_cfg = cfg["acm"]
        if region:
            acm_cfg = {**acm_cfg, "region": region}
        acm_client.revoke_private_certificate(
            acm_cfg, cert_arn, cert_serial, reason, ca_arn=ca_arn
        )
        click.echo(f"Certificate {cert_serial} revoked.")
    except Exception as exc:
        _handle_error(exc)


@acm_pca.command("list")
@click.option("--ca-arn", required=True, help="Private CA ARN.")
@click.option("--region", default=None, help="AWS region override.")
@click.pass_context
def acm_pca_list(ctx: click.Context, ca_arn: str, region: str | None) -> None:
    """List certificates issued by AWS Private CA."""
    try:
        from certmesh import acm_client

        cfg = ctx.obj["cfg"]
        acm_cfg = cfg["acm"]
        if region:
            acm_cfg = {**acm_cfg, "region": region}
        results = acm_client.list_private_certificates(acm_cfg, ca_arn=ca_arn)
        _json_output(results)
    except Exception as exc:
        _handle_error(exc)


# =============================================================================
# Config commands
# =============================================================================


@cli.group()
def config() -> None:
    """Configuration management."""


@config.command("show")
@click.pass_context
def config_show(ctx: click.Context) -> None:
    """Display the effective (merged) configuration."""
    import copy

    cfg = copy.deepcopy(ctx.obj["cfg"])
    # Redact secret-related keys
    for section in ("vault",):
        for sub in ("approle", "ldap"):
            if sub in cfg.get(section, {}):
                for key in list(cfg[section][sub].keys()):
                    if "env" in key:
                        cfg[section][sub][key] = f"<from env: {cfg[section][sub][key]}>"
    _json_output(cfg)


@config.command("validate")
@click.pass_context
def config_validate(ctx: click.Context) -> None:
    """Validate the configuration (Vault URL, output destinations, etc.)."""
    try:
        validate_config(ctx.obj["cfg"])
        click.echo("Configuration is valid.")
    except ConfigurationError as exc:
        click.echo(f"Validation failed: {exc}", err=True)
        sys.exit(1)
