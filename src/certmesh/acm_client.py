"""
certmesh.acm_client
====================

AWS Certificate Manager (ACM) client supporting the full lifecycle for
both **public ACM certificates** and **private CA certificates** (ACM-PCA).

Public ACM operations
---------------------
* ``request_certificate``   -- Request a new public TLS certificate.
* ``describe_certificate``  -- Get full details of a certificate by ARN.
* ``list_certificates``     -- List certificates with optional status filter.
* ``export_certificate``    -- Export cert + private key (encrypted).
* ``delete_certificate``    -- Delete a certificate from ACM.
* ``renew_certificate``     -- Trigger renewal of an eligible managed cert.
* ``get_validation_records`` -- Extract DNS/email validation records.
* ``wait_for_issuance``     -- Poll until certificate is ISSUED or timeout.

Private CA operations (ACM-PCA)
-------------------------------
* ``issue_private_certificate``  -- Issue a certificate from an AWS Private CA.
* ``get_private_certificate``    -- Retrieve a private CA-issued certificate.
* ``revoke_private_certificate`` -- Revoke a private CA certificate.
* ``list_private_certificates``  -- List certificates issued by a private CA.

References
----------
* ACM API:     https://docs.aws.amazon.com/acm/latest/APIReference/
* ACM-PCA API: https://docs.aws.amazon.com/privateca/latest/APIReference/
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import boto3
import botocore.exceptions

from certmesh import certificate_utils as cu
from certmesh.certificate_utils import CertificateBundle
from certmesh.exceptions import (
    ACMError,
    ACMExportError,
    ACMPrivateCAError,
    ACMRequestError,
    ACMValidationError,
)

logger = logging.getLogger(__name__)

JsonDict = dict[str, Any]


# =============================================================================
# Constants
# =============================================================================

_VALID_KEY_ALGORITHMS: frozenset[str] = frozenset(
    {
        "RSA_1024",
        "RSA_2048",
        "RSA_3072",
        "RSA_4096",
        "EC_prime256v1",
        "EC_secp384r1",
        "EC_secp521r1",
    }
)

_VALID_VALIDATION_METHODS: frozenset[str] = frozenset({"DNS", "EMAIL"})

_TERMINAL_STATUSES: frozenset[str] = frozenset(
    {
        "ISSUED",
        "FAILED",
        "REVOKED",
        "EXPIRED",
        "VALIDATION_TIMED_OUT",
    }
)


# =============================================================================
# Data models
# =============================================================================


@dataclass(slots=True, frozen=True)
class ACMCertificateSummary:
    """Lightweight summary returned by ``list_certificates``."""

    certificate_arn: str
    domain_name: str
    status: str
    key_algorithm: str
    type: str
    in_use: bool
    not_after: datetime | None = None
    not_before: datetime | None = None


@dataclass(slots=True, frozen=True)
class ACMCertificateDetail:
    """Full detail returned by ``describe_certificate``."""

    certificate_arn: str
    domain_name: str
    subject_alternative_names: list[str] = field(default_factory=list)
    status: str = ""
    type: str = ""
    key_algorithm: str = ""
    serial: str = ""
    issuer: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None
    created_at: datetime | None = None
    renewal_eligibility: str = ""
    in_use_by: list[str] = field(default_factory=list)
    failure_reason: str = ""
    raw: JsonDict = field(default_factory=dict, repr=False)


@dataclass(slots=True, frozen=True)
class ACMValidationRecord:
    """A single DNS or email validation record for a pending certificate."""

    domain_name: str
    validation_method: str
    validation_status: str
    # DNS validation fields
    resource_record_name: str = ""
    resource_record_type: str = ""
    resource_record_value: str = ""
    # Email validation fields
    validation_emails: list[str] = field(default_factory=list)


# =============================================================================
# Helpers
# =============================================================================


def arn_short_id(arn: str) -> str:
    """Extract the UUID portion from an ACM certificate ARN.

    Example::

        >>> arn_short_id("arn:aws:acm:us-east-1:123456789012:certificate/abcd-1234")
        'abcd-1234'
    """
    parts = arn.rsplit("/", 1)
    return parts[-1] if len(parts) == 2 else arn


def _boto_error_code(exc: botocore.exceptions.ClientError) -> str:
    """Return the AWS error code from a botocore ClientError."""
    return exc.response.get("Error", {}).get("Code", "Unknown")


def _boto_error_message(exc: botocore.exceptions.ClientError) -> str:
    """Return the AWS error message from a botocore ClientError."""
    return exc.response.get("Error", {}).get("Message", str(exc))


# =============================================================================
# Client construction
# =============================================================================


def _build_acm_client(acm_cfg: JsonDict) -> Any:
    """Create a boto3 ACM client from configuration."""
    kwargs: dict[str, Any] = {}
    region = acm_cfg.get("region")
    if region:
        kwargs["region_name"] = region
    return boto3.client("acm", **kwargs)


def _build_acm_pca_client(acm_cfg: JsonDict) -> Any:
    """Create a boto3 ACM-PCA client from configuration."""
    kwargs: dict[str, Any] = {}
    region = acm_cfg.get("region")
    if region:
        kwargs["region_name"] = region
    return boto3.client("acm-pca", **kwargs)


# =============================================================================
# Public ACM: request_certificate
# =============================================================================


def request_certificate(
    acm_cfg: JsonDict,
    domain_name: str,
    *,
    subject_alternative_names: list[str] | None = None,
    validation_method: str | None = None,
    key_algorithm: str | None = None,
    idempotency_token: str | None = None,
    tags: list[JsonDict] | None = None,
) -> str:
    """Request a new public TLS certificate via ACM.

    Args:
        acm_cfg: The ``acm`` section of the application config.
        domain_name: Primary fully-qualified domain name for the certificate.
        subject_alternative_names: Optional additional SANs.
        validation_method: ``"DNS"`` or ``"EMAIL"``.  Defaults to config value.
        key_algorithm: Key algorithm (e.g. ``"RSA_2048"``, ``"EC_prime256v1"``).
        idempotency_token: Optional idempotency token for the request.
        tags: Optional list of ``{"Key": ..., "Value": ...}`` tag dicts.

    Returns:
        The ARN of the newly requested certificate.

    Raises:
        ACMRequestError: If the ACM request fails.
    """
    cert_cfg: JsonDict = acm_cfg.get("certificate", {})
    effective_validation = validation_method or cert_cfg.get("validation_method", "DNS")
    effective_algorithm = key_algorithm or cert_cfg.get("key_algorithm", "RSA_2048")

    if effective_validation not in _VALID_VALIDATION_METHODS:
        raise ACMRequestError(
            f"Invalid validation method '{effective_validation}'. "
            f"Supported: {sorted(_VALID_VALIDATION_METHODS)}"
        )
    if effective_algorithm not in _VALID_KEY_ALGORITHMS:
        raise ACMRequestError(
            f"Invalid key algorithm '{effective_algorithm}'. "
            f"Supported: {sorted(_VALID_KEY_ALGORITHMS)}"
        )

    params: JsonDict = {
        "DomainName": domain_name,
        "ValidationMethod": effective_validation,
        "KeyAlgorithm": effective_algorithm,
    }

    if subject_alternative_names:
        params["SubjectAlternativeNames"] = subject_alternative_names

    token = idempotency_token or cert_cfg.get("idempotency_token")
    if token:
        params["IdempotencyToken"] = token

    if tags:
        params["Tags"] = tags

    client = _build_acm_client(acm_cfg)
    try:
        response = client.request_certificate(**params)
    except botocore.exceptions.ClientError as exc:
        raise ACMRequestError(
            f"ACM request_certificate failed for domain '{domain_name}': "
            f"[{_boto_error_code(exc)}] {_boto_error_message(exc)}"
        ) from exc

    cert_arn: str = response["CertificateArn"]
    logger.info(
        "ACM: requested certificate for domain='%s' (arn=%s, algo=%s, validation=%s).",
        domain_name,
        cert_arn,
        effective_algorithm,
        effective_validation,
    )
    return cert_arn


# =============================================================================
# Public ACM: describe_certificate
# =============================================================================


def describe_certificate(
    acm_cfg: JsonDict,
    certificate_arn: str,
) -> ACMCertificateDetail:
    """Get full details of a certificate by ARN.

    Args:
        acm_cfg: The ``acm`` section of the application config.
        certificate_arn: ARN of the certificate to describe.

    Returns:
        An ``ACMCertificateDetail`` dataclass with all certificate metadata.

    Raises:
        ACMError: If the describe call fails.
    """
    client = _build_acm_client(acm_cfg)
    try:
        response = client.describe_certificate(CertificateArn=certificate_arn)
    except botocore.exceptions.ClientError as exc:
        code = _boto_error_code(exc)
        raise ACMError(
            f"ACM describe_certificate failed for '{certificate_arn}': "
            f"[{code}] {_boto_error_message(exc)}"
        ) from exc

    cert: JsonDict = response.get("Certificate", {})
    detail = ACMCertificateDetail(
        certificate_arn=cert.get("CertificateArn", certificate_arn),
        domain_name=cert.get("DomainName", ""),
        subject_alternative_names=cert.get("SubjectAlternativeNames", []),
        status=cert.get("Status", ""),
        type=cert.get("Type", ""),
        key_algorithm=cert.get("KeyAlgorithm", ""),
        serial=cert.get("Serial", ""),
        issuer=cert.get("Issuer", ""),
        not_before=cert.get("NotBefore"),
        not_after=cert.get("NotAfter"),
        created_at=cert.get("CreatedAt"),
        renewal_eligibility=cert.get("RenewalEligibility", ""),
        in_use_by=cert.get("InUseBy", []),
        failure_reason=cert.get("FailureReason", ""),
        raw=cert,
    )

    logger.debug(
        "ACM: described certificate arn='%s' (status=%s, domain=%s).",
        certificate_arn,
        detail.status,
        detail.domain_name,
    )
    return detail


# =============================================================================
# Public ACM: list_certificates
# =============================================================================


def list_certificates(
    acm_cfg: JsonDict,
    *,
    statuses: list[str] | None = None,
    max_items: int | None = None,
) -> list[ACMCertificateSummary]:
    """List certificates with optional status filter.

    Automatically handles pagination to return all matching certificates
    up to *max_items* (or all if *max_items* is ``None``).

    Args:
        acm_cfg: The ``acm`` section of the application config.
        statuses: Optional list of statuses to filter by (e.g.
            ``["ISSUED", "PENDING_VALIDATION"]``).
        max_items: Optional cap on the number of results returned.

    Returns:
        List of ``ACMCertificateSummary`` objects.

    Raises:
        ACMError: If the list call fails.
    """
    client = _build_acm_client(acm_cfg)
    params: JsonDict = {}
    if statuses:
        params["CertificateStatuses"] = statuses

    summaries: list[ACMCertificateSummary] = []
    try:
        paginator = client.get_paginator("list_certificates")
        page_iterator = paginator.paginate(**params)
        for page in page_iterator:
            for item in page.get("CertificateSummaryList", []):
                summary = ACMCertificateSummary(
                    certificate_arn=item.get("CertificateArn", ""),
                    domain_name=item.get("DomainName", ""),
                    status=item.get("Status", ""),
                    key_algorithm=item.get("KeyAlgorithm", ""),
                    type=item.get("Type", ""),
                    in_use=bool(item.get("InUse", False)),
                    not_after=item.get("NotAfter"),
                    not_before=item.get("NotBefore"),
                )
                summaries.append(summary)
                if max_items is not None and len(summaries) >= max_items:
                    logger.debug(
                        "ACM: reached max_items=%d while listing certificates.", max_items
                    )
                    return summaries
    except botocore.exceptions.ClientError as exc:
        raise ACMError(
            f"ACM list_certificates failed: [{_boto_error_code(exc)}] {_boto_error_message(exc)}"
        ) from exc

    logger.info("ACM: listed %d certificate(s).", len(summaries))
    return summaries


# =============================================================================
# Public ACM: export_certificate
# =============================================================================


def export_certificate(
    acm_cfg: JsonDict,
    certificate_arn: str,
    passphrase: bytes,
) -> CertificateBundle:
    """Export a certificate and its private key from ACM.

    ACM encrypts the private key with the provided *passphrase* before
    returning it.  This function decrypts the key and assembles a
    ``CertificateBundle``.

    Note:
        Only certificates with exportable private keys (e.g. those
        imported into ACM or issued by ACM Private CA) can be exported.

    Args:
        acm_cfg: The ``acm`` section of the application config.
        certificate_arn: ARN of the certificate to export.
        passphrase: Passphrase used to encrypt/decrypt the private key
            (bytes).  Must be between 4 and 128 characters.

    Returns:
        A ``CertificateBundle`` containing certificate, private key, and
        chain PEM material.

    Raises:
        ACMExportError: If the export call fails or the response is
            missing expected material.
    """
    if not passphrase or len(passphrase) < 4:
        raise ACMExportError("Passphrase for ACM export must be at least 4 bytes.")

    client = _build_acm_client(acm_cfg)
    try:
        response = client.export_certificate(
            CertificateArn=certificate_arn,
            Passphrase=passphrase,
        )
    except botocore.exceptions.ClientError as exc:
        code = _boto_error_code(exc)
        raise ACMExportError(
            f"ACM export_certificate failed for '{certificate_arn}': "
            f"[{code}] {_boto_error_message(exc)}"
        ) from exc

    cert_pem_str: str = response.get("Certificate", "")
    key_pem_str: str = response.get("PrivateKey", "")
    chain_pem_str: str = response.get("CertificateChain", "")

    if not cert_pem_str:
        raise ACMExportError(f"ACM export returned empty certificate for '{certificate_arn}'.")
    if not key_pem_str:
        raise ACMExportError(f"ACM export returned empty private key for '{certificate_arn}'.")

    # ACM returns the private key already PEM-encoded (decrypted by the
    # service using the passphrase we provided).  We can use it directly.
    cert_pem = cert_pem_str.encode("utf-8")
    key_pem = key_pem_str.encode("utf-8")
    chain_pem = chain_pem_str.encode("utf-8") if chain_pem_str else None

    short_id = arn_short_id(certificate_arn)
    bundle = cu.assemble_bundle(
        cert_pem=cert_pem,
        private_key_pem=key_pem,
        chain_pem=chain_pem,
        source_id=short_id,
    )

    logger.info(
        "ACM: exported certificate arn='%s' (CN=%s, serial=%s).",
        certificate_arn,
        bundle.common_name,
        bundle.serial_number,
    )
    return bundle


# =============================================================================
# Public ACM: delete_certificate
# =============================================================================


def delete_certificate(
    acm_cfg: JsonDict,
    certificate_arn: str,
) -> None:
    """Delete a certificate from ACM.

    Args:
        acm_cfg: The ``acm`` section of the application config.
        certificate_arn: ARN of the certificate to delete.

    Raises:
        ACMError: If the delete call fails (e.g. certificate is in use).
    """
    client = _build_acm_client(acm_cfg)
    try:
        client.delete_certificate(CertificateArn=certificate_arn)
    except botocore.exceptions.ClientError as exc:
        code = _boto_error_code(exc)
        raise ACMError(
            f"ACM delete_certificate failed for '{certificate_arn}': "
            f"[{code}] {_boto_error_message(exc)}"
        ) from exc

    logger.info("ACM: deleted certificate arn='%s'.", certificate_arn)


# =============================================================================
# Public ACM: renew_certificate
# =============================================================================


def renew_certificate(
    acm_cfg: JsonDict,
    certificate_arn: str,
) -> None:
    """Trigger renewal of an eligible managed certificate.

    Only certificates that are eligible for managed renewal (i.e. those
    originally requested through ACM) can be renewed via this API.

    Args:
        acm_cfg: The ``acm`` section of the application config.
        certificate_arn: ARN of the certificate to renew.

    Raises:
        ACMError: If the renewal call fails.
    """
    client = _build_acm_client(acm_cfg)
    try:
        client.renew_certificate(CertificateArn=certificate_arn)
    except botocore.exceptions.ClientError as exc:
        code = _boto_error_code(exc)
        raise ACMError(
            f"ACM renew_certificate failed for '{certificate_arn}': "
            f"[{code}] {_boto_error_message(exc)}"
        ) from exc

    logger.info("ACM: triggered renewal for certificate arn='%s'.", certificate_arn)


# =============================================================================
# Public ACM: get_validation_records
# =============================================================================


def get_validation_records(
    acm_cfg: JsonDict,
    certificate_arn: str,
) -> list[ACMValidationRecord]:
    """Extract DNS/email validation records from a pending certificate.

    Useful for programmatically creating Route 53 records or notifying
    administrators of the email validation addresses.

    Args:
        acm_cfg: The ``acm`` section of the application config.
        certificate_arn: ARN of the certificate (typically in
            ``PENDING_VALIDATION`` status).

    Returns:
        List of ``ACMValidationRecord`` objects, one per domain.

    Raises:
        ACMValidationError: If the describe call fails or no validation
            options are present.
    """
    try:
        detail = describe_certificate(acm_cfg, certificate_arn)
    except ACMError as exc:
        raise ACMValidationError(
            f"Failed to retrieve validation records for '{certificate_arn}': {exc}"
        ) from exc

    domain_validations: list[JsonDict] = detail.raw.get("DomainValidationOptions", [])
    if not domain_validations:
        raise ACMValidationError(
            f"No DomainValidationOptions found for certificate '{certificate_arn}'. "
            f"Current status: {detail.status}."
        )

    records: list[ACMValidationRecord] = []
    for dv in domain_validations:
        rr = dv.get("ResourceRecord", {})
        record = ACMValidationRecord(
            domain_name=dv.get("DomainName", ""),
            validation_method=dv.get("ValidationMethod", ""),
            validation_status=dv.get("ValidationStatus", ""),
            resource_record_name=rr.get("Name", ""),
            resource_record_type=rr.get("Type", ""),
            resource_record_value=rr.get("Value", ""),
            validation_emails=dv.get("ValidationEmails", []),
        )
        records.append(record)

    logger.info(
        "ACM: retrieved %d validation record(s) for arn='%s'.",
        len(records),
        certificate_arn,
    )
    return records


# =============================================================================
# Public ACM: wait_for_issuance
# =============================================================================


def wait_for_issuance(
    acm_cfg: JsonDict,
    certificate_arn: str,
    *,
    interval_seconds: int | None = None,
    max_wait_seconds: int | None = None,
) -> ACMCertificateDetail:
    """Poll until a certificate is issued or a terminal state is reached.

    Args:
        acm_cfg: The ``acm`` section of the application config.
        certificate_arn: ARN of the certificate to wait on.
        interval_seconds: Override polling interval (seconds).
        max_wait_seconds: Override maximum wait time (seconds).

    Returns:
        The ``ACMCertificateDetail`` once the certificate reaches
        ``ISSUED`` status.

    Raises:
        ACMValidationError: If the certificate reaches a failure state or
            the timeout is exceeded.
    """
    polling_cfg: JsonDict = acm_cfg.get("polling", {})
    interval = (
        interval_seconds
        if interval_seconds is not None
        else int(polling_cfg.get("interval_seconds", 10))
    )
    max_wait = (
        max_wait_seconds
        if max_wait_seconds is not None
        else int(polling_cfg.get("max_wait_seconds", 600))
    )

    short_id = arn_short_id(certificate_arn)
    logger.info(
        "ACM: waiting for certificate '%s' to be issued (interval=%ds, timeout=%ds).",
        short_id,
        interval,
        max_wait,
    )

    elapsed = 0
    last_status = "UNKNOWN"
    while elapsed < max_wait:
        detail = describe_certificate(acm_cfg, certificate_arn)
        last_status = detail.status

        if last_status == "ISSUED":
            logger.info(
                "ACM: certificate '%s' is now ISSUED (waited %ds).",
                short_id,
                elapsed,
            )
            return detail

        if last_status in _TERMINAL_STATUSES and last_status != "ISSUED":
            reason = detail.failure_reason or "no failure reason provided"
            raise ACMValidationError(
                f"Certificate '{certificate_arn}' reached terminal status "
                f"'{last_status}' after {elapsed}s: {reason}."
            )

        logger.debug(
            "ACM: certificate '%s' status='%s', waiting %ds (elapsed=%ds/%ds).",
            short_id,
            last_status,
            interval,
            elapsed,
            max_wait,
        )
        time.sleep(interval)
        elapsed += interval

    raise ACMValidationError(
        f"Timed out after {max_wait}s waiting for certificate "
        f"'{certificate_arn}' to be issued.  Last status: {last_status}."
    )


# =============================================================================
# Private CA: issue_private_certificate
# =============================================================================


def issue_private_certificate(
    acm_cfg: JsonDict,
    csr_pem: str,
    *,
    ca_arn: str | None = None,
    signing_algorithm: str | None = None,
    validity_days: int | None = None,
    template_arn: str | None = None,
    idempotency_token: str | None = None,
) -> str:
    """Issue a certificate from an AWS Private CA.

    Args:
        acm_cfg: The ``acm`` section of the application config.
        csr_pem: PEM-encoded Certificate Signing Request.
        ca_arn: ARN of the Private CA.  Defaults to config value.
        signing_algorithm: Signing algorithm (e.g. ``"SHA256WITHRSA"``).
        validity_days: Validity period in days.
        template_arn: Optional ACM-PCA template ARN for extended key
            usage or policy constraints.
        idempotency_token: Optional idempotency token.

    Returns:
        The ARN of the issued certificate.

    Raises:
        ACMPrivateCAError: If the issue call fails or the CA ARN is not
            configured.
    """
    pca_cfg: JsonDict = acm_cfg.get("private_ca", {})
    effective_ca_arn = ca_arn or pca_cfg.get("ca_arn", "")
    effective_signing = signing_algorithm or pca_cfg.get("signing_algorithm", "SHA256WITHRSA")
    effective_validity = (
        validity_days if validity_days is not None else int(pca_cfg.get("validity_days", 365))
    )
    effective_template = template_arn or pca_cfg.get("template_arn", "")

    if not effective_ca_arn:
        raise ACMPrivateCAError(
            "Private CA ARN is required.  Set acm.private_ca.ca_arn in the "
            "config or pass ca_arn explicitly."
        )

    params: JsonDict = {
        "CertificateAuthorityArn": effective_ca_arn,
        "Csr": csr_pem.encode("utf-8") if isinstance(csr_pem, str) else csr_pem,
        "SigningAlgorithm": effective_signing,
        "Validity": {
            "Value": effective_validity,
            "Type": "DAYS",
        },
    }

    if effective_template:
        params["TemplateArn"] = effective_template

    if idempotency_token:
        params["IdempotencyToken"] = idempotency_token

    pca_client = _build_acm_pca_client(acm_cfg)
    try:
        response = pca_client.issue_certificate(**params)
    except botocore.exceptions.ClientError as exc:
        code = _boto_error_code(exc)
        raise ACMPrivateCAError(
            f"ACM-PCA issue_certificate failed (ca='{effective_ca_arn}'): "
            f"[{code}] {_boto_error_message(exc)}"
        ) from exc

    cert_arn: str = response["CertificateArn"]
    logger.info(
        "ACM-PCA: issued certificate arn='%s' (ca='%s', algo=%s, validity=%dd).",
        cert_arn,
        effective_ca_arn,
        effective_signing,
        effective_validity,
    )
    return cert_arn


# =============================================================================
# Private CA: get_private_certificate
# =============================================================================


def get_private_certificate(
    acm_cfg: JsonDict,
    certificate_arn: str,
    *,
    ca_arn: str | None = None,
) -> tuple[str, str]:
    """Retrieve a private CA-issued certificate and its chain.

    Args:
        acm_cfg: The ``acm`` section of the application config.
        certificate_arn: ARN of the certificate to retrieve.
        ca_arn: ARN of the issuing Private CA.  Defaults to config value.

    Returns:
        A tuple of ``(certificate_pem, certificate_chain_pem)``.

    Raises:
        ACMPrivateCAError: If the get call fails or certificate is not
            yet available (``RequestInProgressException``).
    """
    pca_cfg: JsonDict = acm_cfg.get("private_ca", {})
    effective_ca_arn = ca_arn or pca_cfg.get("ca_arn", "")

    if not effective_ca_arn:
        raise ACMPrivateCAError(
            "Private CA ARN is required.  Set acm.private_ca.ca_arn in the "
            "config or pass ca_arn explicitly."
        )

    pca_client = _build_acm_pca_client(acm_cfg)
    try:
        response = pca_client.get_certificate(
            CertificateAuthorityArn=effective_ca_arn,
            CertificateArn=certificate_arn,
        )
    except botocore.exceptions.ClientError as exc:
        code = _boto_error_code(exc)
        if code == "RequestInProgressException":
            raise ACMPrivateCAError(
                f"Certificate '{certificate_arn}' issuance is still in progress.  "
                "Retry after a short delay."
            ) from exc
        raise ACMPrivateCAError(
            f"ACM-PCA get_certificate failed for '{certificate_arn}': "
            f"[{code}] {_boto_error_message(exc)}"
        ) from exc

    cert_pem: str = response.get("Certificate", "")
    chain_pem: str = response.get("CertificateChain", "")

    if not cert_pem:
        raise ACMPrivateCAError(
            f"ACM-PCA get_certificate returned empty certificate for '{certificate_arn}'."
        )

    logger.info(
        "ACM-PCA: retrieved certificate arn='%s' (ca='%s').",
        certificate_arn,
        effective_ca_arn,
    )
    return cert_pem, chain_pem


# =============================================================================
# Private CA: revoke_private_certificate
# =============================================================================


def revoke_private_certificate(
    acm_cfg: JsonDict,
    certificate_arn: str,
    certificate_serial: str,
    revocation_reason: str = "UNSPECIFIED",
    *,
    ca_arn: str | None = None,
) -> None:
    """Revoke a private CA certificate.

    Args:
        acm_cfg: The ``acm`` section of the application config.
        certificate_arn: ARN of the certificate to revoke.
        certificate_serial: Serial number of the certificate (hex string).
        revocation_reason: One of ``UNSPECIFIED``, ``KEY_COMPROMISE``,
            ``CERTIFICATE_AUTHORITY_COMPROMISE``, ``AFFILIATION_CHANGED``,
            ``SUPERSEDED``, ``CESSATION_OF_OPERATION``,
            ``PRIVILEGE_WITHDRAWN``, ``A_A_COMPROMISE``.
        ca_arn: ARN of the issuing Private CA.  Defaults to config value.

    Raises:
        ACMPrivateCAError: If the revoke call fails.
    """
    pca_cfg: JsonDict = acm_cfg.get("private_ca", {})
    effective_ca_arn = ca_arn or pca_cfg.get("ca_arn", "")

    if not effective_ca_arn:
        raise ACMPrivateCAError(
            "Private CA ARN is required.  Set acm.private_ca.ca_arn in the "
            "config or pass ca_arn explicitly."
        )

    pca_client = _build_acm_pca_client(acm_cfg)
    try:
        pca_client.revoke_certificate(
            CertificateAuthorityArn=effective_ca_arn,
            CertificateSerial=certificate_serial,
            RevocationReason=revocation_reason,
        )
    except botocore.exceptions.ClientError as exc:
        code = _boto_error_code(exc)
        raise ACMPrivateCAError(
            f"ACM-PCA revoke_certificate failed for '{certificate_arn}' "
            f"(serial='{certificate_serial}'): [{code}] {_boto_error_message(exc)}"
        ) from exc

    logger.info(
        "ACM-PCA: revoked certificate arn='%s' (serial=%s, reason=%s).",
        certificate_arn,
        certificate_serial,
        revocation_reason,
    )


# =============================================================================
# Private CA: list_private_certificates
# =============================================================================


def list_private_certificates(
    acm_cfg: JsonDict,
    *,
    ca_arn: str | None = None,
    max_items: int | None = None,
) -> list[JsonDict]:
    """List certificates issued by a private CA.

    Uses the ACM ``list_certificates`` API filtered by the Private CA ARN
    to return only certificates issued by the specified authority.

    Args:
        acm_cfg: The ``acm`` section of the application config.
        ca_arn: ARN of the Private CA.  Defaults to config value.
        max_items: Optional cap on the number of results returned.

    Returns:
        List of certificate summary dicts as returned by the ACM API.

    Raises:
        ACMPrivateCAError: If the list call fails or the CA ARN is not
            configured.
    """
    pca_cfg: JsonDict = acm_cfg.get("private_ca", {})
    effective_ca_arn = ca_arn or pca_cfg.get("ca_arn", "")

    if not effective_ca_arn:
        raise ACMPrivateCAError(
            "Private CA ARN is required.  Set acm.private_ca.ca_arn in the "
            "config or pass ca_arn explicitly."
        )

    client = _build_acm_client(acm_cfg)
    params: JsonDict = {
        "Includes": {
            "keyTypes": list(_VALID_KEY_ALGORITHMS),
        },
    }

    results: list[JsonDict] = []
    try:
        paginator = client.get_paginator("list_certificates")
        page_iterator = paginator.paginate(**params)
        for page in page_iterator:
            for item in page.get("CertificateSummaryList", []):
                # Filter to certificates issued by the target private CA.
                # The CertificateArn contains the CA identifier, but the
                # most reliable method is checking via describe_certificate.
                # However, for efficiency we first check the Type field.
                if item.get("Type") != "PRIVATE":
                    continue
                results.append(item)
                if max_items is not None and len(results) >= max_items:
                    return results
    except botocore.exceptions.ClientError as exc:
        code = _boto_error_code(exc)
        raise ACMPrivateCAError(
            f"ACM list_certificates (private CA filter) failed: "
            f"[{code}] {_boto_error_message(exc)}"
        ) from exc

    logger.info(
        "ACM-PCA: listed %d private certificate(s) (ca='%s').",
        len(results),
        effective_ca_arn,
    )
    return results


# =============================================================================
# Convenience: export + persist
# =============================================================================


def export_and_persist(
    acm_cfg: JsonDict,
    certificate_arn: str,
    passphrase: bytes,
    *,
    vault_client: Any = None,
) -> dict[str, str]:
    """Export a certificate from ACM and persist the bundle.

    Combines ``export_certificate`` and ``certificate_utils.persist_bundle``
    to provide a single-call workflow.

    Args:
        acm_cfg: The ``acm`` section of the application config.
        certificate_arn: ARN of the certificate to export.
        passphrase: Passphrase for the ACM export (bytes).
        vault_client: Optional authenticated hvac.Client for Vault output.

    Returns:
        Dict mapping output labels to filesystem paths or Vault paths.

    Raises:
        ACMExportError: If export fails.
        CertificateExportError: If persisting fails.
    """
    bundle = export_certificate(acm_cfg, certificate_arn, passphrase)
    output_cfg: JsonDict = acm_cfg.get("output", {})

    written = cu.persist_bundle(bundle, output_cfg, vault_client=vault_client)
    logger.info(
        "ACM: exported and persisted certificate arn='%s' -> %s.",
        certificate_arn,
        written,
    )
    return written
