"""
certmesh.digicert_client
==========================

DigiCert CertCentral Services API v2 client supporting the full
certificate lifecycle: list, search, describe, order, download,
revoke, and duplicate.

API reference: https://dev.digicert.com/en/certcentral-apis.html
"""

from __future__ import annotations

import io
import logging
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import hvac
import requests
from tenacity import (
    RetryError,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from certmesh import certificate_utils as cu
from certmesh import credentials as creds
from certmesh.certificate_utils import CertificateBundle, SubjectInfo
from certmesh.circuit_breaker import create_circuit_breaker
from certmesh.exceptions import (
    DigiCertAPIError,
    DigiCertAuthenticationError,
    DigiCertCertificateNotReadyError,
    DigiCertDownloadError,
    DigiCertError,
    DigiCertOrderNotFoundError,
    DigiCertPollingTimeoutError,
    DigiCertRateLimitError,
)

logger = logging.getLogger(__name__)

JsonDict = dict[str, Any]

# DigiCert date format used in most API responses.
_DIGICERT_DATE_FMT = "%Y-%m-%d"

# Valid DigiCert revocation reasons.
_VALID_REVOCATION_REASONS: frozenset[str] = frozenset(
    {
        "unspecified",
        "key_compromise",
        "ca_compromise",
        "affiliation_changed",
        "superseded",
        "cessation_of_operation",
    }
)


# =============================================================================
# Data models
# =============================================================================


@dataclass(slots=True, frozen=True)
class OrderRequest:
    """Parameters for a new DigiCert CertCentral certificate order."""

    common_name: str
    san_dns_names: list[str] = field(default_factory=list)
    organisation: str = ""
    organisational_unit: str = ""
    country: str = "US"
    state: str = ""
    locality: str = ""
    product_name_id: str = "ssl_plus"
    validity_years: int = 1
    signature_hash: str = "sha256"
    organization_id: int | None = None
    key_size: int = 4096
    comments: str = ""


@dataclass(slots=True, frozen=True)
class IssuedCertificateSummary:
    """Condensed representation of a certificate returned by list / search."""

    certificate_id: int
    order_id: int
    common_name: str
    serial_number: str
    status: str
    valid_from: str
    valid_till: str
    product_name: str


@dataclass(slots=True, frozen=True)
class DigiCertCertificateDetail:
    """Full detail for a single certificate from the ``/certificate/{id}`` endpoint."""

    certificate_id: int
    order_id: int
    common_name: str
    serial_number: str
    status: str
    valid_from: str
    valid_till: str
    product_name: str
    sans: list[str]
    organization: str
    signature_hash: str
    key_size: int
    thumbprint: str
    raw: JsonDict


# =============================================================================
# HTTP helpers
# =============================================================================


def _build_session(
    digicert_cfg: JsonDict,
    vault_cfg: JsonDict,
    vault_cl: hvac.Client | None,
) -> requests.Session:
    """Build an authenticated ``requests.Session`` for the DigiCert API."""
    api_key: str = creds.resolve_digicert_api_key(vault_cfg, vault_cl)
    session = requests.Session()
    session.headers.update(
        {
            "X-DC-DEVKEY": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
    )
    session.certmesh_timeout = int(digicert_cfg.get("timeout_seconds", 30))  # type: ignore[attr-defined]
    return session


def _raise_for_digicert_error(resp: requests.Response) -> None:
    """Inspect a DigiCert HTTP response and raise the appropriate exception.

    * 401 / 403 -> ``DigiCertAuthenticationError``
    * 404       -> ``DigiCertOrderNotFoundError``
    * 429       -> ``DigiCertRateLimitError`` (honours *Retry-After* header)
    * 4xx / 5xx -> ``DigiCertAPIError``
    """
    if resp.ok:
        return

    status = resp.status_code
    body = resp.text[:500]

    if status in (401, 403):
        raise DigiCertAuthenticationError(
            f"DigiCert authentication failed (HTTP {status}). Verify your API key."
        )

    if status == 404:
        raise DigiCertOrderNotFoundError(f"DigiCert resource not found (HTTP 404): {body}")

    if status == 429:
        retry_after = resp.headers.get("Retry-After", "")
        logger.warning(
            "DigiCert rate limit hit (HTTP 429). Retry-After: '%s'.",
            retry_after,
        )
        raise DigiCertRateLimitError(f"DigiCert rate limit exceeded (HTTP 429): {body}")

    raise DigiCertAPIError(
        f"DigiCert API error (HTTP {status})",
        status_code=status,
        body=body,
    )


def _request_timeout(session: requests.Session) -> int:
    """Return the timeout value stored on the session during construction."""
    return getattr(session, "certmesh_timeout", 30)


def _base_url(digicert_cfg: JsonDict) -> str:
    """Return the base URL, stripping any trailing slash."""
    return digicert_cfg.get("base_url", "https://www.digicert.com/services/v2").rstrip("/")


# =============================================================================
# Date parsing / client-side filtering helpers
# =============================================================================


def _parse_digicert_date(date_str: str) -> datetime:
    """Parse a DigiCert date string (``YYYY-MM-DD``) into a tz-aware datetime."""
    return datetime.strptime(date_str, _DIGICERT_DATE_FMT).replace(tzinfo=timezone.utc)


def _filter_by_expiry(
    certs: list[IssuedCertificateSummary],
    *,
    expires_before: datetime | None = None,
    expires_after: datetime | None = None,
) -> list[IssuedCertificateSummary]:
    """Client-side filter on ``valid_till``."""
    result: list[IssuedCertificateSummary] = []
    for cert in certs:
        try:
            expiry = _parse_digicert_date(cert.valid_till)
        except ValueError:
            # Unparseable dates pass through so callers still see the cert.
            result.append(cert)
            continue

        if expires_before and expiry >= expires_before:
            continue
        if expires_after and expiry <= expires_after:
            continue
        result.append(cert)
    return result


# =============================================================================
# ZIP / PEM extraction
# =============================================================================


def _extract_pem_from_zip(zip_bytes: bytes) -> tuple[bytes, bytes | None]:
    """Extract leaf certificate PEM and optional chain PEM from a ``pem_all`` ZIP.

    DigiCert's ``/certificate/{id}/download/format/pem_all`` endpoint returns
    a ZIP archive containing the server certificate and intermediate(s).

    Returns:
        ``(cert_pem, chain_pem)`` where *chain_pem* may be ``None`` if the
        archive contains no intermediates.
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile as exc:
        raise DigiCertDownloadError(
            f"Downloaded content is not a valid ZIP archive: {exc}"
        ) from exc

    with zf:
        pem_files: list[str] = [n for n in zf.namelist() if n.lower().endswith(".pem")]
        if not pem_files:
            raise DigiCertDownloadError(
                "ZIP archive from DigiCert does not contain any .pem files."
            )

        cert_pem: bytes | None = None
        chain_parts: list[bytes] = []

        for name in sorted(pem_files):
            content = zf.read(name)
            lower = name.lower()
            # Heuristic: the server cert file usually does not contain "intermediate"
            # or "chain" or "ca" in its name.
            if any(kw in lower for kw in ("intermediate", "chain", "root", "ca-bundle")):
                chain_parts.append(content)
            elif cert_pem is None:
                cert_pem = content
            else:
                # Additional PEMs that aren't obviously chain go to chain.
                chain_parts.append(content)

    if cert_pem is None:
        raise DigiCertDownloadError(
            "Could not identify the server certificate PEM in the ZIP archive. "
            f"Files found: {pem_files}"
        )

    chain_pem = b"\n".join(chain_parts) if chain_parts else None
    return cert_pem, chain_pem


# =============================================================================
# Summary builder
# =============================================================================


def _cert_summary_from_dict(data: JsonDict) -> IssuedCertificateSummary:
    """Build an ``IssuedCertificateSummary`` from a raw DigiCert API dict."""
    return IssuedCertificateSummary(
        certificate_id=int(data.get("id", data.get("certificate_id", 0))),
        order_id=int(data.get("order_id", 0)),
        common_name=data.get("common_name", ""),
        serial_number=data.get("serial_number", ""),
        status=data.get("status", ""),
        valid_from=data.get("valid_from", ""),
        valid_till=data.get("valid_till", ""),
        product_name=data.get("product", {}).get("name", "")
        if isinstance(data.get("product"), dict)
        else str(data.get("product_name", "")),
    )


# =============================================================================
# Retry / circuit-breaker factory
# =============================================================================


def _make_retry_decorator(digicert_cfg: JsonDict) -> Any:
    """Build a tenacity retry decorator from the ``digicert.retry`` config."""
    retry_cfg: JsonDict = digicert_cfg.get("retry", {})
    return retry(
        retry=retry_if_exception_type(
            (
                DigiCertRateLimitError,
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
            )
        ),
        stop=stop_after_attempt(int(retry_cfg.get("max_attempts", 5))),
        wait=wait_exponential(
            multiplier=float(retry_cfg.get("wait_multiplier", 1.5)),
            min=float(retry_cfg.get("wait_min_seconds", 2)),
            max=float(retry_cfg.get("wait_max_seconds", 60)),
        ),
        reraise=True,
    )


def _make_circuit_breaker(digicert_cfg: JsonDict, name: str) -> Any:
    """Build a circuit breaker decorator from the ``digicert.circuit_breaker`` config."""
    cb_cfg: JsonDict = digicert_cfg.get("circuit_breaker", {})
    return create_circuit_breaker(
        failure_threshold=int(cb_cfg.get("failure_threshold", 5)),
        recovery_timeout_seconds=float(cb_cfg.get("recovery_timeout_seconds", 120)),
        name=name,
    )


# =============================================================================
# Public API: list_issued_certificates
# =============================================================================


def list_issued_certificates(
    digicert_cfg: JsonDict,
    vault_cfg: JsonDict,
    vault_cl: hvac.Client | None,
    *,
    page_size: int = 100,
    max_pages: int = 50,
    status: str | None = None,
    expires_before: datetime | None = None,
    expires_after: datetime | None = None,
) -> list[IssuedCertificateSummary]:
    """Retrieve all issued certificates from CertCentral, with optional filtering.

    Server-side filters are applied where the API supports them (``status``);
    expiry-based filters are applied client-side after retrieval.

    Args:
        digicert_cfg: The ``digicert`` section of the application config.
        vault_cfg: The ``vault`` section of the application config.
        vault_cl: An authenticated ``hvac.Client`` (or ``None`` if env-based).
        page_size: Number of certificates per page (max 1000).
        max_pages: Safety limit on the number of pages to fetch.
        status: Optional status filter (e.g. ``"issued"``).
        expires_before: Client-side: only certs expiring before this date.
        expires_after: Client-side: only certs expiring after this date.

    Returns:
        List of ``IssuedCertificateSummary`` objects.
    """
    session = _build_session(digicert_cfg, vault_cfg, vault_cl)
    base = _base_url(digicert_cfg)
    url = f"{base}/order/certificate"

    retry_dec = _make_retry_decorator(digicert_cfg)
    cb_dec = _make_circuit_breaker(digicert_cfg, "digicert-list-certs")

    @cb_dec
    @retry_dec
    def _fetch_page(offset: int) -> JsonDict:
        params: dict[str, Any] = {
            "limit": page_size,
            "offset": offset,
        }
        if status:
            params["filters[status]"] = status
        resp = session.get(url, params=params, timeout=_request_timeout(session))
        _raise_for_digicert_error(resp)
        return resp.json()

    all_certs: list[IssuedCertificateSummary] = []
    offset = 0

    for _ in range(max_pages):
        try:
            payload = _fetch_page(offset)
        except RetryError as exc:
            raise DigiCertAPIError(f"Failed to list certificates after retries: {exc}") from exc

        orders: list[JsonDict] = payload.get("orders", [])
        for order in orders:
            cert_data: JsonDict = order.get("certificate", {})
            if not cert_data:
                continue
            cert_data.setdefault("order_id", order.get("id", 0))
            cert_data.setdefault("product", order.get("product", {}))
            all_certs.append(_cert_summary_from_dict(cert_data))

        # Pagination: check if there are more pages.
        page_info: JsonDict = payload.get("page", {})
        total: int = int(page_info.get("total", 0))
        offset += page_size
        if offset >= total:
            break

    logger.info("DigiCert: listed %d certificate(s).", len(all_certs))

    # Client-side expiry filtering.
    if expires_before or expires_after:
        all_certs = _filter_by_expiry(
            all_certs,
            expires_before=expires_before,
            expires_after=expires_after,
        )
        logger.debug(
            "DigiCert: %d certificate(s) after expiry filtering.",
            len(all_certs),
        )

    return all_certs


# =============================================================================
# Public API: search_certificates
# =============================================================================


def search_certificates(
    digicert_cfg: JsonDict,
    vault_cfg: JsonDict,
    vault_cl: hvac.Client | None,
    *,
    common_name: str | None = None,
    serial_number: str | None = None,
    status: str | None = None,
    product_name_id: str | None = None,
    expires_before: datetime | None = None,
    expires_after: datetime | None = None,
    page_size: int = 100,
    max_pages: int = 50,
) -> list[IssuedCertificateSummary]:
    """Search certificates using server-side and client-side filters.

    Server-side filters forwarded to the API: ``common_name``,
    ``serial_number``, ``status``.

    Client-side filters applied after retrieval: ``product_name_id``,
    ``expires_before``, ``expires_after``.

    Args:
        digicert_cfg: The ``digicert`` section of the application config.
        vault_cfg: The ``vault`` section of the application config.
        vault_cl: An authenticated ``hvac.Client`` (or ``None`` if env-based).
        common_name: Filter by CN (server-side, substring match).
        serial_number: Filter by serial number (server-side, exact match).
        status: Filter by status (server-side, e.g. ``"issued"``).
        product_name_id: Filter by product type (client-side).
        expires_before: Client-side: only certs expiring before this date.
        expires_after: Client-side: only certs expiring after this date.
        page_size: Number of results per page.
        max_pages: Safety limit on the number of pages to fetch.

    Returns:
        List of matching ``IssuedCertificateSummary`` objects.
    """
    session = _build_session(digicert_cfg, vault_cfg, vault_cl)
    base = _base_url(digicert_cfg)
    url = f"{base}/order/certificate"

    retry_dec = _make_retry_decorator(digicert_cfg)
    cb_dec = _make_circuit_breaker(digicert_cfg, "digicert-search-certs")

    @cb_dec
    @retry_dec
    def _fetch_page(offset: int) -> JsonDict:
        params: dict[str, Any] = {
            "limit": page_size,
            "offset": offset,
        }
        if common_name:
            params["filters[common_name]"] = common_name
        if serial_number:
            params["filters[serial_number]"] = serial_number
        if status:
            params["filters[status]"] = status
        resp = session.get(url, params=params)
        _raise_for_digicert_error(resp)
        return resp.json()

    all_certs: list[IssuedCertificateSummary] = []
    offset = 0

    for _ in range(max_pages):
        try:
            payload = _fetch_page(offset)
        except RetryError as exc:
            raise DigiCertAPIError(f"Failed to search certificates after retries: {exc}") from exc

        orders: list[JsonDict] = payload.get("orders", [])
        for order in orders:
            cert_data: JsonDict = order.get("certificate", {})
            if not cert_data:
                continue
            cert_data.setdefault("order_id", order.get("id", 0))
            cert_data.setdefault("product", order.get("product", {}))
            all_certs.append(_cert_summary_from_dict(cert_data))

        page_info: JsonDict = payload.get("page", {})
        total: int = int(page_info.get("total", 0))
        offset += page_size
        if offset >= total:
            break

    # Client-side: product_name_id filter.
    if product_name_id:
        all_certs = [c for c in all_certs if product_name_id.lower() in c.product_name.lower()]

    # Client-side: expiry filter.
    if expires_before or expires_after:
        all_certs = _filter_by_expiry(
            all_certs,
            expires_before=expires_before,
            expires_after=expires_after,
        )

    logger.info(
        "DigiCert: search returned %d certificate(s) (cn=%s, status=%s).",
        len(all_certs),
        common_name,
        status,
    )
    return all_certs


# =============================================================================
# Public API: describe_certificate
# =============================================================================


def describe_certificate(
    digicert_cfg: JsonDict,
    vault_cfg: JsonDict,
    vault_cl: hvac.Client | None,
    certificate_id: int,
) -> DigiCertCertificateDetail:
    """Retrieve full detail for a single certificate.

    Calls ``GET /certificate/{certificate_id}``.

    Args:
        digicert_cfg: The ``digicert`` section of the application config.
        vault_cfg: The ``vault`` section of the application config.
        vault_cl: An authenticated ``hvac.Client`` (or ``None``).
        certificate_id: The DigiCert certificate ID.

    Returns:
        A ``DigiCertCertificateDetail`` with all available metadata.
    """
    session = _build_session(digicert_cfg, vault_cfg, vault_cl)
    base = _base_url(digicert_cfg)
    url = f"{base}/certificate/{certificate_id}"

    retry_dec = _make_retry_decorator(digicert_cfg)
    cb_dec = _make_circuit_breaker(digicert_cfg, "digicert-describe-cert")

    @cb_dec
    @retry_dec
    def _fetch() -> JsonDict:
        resp = session.get(url, timeout=_request_timeout(session))
        _raise_for_digicert_error(resp)
        return resp.json()

    try:
        data = _fetch()
    except RetryError as exc:
        raise DigiCertAPIError(
            f"Failed to describe certificate {certificate_id} after retries: {exc}"
        ) from exc

    sans_list: list[str] = []
    for san_entry in data.get("dns_names", []):
        if isinstance(san_entry, str):
            sans_list.append(san_entry)
        elif isinstance(san_entry, dict):
            sans_list.append(san_entry.get("name", ""))

    detail = DigiCertCertificateDetail(
        certificate_id=int(data.get("id", certificate_id)),
        order_id=int(data.get("order_id", 0)),
        common_name=data.get("common_name", ""),
        serial_number=data.get("serial_number", ""),
        status=data.get("status", ""),
        valid_from=data.get("valid_from", ""),
        valid_till=data.get("valid_till", ""),
        product_name=data.get("product", {}).get("name", "")
        if isinstance(data.get("product"), dict)
        else "",
        sans=sans_list,
        organization=data.get("organization", {}).get("name", "")
        if isinstance(data.get("organization"), dict)
        else "",
        signature_hash=data.get("signature_hash", ""),
        key_size=int(data.get("key_size", 0)),
        thumbprint=data.get("thumbprint", ""),
        raw=data,
    )

    logger.info(
        "DigiCert: described certificate %d (CN='%s', status='%s').",
        certificate_id,
        detail.common_name,
        detail.status,
    )
    return detail


# =============================================================================
# Public API: download_issued_certificate
# =============================================================================


def download_issued_certificate(
    digicert_cfg: JsonDict,
    vault_cfg: JsonDict,
    vault_cl: hvac.Client | None,
    certificate_id: int,
    private_key_pem: str,
) -> CertificateBundle:
    """Download an issued certificate from DigiCert in ``pem_all`` ZIP format.

    Args:
        digicert_cfg: The ``digicert`` section of the application config.
        vault_cfg: The ``vault`` section of the application config.
        vault_cl: An authenticated ``hvac.Client`` (or ``None``).
        certificate_id: The DigiCert certificate ID to download.
        private_key_pem: The PEM-encoded private key (generated locally).

    Returns:
        A ``CertificateBundle`` ready for persistence.
    """
    session = _build_session(digicert_cfg, vault_cfg, vault_cl)
    base = _base_url(digicert_cfg)
    url = f"{base}/certificate/{certificate_id}/download/format/pem_all"

    retry_dec = _make_retry_decorator(digicert_cfg)
    cb_dec = _make_circuit_breaker(digicert_cfg, "digicert-download-cert")

    @cb_dec
    @retry_dec
    def _download() -> bytes:
        resp = session.get(
            url, headers={"Accept": "application/zip"}, timeout=_request_timeout(session)
        )
        _raise_for_digicert_error(resp)
        if not resp.content:
            raise DigiCertDownloadError(
                f"DigiCert returned empty body for certificate {certificate_id} download."
            )
        return resp.content

    try:
        zip_bytes = _download()
    except RetryError as exc:
        raise DigiCertDownloadError(
            f"Failed to download certificate {certificate_id} after retries: {exc}"
        ) from exc

    cert_pem, chain_pem = _extract_pem_from_zip(zip_bytes)

    bundle = cu.assemble_bundle(
        cert_pem=cert_pem,
        private_key_pem=private_key_pem.encode("utf-8"),
        chain_pem=chain_pem,
        source_id=str(certificate_id),
    )

    logger.info(
        "DigiCert: downloaded certificate %d (CN='%s', serial='%s').",
        certificate_id,
        bundle.common_name,
        bundle.serial_number,
    )
    return bundle


# =============================================================================
# Public API: order_and_await_certificate
# =============================================================================


def order_and_await_certificate(
    digicert_cfg: JsonDict,
    vault_cfg: JsonDict,
    vault_cl: hvac.Client | None,
    order_request: OrderRequest,
) -> CertificateBundle:
    """Submit a certificate order, poll until issued, then download the bundle.

    Steps:
        1. Generate an RSA private key and CSR.
        2. Submit the order to ``POST /order/certificate/{product_name_id}``.
        3. Poll ``GET /order/certificate/{order_id}`` until the order status
           is ``"issued"`` or the configured timeout elapses.
        4. Download the certificate via ``download_issued_certificate``.

    Args:
        digicert_cfg: The ``digicert`` section of the application config.
        vault_cfg: The ``vault`` section of the application config.
        vault_cl: An authenticated ``hvac.Client`` (or ``None``).
        order_request: An ``OrderRequest`` describing the desired certificate.

    Returns:
        A ``CertificateBundle`` containing the certificate, key, and chain.

    Raises:
        DigiCertPollingTimeoutError: If issuance does not complete in time.
        DigiCertAPIError: On unexpected API failures.
    """
    # ---- 1. Key + CSR generation ----
    subject = SubjectInfo(
        common_name=order_request.common_name,
        san_dns_names=order_request.san_dns_names,
        organisation=order_request.organisation,
        organisational_unit=order_request.organisational_unit,
        country=order_request.country,
        state=order_request.state,
        locality=order_request.locality,
    )

    private_key = cu.generate_rsa_private_key(key_size=order_request.key_size)
    private_key_pem = cu.private_key_to_pem(private_key).decode("utf-8")
    csr = cu.build_csr(private_key, subject)
    csr_pem = cu.csr_to_pem(csr)

    # ---- 2. Submit order ----
    session = _build_session(digicert_cfg, vault_cfg, vault_cl)
    base = _base_url(digicert_cfg)
    url = f"{base}/order/certificate/{order_request.product_name_id}"

    order_body: JsonDict = {
        "certificate": {
            "common_name": order_request.common_name,
            "csr": csr_pem,
            "signature_hash": order_request.signature_hash,
        },
        "validity_years": order_request.validity_years,
    }

    if order_request.san_dns_names:
        order_body["certificate"]["dns_names"] = order_request.san_dns_names

    if order_request.organization_id:
        order_body["organization"] = {"id": order_request.organization_id}

    if order_request.comments:
        order_body["comments"] = order_request.comments

    retry_dec = _make_retry_decorator(digicert_cfg)
    cb_dec = _make_circuit_breaker(digicert_cfg, "digicert-order-cert")

    @cb_dec
    @retry_dec
    def _submit_order() -> JsonDict:
        resp = session.post(url, json=order_body, timeout=_request_timeout(session))
        _raise_for_digicert_error(resp)
        return resp.json()

    try:
        order_resp = _submit_order()
    except RetryError as exc:
        raise DigiCertAPIError(f"Failed to submit certificate order after retries: {exc}") from exc

    order_id: int = int(order_resp.get("id", 0))
    if not order_id:
        raise DigiCertAPIError(
            "DigiCert order response did not contain an order ID.",
            body=str(order_resp)[:200],
        )

    logger.info(
        "DigiCert: submitted order %d for CN='%s' (product=%s).",
        order_id,
        order_request.common_name,
        order_request.product_name_id,
    )

    # ---- 3. Poll for issuance ----
    polling_cfg: JsonDict = digicert_cfg.get("polling", {})
    poll_interval: int = int(polling_cfg.get("interval_seconds", 15))
    max_wait: int = int(polling_cfg.get("max_wait_seconds", 1800))
    status_url = f"{base}/order/certificate/{order_id}"

    @cb_dec
    @retry_dec
    def _check_order_status() -> JsonDict:
        resp = session.get(status_url)
        _raise_for_digicert_error(resp)
        return resp.json()

    certificate_id: int | None = None
    elapsed = 0

    while elapsed < max_wait:
        try:
            status_resp = _check_order_status()
        except RetryError as exc:
            raise DigiCertAPIError(
                f"Failed to check order {order_id} status after retries: {exc}"
            ) from exc

        order_status: str = status_resp.get("status", "")
        cert_data: JsonDict = status_resp.get("certificate", {})

        if order_status == "issued" and cert_data.get("id"):
            certificate_id = int(cert_data["id"])
            logger.info(
                "DigiCert: order %d is issued (certificate_id=%d).",
                order_id,
                certificate_id,
            )
            break

        if order_status in ("rejected", "revoked", "canceled"):
            raise DigiCertAPIError(
                f"DigiCert order {order_id} was {order_status}.",
                body=str(status_resp)[:200],
            )

        logger.debug(
            "DigiCert: order %d status='%s', waiting %ds (elapsed=%ds/%ds).",
            order_id,
            order_status,
            poll_interval,
            elapsed,
            max_wait,
        )
        time.sleep(poll_interval)
        elapsed += poll_interval

    if certificate_id is None:
        raise DigiCertPollingTimeoutError(
            f"Timed out after {max_wait}s waiting for DigiCert order {order_id} to be issued."
        )

    # ---- 4. Download ----
    bundle = download_issued_certificate(
        digicert_cfg,
        vault_cfg,
        vault_cl,
        certificate_id,
        private_key_pem,
    )

    return bundle


# =============================================================================
# Public API: revoke_certificate
# =============================================================================


def revoke_certificate(
    digicert_cfg: JsonDict,
    vault_cfg: JsonDict,
    vault_cl: hvac.Client | None,
    *,
    certificate_id: int | None = None,
    order_id: int | None = None,
    reason: str = "unspecified",
    comments: str = "",
) -> JsonDict:
    """Revoke a DigiCert certificate.

    Calls ``PUT /certificate/{certificate_id}/revoke``.

    Either ``certificate_id`` or ``order_id`` must be supplied.  When only
    ``order_id`` is given the function fetches the order detail to resolve
    the ``certificate_id``.

    Args:
        digicert_cfg: The ``digicert`` section of the application config.
        vault_cfg: The ``vault`` section of the application config.
        vault_cl: An authenticated ``hvac.Client`` (or ``None``).
        certificate_id: The DigiCert certificate ID.
        order_id: The DigiCert order ID (used to look up the certificate).
        reason: Revocation reason. One of: ``"unspecified"``,
            ``"key_compromise"``, ``"ca_compromise"``,
            ``"affiliation_changed"``, ``"superseded"``,
            ``"cessation_of_operation"``.
        comments: Optional free-text comment attached to the request.

    Returns:
        The JSON response body from DigiCert (typically empty on success,
        or status confirmation).

    Raises:
        DigiCertError: If neither ``certificate_id`` nor ``order_id`` is given.
        DigiCertAPIError: On unexpected API failures.
    """
    if certificate_id is None and order_id is None:
        raise DigiCertError(
            "Either certificate_id or order_id must be provided to revoke a certificate."
        )

    if reason not in _VALID_REVOCATION_REASONS:
        raise DigiCertError(
            f"Invalid revocation reason '{reason}'. "
            f"Valid reasons: {sorted(_VALID_REVOCATION_REASONS)}"
        )

    session = _build_session(digicert_cfg, vault_cfg, vault_cl)
    base = _base_url(digicert_cfg)

    # Resolve certificate_id from order if needed.
    if certificate_id is None:
        certificate_id = _resolve_certificate_id_from_order(
            session,
            base,
            order_id,
            digicert_cfg,  # type: ignore[arg-type]
        )

    url = f"{base}/certificate/{certificate_id}/revoke"

    revoke_body: JsonDict = {"reason": reason}
    if comments:
        revoke_body["comments"] = comments

    retry_dec = _make_retry_decorator(digicert_cfg)
    cb_dec = _make_circuit_breaker(digicert_cfg, "digicert-revoke-cert")

    @cb_dec
    @retry_dec
    def _revoke() -> JsonDict:
        resp = session.put(url, json=revoke_body, timeout=_request_timeout(session))
        _raise_for_digicert_error(resp)
        # DigiCert returns 204 No Content on successful revocation.
        if resp.status_code == 204 or not resp.content:
            return {"status": "revoked", "certificate_id": certificate_id}
        return resp.json()

    try:
        result = _revoke()
    except RetryError as exc:
        raise DigiCertAPIError(
            f"Failed to revoke certificate {certificate_id} after retries: {exc}"
        ) from exc

    logger.info(
        "DigiCert: revoked certificate %d (reason='%s').",
        certificate_id,
        reason,
    )
    return result


def _resolve_certificate_id_from_order(
    session: requests.Session,
    base_url: str,
    order_id: int,
    digicert_cfg: JsonDict,
) -> int:
    """Look up the certificate_id for a given order_id."""
    url = f"{base_url}/order/certificate/{order_id}"

    retry_dec = _make_retry_decorator(digicert_cfg)
    cb_dec = _make_circuit_breaker(digicert_cfg, "digicert-resolve-order")

    @cb_dec
    @retry_dec
    def _fetch() -> JsonDict:
        resp = session.get(url, timeout=_request_timeout(session))
        _raise_for_digicert_error(resp)
        return resp.json()

    try:
        data = _fetch()
    except RetryError as exc:
        raise DigiCertAPIError(
            f"Failed to resolve certificate for order {order_id} after retries: {exc}"
        ) from exc

    cert_data: JsonDict = data.get("certificate", {})
    cert_id = cert_data.get("id")
    if not cert_id:
        raise DigiCertCertificateNotReadyError(
            f"Order {order_id} does not have an issued certificate yet. "
            f"Order status: {data.get('status', 'unknown')}."
        )

    return int(cert_id)


# =============================================================================
# Public API: duplicate_certificate
# =============================================================================


def duplicate_certificate(
    digicert_cfg: JsonDict,
    vault_cfg: JsonDict,
    vault_cl: hvac.Client | None,
    order_id: int,
    csr_pem: str,
    *,
    common_name: str | None = None,
    san_dns_names: list[str] | None = None,
    signature_hash: str = "sha256",
    comments: str = "",
) -> JsonDict:
    """Request a duplicate certificate for an existing order.

    Calls ``POST /order/certificate/{order_id}/duplicate``.

    A duplicate reuses the validation from the original order but issues
    a new certificate with a potentially different CSR, CN, or SANs.

    Args:
        digicert_cfg: The ``digicert`` section of the application config.
        vault_cfg: The ``vault`` section of the application config.
        vault_cl: An authenticated ``hvac.Client`` (or ``None``).
        order_id: The DigiCert order ID to duplicate.
        csr_pem: PEM-encoded CSR for the duplicate certificate.
        common_name: Optional new CN (defaults to the original order's CN).
        san_dns_names: Optional new SAN list.
        signature_hash: Signature hash algorithm (default ``"sha256"``).
        comments: Optional free-text comment.

    Returns:
        The DigiCert API response dict containing the duplicate order info,
        typically including ``id`` (new order/request ID) and ``certificate_id``.

    Raises:
        DigiCertAPIError: On unexpected API failures.
        DigiCertOrderNotFoundError: If the original order cannot be found.
    """
    session = _build_session(digicert_cfg, vault_cfg, vault_cl)
    base = _base_url(digicert_cfg)
    url = f"{base}/order/certificate/{order_id}/duplicate"

    dup_body: JsonDict = {
        "certificate": {
            "csr": csr_pem,
            "signature_hash": signature_hash,
        },
    }

    if common_name:
        dup_body["certificate"]["common_name"] = common_name
    if san_dns_names:
        dup_body["certificate"]["dns_names"] = san_dns_names
    if comments:
        dup_body["comments"] = comments

    retry_dec = _make_retry_decorator(digicert_cfg)
    cb_dec = _make_circuit_breaker(digicert_cfg, "digicert-duplicate-cert")

    @cb_dec
    @retry_dec
    def _submit_duplicate() -> JsonDict:
        resp = session.post(url, json=dup_body, timeout=_request_timeout(session))
        _raise_for_digicert_error(resp)
        return resp.json()

    try:
        result = _submit_duplicate()
    except RetryError as exc:
        raise DigiCertAPIError(
            f"Failed to submit duplicate for order {order_id} after retries: {exc}"
        ) from exc

    logger.info(
        "DigiCert: submitted duplicate request for order %d (CN=%s).",
        order_id,
        common_name or "(original)",
    )
    return result
