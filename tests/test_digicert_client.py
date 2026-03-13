"""Tests for certmesh.digicert_client."""

from __future__ import annotations

import io
import zipfile
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from certmesh.digicert_client import (
    DigiCertCertificateDetail,
    IssuedCertificateSummary,
    OrderRequest,
    _cert_summary_from_dict,
    _extract_pem_from_zip,
    _filter_by_expiry,
    _raise_for_digicert_error,
    describe_certificate,
    download_issued_certificate,
    duplicate_certificate,
    list_issued_certificates,
    order_and_await_certificate,
    revoke_certificate,
    search_certificates,
)
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

JsonDict = dict[str, Any]


# =============================================================================
# Helpers
# =============================================================================


def _make_response(
    status_code: int = 200,
    json_data: JsonDict | None = None,
    content: bytes = b"",
    text: str = "",
    headers: dict[str, str] | None = None,
) -> MagicMock:
    """Build a mock ``requests.Response``."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.ok = 200 <= status_code < 300
    resp.json.return_value = json_data or {}
    resp.content = content
    resp.text = text or (str(json_data) if json_data else "")
    resp.headers = headers or {}
    return resp


def _make_zip(files: dict[str, bytes]) -> bytes:
    """Create an in-memory ZIP archive from a dict of ``{filename: content}``."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


CERT_PEM = b"-----BEGIN CERTIFICATE-----\nMIIFAKE\n-----END CERTIFICATE-----\n"
CHAIN_PEM = b"-----BEGIN CERTIFICATE-----\nMIIINTER\n-----END CERTIFICATE-----\n"


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture()
def mock_session() -> MagicMock:
    """A mock ``requests.Session`` with get/post/put stubs."""
    session = MagicMock()
    session.headers = {}
    return session


@pytest.fixture()
def _patch_build_session(mock_session: MagicMock) -> MagicMock:
    """Patch ``_build_session`` to return our mock session."""
    with patch("certmesh.digicert_client._build_session", return_value=mock_session):
        yield mock_session


# =============================================================================
# OrderRequest dataclass
# =============================================================================


class TestOrderRequest:
    def test_defaults(self) -> None:
        req = OrderRequest(common_name="example.com")
        assert req.common_name == "example.com"
        assert req.san_dns_names == []
        assert req.organisation == ""
        assert req.country == "US"
        assert req.product_name_id == "ssl_plus"
        assert req.validity_years == 1
        assert req.signature_hash == "sha256"
        assert req.organization_id is None
        assert req.key_size == 4096
        assert req.comments == ""

    def test_custom_values(self) -> None:
        req = OrderRequest(
            common_name="api.example.com",
            san_dns_names=["www.example.com"],
            organisation="Acme Inc",
            organisational_unit="Engineering",
            country="GB",
            state="London",
            locality="City",
            product_name_id="ssl_wildcard",
            validity_years=2,
            signature_hash="sha384",
            organization_id=12345,
            key_size=2048,
            comments="automated order",
        )
        assert req.common_name == "api.example.com"
        assert req.san_dns_names == ["www.example.com"]
        assert req.organisation == "Acme Inc"
        assert req.organization_id == 12345
        assert req.validity_years == 2

    def test_frozen(self) -> None:
        req = OrderRequest(common_name="test.com")
        with pytest.raises(AttributeError):
            req.common_name = "other.com"  # type: ignore[misc]


# =============================================================================
# _raise_for_digicert_error
# =============================================================================


class TestRaiseForDigicertError:
    def test_ok_response_does_nothing(self) -> None:
        resp = _make_response(status_code=200)
        _raise_for_digicert_error(resp)  # should not raise

    def test_204_ok_does_nothing(self) -> None:
        resp = _make_response(status_code=204)
        _raise_for_digicert_error(resp)

    def test_401_raises_authentication_error(self) -> None:
        resp = _make_response(status_code=401, text="Unauthorized")
        with pytest.raises(DigiCertAuthenticationError, match="authentication failed"):
            _raise_for_digicert_error(resp)

    def test_403_raises_authentication_error(self) -> None:
        resp = _make_response(status_code=403, text="Forbidden")
        with pytest.raises(DigiCertAuthenticationError, match="authentication failed"):
            _raise_for_digicert_error(resp)

    def test_404_raises_order_not_found(self) -> None:
        resp = _make_response(status_code=404, text="Not Found")
        with pytest.raises(DigiCertOrderNotFoundError, match="not found"):
            _raise_for_digicert_error(resp)

    def test_429_raises_rate_limit_error(self) -> None:
        resp = _make_response(status_code=429, text="Too Many Requests")
        with pytest.raises(DigiCertRateLimitError, match="rate limit"):
            _raise_for_digicert_error(resp)

    def test_429_with_retry_after_sleeps(self) -> None:
        resp = _make_response(
            status_code=429,
            text="Too Many Requests",
            headers={"Retry-After": "2"},
        )
        with patch("certmesh.digicert_client.time.sleep") as mock_sleep:
            with pytest.raises(DigiCertRateLimitError):
                _raise_for_digicert_error(resp)
            mock_sleep.assert_called_once_with(2)

    def test_429_with_non_numeric_retry_after(self) -> None:
        resp = _make_response(
            status_code=429,
            text="Too Many Requests",
            headers={"Retry-After": "not-a-number"},
        )
        with patch("certmesh.digicert_client.time.sleep") as mock_sleep:
            with pytest.raises(DigiCertRateLimitError):
                _raise_for_digicert_error(resp)
            mock_sleep.assert_not_called()

    def test_500_raises_api_error(self) -> None:
        resp = _make_response(status_code=500, text="Internal Server Error")
        with pytest.raises(DigiCertAPIError) as exc_info:
            _raise_for_digicert_error(resp)
        assert exc_info.value.status_code == 500

    def test_502_raises_api_error(self) -> None:
        resp = _make_response(status_code=502, text="Bad Gateway")
        with pytest.raises(DigiCertAPIError) as exc_info:
            _raise_for_digicert_error(resp)
        assert exc_info.value.status_code == 502

    def test_400_raises_api_error(self) -> None:
        resp = _make_response(status_code=400, text="Bad Request body here")
        with pytest.raises(DigiCertAPIError) as exc_info:
            _raise_for_digicert_error(resp)
        assert exc_info.value.status_code == 400
        assert "Bad Request" in (exc_info.value.body or "")

    def test_body_truncated_to_500_chars(self) -> None:
        long_text = "x" * 1000
        resp = _make_response(status_code=500, text=long_text)
        with pytest.raises(DigiCertAPIError) as exc_info:
            _raise_for_digicert_error(resp)
        assert len(exc_info.value.body or "") <= 500


# =============================================================================
# _extract_pem_from_zip
# =============================================================================


class TestExtractPemFromZip:
    def test_single_cert_no_chain(self) -> None:
        zip_bytes = _make_zip({"server.pem": CERT_PEM})
        cert, chain = _extract_pem_from_zip(zip_bytes)
        assert cert == CERT_PEM
        assert chain is None

    def test_cert_and_intermediate_chain(self) -> None:
        zip_bytes = _make_zip(
            {
                "server.pem": CERT_PEM,
                "intermediate.pem": CHAIN_PEM,
            }
        )
        cert, chain = _extract_pem_from_zip(zip_bytes)
        assert cert == CERT_PEM
        assert chain is not None
        assert CHAIN_PEM in chain

    def test_cert_and_ca_bundle(self) -> None:
        zip_bytes = _make_zip(
            {
                "domain.pem": CERT_PEM,
                "ca-bundle.pem": CHAIN_PEM,
            }
        )
        cert, chain = _extract_pem_from_zip(zip_bytes)
        assert cert == CERT_PEM
        assert chain is not None

    def test_chain_keyword_in_filename(self) -> None:
        zip_bytes = _make_zip(
            {
                "cert.pem": CERT_PEM,
                "chain.pem": CHAIN_PEM,
            }
        )
        cert, chain = _extract_pem_from_zip(zip_bytes)
        assert cert == CERT_PEM
        assert chain is not None

    def test_root_keyword_in_filename(self) -> None:
        zip_bytes = _make_zip(
            {
                "leaf.pem": CERT_PEM,
                "root.pem": CHAIN_PEM,
            }
        )
        cert, chain = _extract_pem_from_zip(zip_bytes)
        assert cert == CERT_PEM
        assert chain is not None

    def test_multiple_chain_files_concatenated(self) -> None:
        inter1 = b"-----BEGIN CERTIFICATE-----\nINTER1\n-----END CERTIFICATE-----\n"
        inter2 = b"-----BEGIN CERTIFICATE-----\nINTER2\n-----END CERTIFICATE-----\n"
        zip_bytes = _make_zip(
            {
                "cert.pem": CERT_PEM,
                "intermediate1.pem": inter1,
                "intermediate2.pem": inter2,
            }
        )
        cert, chain = _extract_pem_from_zip(zip_bytes)
        assert cert == CERT_PEM
        assert chain is not None
        assert inter1 in chain
        assert inter2 in chain

    def test_non_pem_files_ignored(self) -> None:
        zip_bytes = _make_zip(
            {
                "cert.pem": CERT_PEM,
                "readme.txt": b"some instructions",
                "logo.png": b"\x89PNG",
            }
        )
        cert, chain = _extract_pem_from_zip(zip_bytes)
        assert cert == CERT_PEM
        assert chain is None

    def test_bad_zip_raises(self) -> None:
        with pytest.raises(DigiCertDownloadError, match="not a valid ZIP"):
            _extract_pem_from_zip(b"this is not a zip file")

    def test_empty_zip_raises(self) -> None:
        zip_bytes = _make_zip({})
        with pytest.raises(DigiCertDownloadError, match="does not contain any .pem"):
            _extract_pem_from_zip(zip_bytes)

    def test_zip_with_only_non_pem_files_raises(self) -> None:
        zip_bytes = _make_zip({"readme.txt": b"hello"})
        with pytest.raises(DigiCertDownloadError, match="does not contain any .pem"):
            _extract_pem_from_zip(zip_bytes)

    def test_all_files_are_chain_raises(self) -> None:
        """If all PEM files are detected as chain, cert_pem stays None."""
        zip_bytes = _make_zip(
            {
                "intermediate.pem": CHAIN_PEM,
                "root.pem": CHAIN_PEM,
            }
        )
        with pytest.raises(DigiCertDownloadError, match="Could not identify"):
            _extract_pem_from_zip(zip_bytes)

    def test_extra_pem_goes_to_chain(self) -> None:
        extra = b"-----BEGIN CERTIFICATE-----\nEXTRA\n-----END CERTIFICATE-----\n"
        zip_bytes = _make_zip(
            {
                "aaa_cert.pem": CERT_PEM,
                "bbb_extra.pem": extra,
            }
        )
        cert, chain = _extract_pem_from_zip(zip_bytes)
        assert cert == CERT_PEM
        assert chain is not None
        assert extra in chain


# =============================================================================
# _cert_summary_from_dict
# =============================================================================


class TestCertSummaryFromDict:
    def test_full_data(self) -> None:
        data: JsonDict = {
            "id": 1001,
            "order_id": 5001,
            "common_name": "test.example.com",
            "serial_number": "AABB",
            "status": "issued",
            "valid_from": "2025-01-01",
            "valid_till": "2026-01-01",
            "product": {"name": "SSL Plus"},
        }
        summary = _cert_summary_from_dict(data)
        assert summary.certificate_id == 1001
        assert summary.order_id == 5001
        assert summary.common_name == "test.example.com"
        assert summary.serial_number == "AABB"
        assert summary.status == "issued"
        assert summary.valid_from == "2025-01-01"
        assert summary.valid_till == "2026-01-01"
        assert summary.product_name == "SSL Plus"

    def test_missing_fields_use_defaults(self) -> None:
        data: JsonDict = {}
        summary = _cert_summary_from_dict(data)
        assert summary.certificate_id == 0
        assert summary.order_id == 0
        assert summary.common_name == ""
        assert summary.serial_number == ""
        assert summary.status == ""
        assert summary.product_name == ""

    def test_certificate_id_fallback(self) -> None:
        data: JsonDict = {"certificate_id": 999}
        summary = _cert_summary_from_dict(data)
        assert summary.certificate_id == 999

    def test_product_as_string(self) -> None:
        data: JsonDict = {"product_name": "WildCard"}
        summary = _cert_summary_from_dict(data)
        assert summary.product_name == "WildCard"

    def test_product_as_dict(self) -> None:
        data: JsonDict = {"product": {"name": "EV SSL"}}
        summary = _cert_summary_from_dict(data)
        assert summary.product_name == "EV SSL"

    def test_product_dict_without_name(self) -> None:
        data: JsonDict = {"product": {"id": "ssl_plus"}}
        summary = _cert_summary_from_dict(data)
        assert summary.product_name == ""


# =============================================================================
# _filter_by_expiry
# =============================================================================


class TestFilterByExpiry:
    def _make_cert(self, valid_till: str) -> IssuedCertificateSummary:
        return IssuedCertificateSummary(
            certificate_id=1,
            order_id=1,
            common_name="test.com",
            serial_number="AA",
            status="issued",
            valid_from="2025-01-01",
            valid_till=valid_till,
            product_name="SSL Plus",
        )

    def test_no_filters_returns_all(self) -> None:
        certs = [self._make_cert("2026-06-15")]
        result = _filter_by_expiry(certs)
        assert len(result) == 1

    def test_expires_before_keeps_earlier(self) -> None:
        before = datetime(2026, 7, 1, tzinfo=timezone.utc)
        certs = [
            self._make_cert("2026-06-15"),  # expires before cutoff -> keep
            self._make_cert("2026-08-01"),  # expires after cutoff -> drop
        ]
        result = _filter_by_expiry(certs, expires_before=before)
        assert len(result) == 1
        assert result[0].valid_till == "2026-06-15"

    def test_expires_after_keeps_later(self) -> None:
        after = datetime(2026, 7, 1, tzinfo=timezone.utc)
        certs = [
            self._make_cert("2026-06-15"),  # expires before cutoff -> drop
            self._make_cert("2026-08-01"),  # expires after cutoff -> keep
        ]
        result = _filter_by_expiry(certs, expires_after=after)
        assert len(result) == 1
        assert result[0].valid_till == "2026-08-01"

    def test_both_filters_combined(self) -> None:
        after = datetime(2026, 3, 1, tzinfo=timezone.utc)
        before = datetime(2026, 9, 1, tzinfo=timezone.utc)
        certs = [
            self._make_cert("2026-01-15"),  # too early -> drop
            self._make_cert("2026-06-15"),  # in range -> keep
            self._make_cert("2026-12-01"),  # too late -> drop
        ]
        result = _filter_by_expiry(certs, expires_before=before, expires_after=after)
        assert len(result) == 1
        assert result[0].valid_till == "2026-06-15"

    def test_unparseable_date_passes_through(self) -> None:
        certs = [self._make_cert("not-a-date")]
        result = _filter_by_expiry(
            certs,
            expires_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        assert len(result) == 1

    def test_empty_list(self) -> None:
        result = _filter_by_expiry([], expires_before=datetime(2026, 1, 1, tzinfo=timezone.utc))
        assert result == []

    def test_exact_boundary_excluded_by_expires_before(self) -> None:
        """Cert expiring on the exact cutoff date is excluded (>=)."""
        cutoff = datetime(2026, 6, 15, tzinfo=timezone.utc)
        certs = [self._make_cert("2026-06-15")]
        result = _filter_by_expiry(certs, expires_before=cutoff)
        assert len(result) == 0

    def test_exact_boundary_excluded_by_expires_after(self) -> None:
        """Cert expiring on the exact cutoff date is excluded (<=)."""
        cutoff = datetime(2026, 6, 15, tzinfo=timezone.utc)
        certs = [self._make_cert("2026-06-15")]
        result = _filter_by_expiry(certs, expires_after=cutoff)
        assert len(result) == 0


# =============================================================================
# list_issued_certificates
# =============================================================================


class TestListIssuedCertificates:
    def _orders_page(
        self,
        orders: list[JsonDict],
        total: int,
    ) -> JsonDict:
        return {"orders": orders, "page": {"total": total}}

    def _order(
        self,
        order_id: int = 100,
        cert_id: int = 200,
        cn: str = "test.com",
    ) -> JsonDict:
        return {
            "id": order_id,
            "product": {"name": "SSL Plus"},
            "certificate": {
                "id": cert_id,
                "common_name": cn,
                "serial_number": "AA",
                "status": "issued",
                "valid_from": "2025-01-01",
                "valid_till": "2026-01-01",
            },
        }

    @pytest.mark.usefixtures("_patch_build_session")
    def test_single_page(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        page = self._orders_page([self._order()], total=1)
        mock_session.get.return_value = _make_response(json_data=page)

        result = list_issued_certificates(digicert_cfg, vault_cfg, None)
        assert len(result) == 1
        assert result[0].certificate_id == 200
        assert result[0].common_name == "test.com"

    @pytest.mark.usefixtures("_patch_build_session")
    def test_multi_page_pagination(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        page1 = self._orders_page([self._order(order_id=1, cert_id=10, cn="a.com")], total=2)
        page2 = self._orders_page([self._order(order_id=2, cert_id=20, cn="b.com")], total=2)
        mock_session.get.side_effect = [
            _make_response(json_data=page1),
            _make_response(json_data=page2),
        ]

        result = list_issued_certificates(digicert_cfg, vault_cfg, None, page_size=1)
        assert len(result) == 2
        assert {c.common_name for c in result} == {"a.com", "b.com"}

    @pytest.mark.usefixtures("_patch_build_session")
    def test_status_filter_passed_to_api(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        page = self._orders_page([], total=0)
        mock_session.get.return_value = _make_response(json_data=page)

        list_issued_certificates(digicert_cfg, vault_cfg, None, status="issued")
        call_kwargs = mock_session.get.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params", {})
        assert params.get("filters[status]") == "issued"

    @pytest.mark.usefixtures("_patch_build_session")
    def test_expiry_filters_applied_client_side(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        order_early = self._order(order_id=1, cert_id=10, cn="early.com")
        order_early["certificate"]["valid_till"] = "2025-06-01"
        order_late = self._order(order_id=2, cert_id=20, cn="late.com")
        order_late["certificate"]["valid_till"] = "2027-06-01"

        page = self._orders_page([order_early, order_late], total=2)
        mock_session.get.return_value = _make_response(json_data=page)

        result = list_issued_certificates(
            digicert_cfg,
            vault_cfg,
            None,
            expires_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        assert len(result) == 1
        assert result[0].common_name == "early.com"

    @pytest.mark.usefixtures("_patch_build_session")
    def test_orders_without_certificate_skipped(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        page = self._orders_page(
            [{"id": 1, "product": {"name": "SSL"}, "certificate": {}}],
            total=1,
        )
        mock_session.get.return_value = _make_response(json_data=page)

        result = list_issued_certificates(digicert_cfg, vault_cfg, None)
        assert len(result) == 0

    @pytest.mark.usefixtures("_patch_build_session")
    def test_api_error_raises(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        mock_session.get.return_value = _make_response(
            status_code=500, text="Internal Server Error"
        )
        with pytest.raises(DigiCertAPIError):
            list_issued_certificates(digicert_cfg, vault_cfg, None)

    @pytest.mark.usefixtures("_patch_build_session")
    def test_auth_error_raises(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        mock_session.get.return_value = _make_response(status_code=401, text="Unauthorized")
        with pytest.raises(DigiCertAuthenticationError):
            list_issued_certificates(digicert_cfg, vault_cfg, None)


# =============================================================================
# search_certificates
# =============================================================================


class TestSearchCertificates:
    def _orders_page(self, orders: list[JsonDict], total: int) -> JsonDict:
        return {"orders": orders, "page": {"total": total}}

    def _order(
        self,
        order_id: int = 100,
        cert_id: int = 200,
        cn: str = "test.com",
        product_name: str = "SSL Plus",
    ) -> JsonDict:
        return {
            "id": order_id,
            "product": {"name": product_name},
            "certificate": {
                "id": cert_id,
                "common_name": cn,
                "serial_number": "BB",
                "status": "issued",
                "valid_from": "2025-01-01",
                "valid_till": "2026-01-01",
            },
        }

    @pytest.mark.usefixtures("_patch_build_session")
    def test_search_by_common_name(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        page = self._orders_page([self._order(cn="api.example.com")], total=1)
        mock_session.get.return_value = _make_response(json_data=page)

        result = search_certificates(digicert_cfg, vault_cfg, None, common_name="api.example.com")
        assert len(result) == 1

        call_kwargs = mock_session.get.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params", {})
        assert params.get("filters[common_name]") == "api.example.com"

    @pytest.mark.usefixtures("_patch_build_session")
    def test_search_by_serial_number(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        page = self._orders_page([self._order()], total=1)
        mock_session.get.return_value = _make_response(json_data=page)

        search_certificates(digicert_cfg, vault_cfg, None, serial_number="AABB")
        call_kwargs = mock_session.get.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params", {})
        assert params.get("filters[serial_number]") == "AABB"

    @pytest.mark.usefixtures("_patch_build_session")
    def test_product_name_id_client_filter(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        page = self._orders_page(
            [
                self._order(order_id=1, cert_id=10, product_name="SSL Plus"),
                self._order(order_id=2, cert_id=20, product_name="EV SSL"),
            ],
            total=2,
        )
        mock_session.get.return_value = _make_response(json_data=page)

        result = search_certificates(digicert_cfg, vault_cfg, None, product_name_id="EV")
        assert len(result) == 1
        assert result[0].product_name == "EV SSL"

    @pytest.mark.usefixtures("_patch_build_session")
    def test_expiry_filter_client_side(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        order = self._order()
        order["certificate"]["valid_till"] = "2025-06-01"
        page = self._orders_page([order], total=1)
        mock_session.get.return_value = _make_response(json_data=page)

        result = search_certificates(
            digicert_cfg,
            vault_cfg,
            None,
            expires_after=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        assert len(result) == 0

    @pytest.mark.usefixtures("_patch_build_session")
    def test_search_empty_result(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        page = self._orders_page([], total=0)
        mock_session.get.return_value = _make_response(json_data=page)

        result = search_certificates(digicert_cfg, vault_cfg, None)
        assert result == []

    @pytest.mark.usefixtures("_patch_build_session")
    def test_search_api_error(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        mock_session.get.return_value = _make_response(status_code=403, text="Forbidden")
        with pytest.raises(DigiCertAuthenticationError):
            search_certificates(digicert_cfg, vault_cfg, None)


# =============================================================================
# describe_certificate
# =============================================================================


class TestDescribeCertificate:
    def _cert_detail(self) -> JsonDict:
        return {
            "id": 1001,
            "order_id": 5001,
            "common_name": "api.example.com",
            "serial_number": "AABBCCDD",
            "status": "issued",
            "valid_from": "2025-01-01",
            "valid_till": "2026-01-01",
            "product": {"name": "SSL Plus"},
            "dns_names": ["api.example.com", {"name": "www.example.com"}],
            "organization": {"name": "Acme Inc"},
            "signature_hash": "sha256",
            "key_size": 4096,
            "thumbprint": "AABB1122",
        }

    @pytest.mark.usefixtures("_patch_build_session")
    def test_success(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        mock_session.get.return_value = _make_response(json_data=self._cert_detail())

        detail = describe_certificate(digicert_cfg, vault_cfg, None, 1001)
        assert isinstance(detail, DigiCertCertificateDetail)
        assert detail.certificate_id == 1001
        assert detail.order_id == 5001
        assert detail.common_name == "api.example.com"
        assert detail.serial_number == "AABBCCDD"
        assert detail.status == "issued"
        assert detail.product_name == "SSL Plus"
        assert detail.sans == ["api.example.com", "www.example.com"]
        assert detail.organization == "Acme Inc"
        assert detail.signature_hash == "sha256"
        assert detail.key_size == 4096
        assert detail.thumbprint == "AABB1122"
        assert detail.raw == self._cert_detail()

    @pytest.mark.usefixtures("_patch_build_session")
    def test_missing_optional_fields(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        data: JsonDict = {"id": 2002}
        mock_session.get.return_value = _make_response(json_data=data)

        detail = describe_certificate(digicert_cfg, vault_cfg, None, 2002)
        assert detail.certificate_id == 2002
        assert detail.common_name == ""
        assert detail.sans == []
        assert detail.organization == ""
        assert detail.key_size == 0

    @pytest.mark.usefixtures("_patch_build_session")
    def test_404_raises(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        mock_session.get.return_value = _make_response(status_code=404, text="Not Found")
        with pytest.raises(DigiCertOrderNotFoundError):
            describe_certificate(digicert_cfg, vault_cfg, None, 9999)


# =============================================================================
# download_issued_certificate
# =============================================================================


class TestDownloadIssuedCertificate:
    @pytest.mark.usefixtures("_patch_build_session")
    def test_success(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
        self_signed_cert_pem: bytes,
        private_key_pem: bytes,
    ) -> None:
        zip_bytes = _make_zip(
            {
                "server.pem": self_signed_cert_pem,
                "intermediate.pem": CHAIN_PEM,
            }
        )
        mock_session.get.return_value = _make_response(content=zip_bytes)

        bundle = download_issued_certificate(
            digicert_cfg,
            vault_cfg,
            None,
            certificate_id=1001,
            private_key_pem=private_key_pem.decode("utf-8"),
        )
        assert bundle.common_name == "test.example.com"
        assert bundle.source_id == "1001"
        assert bundle.private_key_pem == private_key_pem.decode("utf-8")
        assert bundle.chain_pem is not None

    @pytest.mark.usefixtures("_patch_build_session")
    def test_empty_body_raises(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        mock_session.get.return_value = _make_response(content=b"")
        with pytest.raises(DigiCertDownloadError, match="empty body"):
            download_issued_certificate(digicert_cfg, vault_cfg, None, 1001, "key-pem")

    @pytest.mark.usefixtures("_patch_build_session")
    def test_bad_zip_raises(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        mock_session.get.return_value = _make_response(content=b"not-a-zip")
        with pytest.raises(DigiCertDownloadError, match="not a valid ZIP"):
            download_issued_certificate(digicert_cfg, vault_cfg, None, 1001, "key-pem")

    @pytest.mark.usefixtures("_patch_build_session")
    def test_api_error_on_download(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        mock_session.get.return_value = _make_response(status_code=500, text="Server Error")
        with pytest.raises(DigiCertAPIError):
            download_issued_certificate(digicert_cfg, vault_cfg, None, 1001, "key-pem")


# =============================================================================
# order_and_await_certificate
# =============================================================================


class TestOrderAndAwaitCertificate:
    @pytest.mark.usefixtures("_patch_build_session")
    def test_immediate_issuance(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
        self_signed_cert_pem: bytes,
        private_key_pem: bytes,
    ) -> None:
        # Step 2: submit order
        order_resp = _make_response(json_data={"id": 5001})
        # Step 3: poll status -- issued immediately
        status_resp = _make_response(
            json_data={
                "status": "issued",
                "certificate": {"id": 3001},
            }
        )
        # Step 4: download
        zip_bytes = _make_zip({"server.pem": self_signed_cert_pem})
        download_resp = _make_response(content=zip_bytes)

        mock_session.post.return_value = order_resp
        mock_session.get.side_effect = [status_resp, download_resp]

        order_req = OrderRequest(common_name="test.example.com")

        with (
            patch("certmesh.digicert_client.cu.generate_rsa_private_key") as mock_keygen,
            patch("certmesh.digicert_client.cu.private_key_to_pem", return_value=private_key_pem),
            patch("certmesh.digicert_client.cu.build_csr") as mock_csr,
            patch("certmesh.digicert_client.cu.csr_to_pem", return_value="CSR-PEM"),
        ):
            mock_keygen.return_value = MagicMock()
            mock_csr.return_value = MagicMock()

            bundle = order_and_await_certificate(digicert_cfg, vault_cfg, None, order_req)

        assert bundle.common_name == "test.example.com"
        mock_session.post.assert_called_once()

    @pytest.mark.usefixtures("_patch_build_session")
    def test_polling_until_issued(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
        self_signed_cert_pem: bytes,
        private_key_pem: bytes,
    ) -> None:
        order_resp = _make_response(json_data={"id": 5001})
        pending_resp = _make_response(json_data={"status": "pending", "certificate": {}})
        issued_resp = _make_response(
            json_data={
                "status": "issued",
                "certificate": {"id": 3001},
            }
        )
        zip_bytes = _make_zip({"server.pem": self_signed_cert_pem})
        download_resp = _make_response(content=zip_bytes)

        mock_session.post.return_value = order_resp
        mock_session.get.side_effect = [pending_resp, issued_resp, download_resp]

        order_req = OrderRequest(common_name="test.example.com")

        with (
            patch("certmesh.digicert_client.cu.generate_rsa_private_key") as mock_keygen,
            patch("certmesh.digicert_client.cu.private_key_to_pem", return_value=private_key_pem),
            patch("certmesh.digicert_client.cu.build_csr"),
            patch("certmesh.digicert_client.cu.csr_to_pem", return_value="CSR-PEM"),
            patch("certmesh.digicert_client.time.sleep"),
        ):
            mock_keygen.return_value = MagicMock()

            bundle = order_and_await_certificate(digicert_cfg, vault_cfg, None, order_req)

        assert bundle.common_name == "test.example.com"

    @pytest.mark.usefixtures("_patch_build_session")
    def test_order_rejected_raises(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
        private_key_pem: bytes,
    ) -> None:
        order_resp = _make_response(json_data={"id": 5001})
        rejected_resp = _make_response(json_data={"status": "rejected", "certificate": {}})

        mock_session.post.return_value = order_resp
        mock_session.get.return_value = rejected_resp

        order_req = OrderRequest(common_name="test.com")

        with (
            patch("certmesh.digicert_client.cu.generate_rsa_private_key") as mock_keygen,
            patch("certmesh.digicert_client.cu.private_key_to_pem", return_value=private_key_pem),
            patch("certmesh.digicert_client.cu.build_csr"),
            patch("certmesh.digicert_client.cu.csr_to_pem", return_value="CSR-PEM"),
        ):
            mock_keygen.return_value = MagicMock()

            with pytest.raises(DigiCertAPIError, match="rejected"):
                order_and_await_certificate(digicert_cfg, vault_cfg, None, order_req)

    @pytest.mark.usefixtures("_patch_build_session")
    def test_polling_timeout_raises(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
        private_key_pem: bytes,
    ) -> None:
        # Make polling timeout very short
        digicert_cfg["polling"] = {
            "interval_seconds": 1,
            "max_wait_seconds": 0,
        }

        order_resp = _make_response(json_data={"id": 5001})
        mock_session.post.return_value = order_resp
        # Never reaches "issued"
        mock_session.get.return_value = _make_response(
            json_data={"status": "pending", "certificate": {}}
        )

        order_req = OrderRequest(common_name="test.com")

        with (
            patch("certmesh.digicert_client.cu.generate_rsa_private_key") as mock_keygen,
            patch("certmesh.digicert_client.cu.private_key_to_pem", return_value=private_key_pem),
            patch("certmesh.digicert_client.cu.build_csr"),
            patch("certmesh.digicert_client.cu.csr_to_pem", return_value="CSR-PEM"),
            patch("certmesh.digicert_client.time.sleep"),
        ):
            mock_keygen.return_value = MagicMock()

            with pytest.raises(DigiCertPollingTimeoutError, match="Timed out"):
                order_and_await_certificate(digicert_cfg, vault_cfg, None, order_req)

    @pytest.mark.usefixtures("_patch_build_session")
    def test_no_order_id_in_response_raises(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
        private_key_pem: bytes,
    ) -> None:
        # Response without an order ID
        order_resp = _make_response(json_data={})
        mock_session.post.return_value = order_resp

        order_req = OrderRequest(common_name="test.com")

        with (
            patch("certmesh.digicert_client.cu.generate_rsa_private_key") as mock_keygen,
            patch("certmesh.digicert_client.cu.private_key_to_pem", return_value=private_key_pem),
            patch("certmesh.digicert_client.cu.build_csr"),
            patch("certmesh.digicert_client.cu.csr_to_pem", return_value="CSR-PEM"),
        ):
            mock_keygen.return_value = MagicMock()

            with pytest.raises(DigiCertAPIError, match="order ID"):
                order_and_await_certificate(digicert_cfg, vault_cfg, None, order_req)

    @pytest.mark.usefixtures("_patch_build_session")
    def test_order_body_includes_sans_and_org(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
        self_signed_cert_pem: bytes,
        private_key_pem: bytes,
    ) -> None:
        order_resp = _make_response(json_data={"id": 5001})
        issued_resp = _make_response(
            json_data={
                "status": "issued",
                "certificate": {"id": 3001},
            }
        )
        zip_bytes = _make_zip({"server.pem": self_signed_cert_pem})
        download_resp = _make_response(content=zip_bytes)

        mock_session.post.return_value = order_resp
        mock_session.get.side_effect = [issued_resp, download_resp]

        order_req = OrderRequest(
            common_name="test.example.com",
            san_dns_names=["www.example.com"],
            organization_id=9999,
            comments="auto order",
        )

        with (
            patch("certmesh.digicert_client.cu.generate_rsa_private_key") as mock_keygen,
            patch("certmesh.digicert_client.cu.private_key_to_pem", return_value=private_key_pem),
            patch("certmesh.digicert_client.cu.build_csr"),
            patch("certmesh.digicert_client.cu.csr_to_pem", return_value="CSR-PEM"),
        ):
            mock_keygen.return_value = MagicMock()

            order_and_await_certificate(digicert_cfg, vault_cfg, None, order_req)

        post_call = mock_session.post.call_args
        body = post_call.kwargs.get("json") or post_call[1].get("json", {})
        assert body["certificate"]["dns_names"] == ["www.example.com"]
        assert body["organization"] == {"id": 9999}
        assert body["comments"] == "auto order"


# =============================================================================
# revoke_certificate
# =============================================================================


class TestRevokeCertificate:
    @pytest.mark.usefixtures("_patch_build_session")
    def test_revoke_by_certificate_id(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        mock_session.put.return_value = _make_response(status_code=204, content=b"")

        result = revoke_certificate(
            digicert_cfg,
            vault_cfg,
            None,
            certificate_id=1001,
            reason="key_compromise",
            comments="compromised key",
        )
        assert result["status"] == "revoked"
        assert result["certificate_id"] == 1001

        put_call = mock_session.put.call_args
        body = put_call.kwargs.get("json") or put_call[1].get("json", {})
        assert body["reason"] == "key_compromise"
        assert body["comments"] == "compromised key"

    @pytest.mark.usefixtures("_patch_build_session")
    def test_revoke_by_order_id_resolves_cert(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        # First call: resolve cert ID from order
        order_resp = _make_response(json_data={"certificate": {"id": 2002}, "status": "issued"})
        # Second call: revoke
        revoke_resp = _make_response(status_code=204, content=b"")

        mock_session.get.return_value = order_resp
        mock_session.put.return_value = revoke_resp

        result = revoke_certificate(digicert_cfg, vault_cfg, None, order_id=5001)
        assert result["status"] == "revoked"
        assert result["certificate_id"] == 2002

    def test_no_id_raises(
        self,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        with pytest.raises(DigiCertError, match="Either certificate_id or order_id"):
            revoke_certificate(digicert_cfg, vault_cfg, None)

    def test_invalid_reason_raises(
        self,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        with pytest.raises(DigiCertError, match="Invalid revocation reason"):
            revoke_certificate(
                digicert_cfg,
                vault_cfg,
                None,
                certificate_id=1001,
                reason="invalid_reason",
            )

    @pytest.mark.usefixtures("_patch_build_session")
    def test_revoke_with_json_body_response(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        mock_session.put.return_value = _make_response(
            status_code=200,
            json_data={"id": 1001, "status": "revoked"},
            content=b'{"id": 1001, "status": "revoked"}',
        )

        result = revoke_certificate(digicert_cfg, vault_cfg, None, certificate_id=1001)
        assert result == {"id": 1001, "status": "revoked"}

    @pytest.mark.usefixtures("_patch_build_session")
    def test_revoke_order_without_cert_raises(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        mock_session.get.return_value = _make_response(
            json_data={"certificate": {}, "status": "pending"}
        )

        with pytest.raises(DigiCertCertificateNotReadyError, match="not have an issued"):
            revoke_certificate(digicert_cfg, vault_cfg, None, order_id=5001)

    @pytest.mark.usefixtures("_patch_build_session")
    def test_all_valid_revocation_reasons(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        valid_reasons = [
            "unspecified",
            "key_compromise",
            "ca_compromise",
            "affiliation_changed",
            "superseded",
            "cessation_of_operation",
        ]
        mock_session.put.return_value = _make_response(status_code=204, content=b"")
        for reason in valid_reasons:
            result = revoke_certificate(
                digicert_cfg,
                vault_cfg,
                None,
                certificate_id=1001,
                reason=reason,
            )
            assert result["status"] == "revoked"

    @pytest.mark.usefixtures("_patch_build_session")
    def test_revoke_api_error(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        mock_session.put.return_value = _make_response(status_code=500, text="Internal Error")
        with pytest.raises(DigiCertAPIError):
            revoke_certificate(digicert_cfg, vault_cfg, None, certificate_id=1001)


# =============================================================================
# duplicate_certificate
# =============================================================================


class TestDuplicateCertificate:
    @pytest.mark.usefixtures("_patch_build_session")
    def test_basic_duplicate(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        mock_session.post.return_value = _make_response(
            json_data={"id": 6001, "certificate_id": 3001}
        )

        result = duplicate_certificate(
            digicert_cfg, vault_cfg, None, order_id=5001, csr_pem="CSR-PEM"
        )
        assert result["id"] == 6001
        assert result["certificate_id"] == 3001

        post_call = mock_session.post.call_args
        body = post_call.kwargs.get("json") or post_call[1].get("json", {})
        assert body["certificate"]["csr"] == "CSR-PEM"
        assert body["certificate"]["signature_hash"] == "sha256"

    @pytest.mark.usefixtures("_patch_build_session")
    def test_duplicate_with_optional_fields(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        mock_session.post.return_value = _make_response(json_data={"id": 6002})

        duplicate_certificate(
            digicert_cfg,
            vault_cfg,
            None,
            order_id=5001,
            csr_pem="CSR-PEM",
            common_name="new.example.com",
            san_dns_names=["www.new.example.com"],
            signature_hash="sha384",
            comments="test duplicate",
        )

        post_call = mock_session.post.call_args
        body = post_call.kwargs.get("json") or post_call[1].get("json", {})
        assert body["certificate"]["common_name"] == "new.example.com"
        assert body["certificate"]["dns_names"] == ["www.new.example.com"]
        assert body["certificate"]["signature_hash"] == "sha384"
        assert body["comments"] == "test duplicate"

    @pytest.mark.usefixtures("_patch_build_session")
    def test_duplicate_no_optional_fields(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        mock_session.post.return_value = _make_response(json_data={"id": 6003})

        duplicate_certificate(digicert_cfg, vault_cfg, None, order_id=5001, csr_pem="CSR")

        post_call = mock_session.post.call_args
        body = post_call.kwargs.get("json") or post_call[1].get("json", {})
        assert "common_name" not in body["certificate"]
        assert "dns_names" not in body["certificate"]
        assert "comments" not in body

    @pytest.mark.usefixtures("_patch_build_session")
    def test_duplicate_404_raises(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        mock_session.post.return_value = _make_response(status_code=404, text="Order not found")
        with pytest.raises(DigiCertOrderNotFoundError):
            duplicate_certificate(digicert_cfg, vault_cfg, None, order_id=9999, csr_pem="CSR")

    @pytest.mark.usefixtures("_patch_build_session")
    def test_duplicate_api_error(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        mock_session.post.return_value = _make_response(status_code=500, text="Internal Error")
        with pytest.raises(DigiCertAPIError):
            duplicate_certificate(digicert_cfg, vault_cfg, None, order_id=5001, csr_pem="CSR")

    @pytest.mark.usefixtures("_patch_build_session")
    def test_duplicate_url_includes_order_id(
        self,
        mock_session: MagicMock,
        digicert_cfg: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        mock_session.post.return_value = _make_response(json_data={"id": 1})

        duplicate_certificate(digicert_cfg, vault_cfg, None, order_id=7777, csr_pem="CSR")
        post_call = mock_session.post.call_args
        url = post_call.args[0] if post_call.args else post_call[0][0]
        assert "7777/duplicate" in url


# =============================================================================
# IssuedCertificateSummary and DigiCertCertificateDetail dataclasses
# =============================================================================


class TestDataclasses:
    def test_issued_certificate_summary_frozen(self) -> None:
        summary = IssuedCertificateSummary(
            certificate_id=1,
            order_id=1,
            common_name="test.com",
            serial_number="AA",
            status="issued",
            valid_from="2025-01-01",
            valid_till="2026-01-01",
            product_name="SSL",
        )
        with pytest.raises(AttributeError):
            summary.common_name = "other.com"  # type: ignore[misc]

    def test_digicert_certificate_detail_frozen(self) -> None:
        detail = DigiCertCertificateDetail(
            certificate_id=1,
            order_id=1,
            common_name="test.com",
            serial_number="AA",
            status="issued",
            valid_from="2025-01-01",
            valid_till="2026-01-01",
            product_name="SSL",
            sans=[],
            organization="Org",
            signature_hash="sha256",
            key_size=4096,
            thumbprint="AABB",
            raw={},
        )
        with pytest.raises(AttributeError):
            detail.common_name = "other.com"  # type: ignore[misc]
