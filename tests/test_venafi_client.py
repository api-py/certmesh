"""Tests for certmesh.venafi_client."""

from __future__ import annotations

import base64
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from certmesh.certificate_utils import CertificateBundle, SubjectInfo
from certmesh.exceptions import (
    ConfigurationError,
    VenafiAPIError,
    VenafiAuthenticationError,
    VenafiCertificateNotFoundError,
    VenafiLDAPAuthError,
    VenafiPollingTimeoutError,
    VenafiPrivateKeyExportError,
    VenafiWorkflowApprovalError,
)
from certmesh.venafi_client import (
    _authenticate_ldap,
    _authenticate_oauth,
    _is_guid,
    _raise_for_status,
    _split_pem_chain,
    authenticate,
    describe_certificate,
    list_certificates,
    renew_and_download_certificate,
    request_certificate,
    revoke_certificate,
    search_certificates,
)

JsonDict = dict[str, Any]

# ---------------------------------------------------------------------------
# Helpers for building mock responses
# ---------------------------------------------------------------------------

BASE_URL = "https://venafi.corp.example.com"


def _mock_response(
    *,
    status_code: int = 200,
    json_data: JsonDict | None = None,
    text: str = "",
    content: bytes = b"",
    ok: bool | None = None,
    headers: dict[str, str] | None = None,
) -> MagicMock:
    """Return a ``MagicMock`` that behaves like a ``requests.Response``."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.ok = ok if ok is not None else (200 <= status_code < 300)
    resp.text = text or (str(json_data) if json_data else "")
    resp.content = content
    resp.headers = headers or {"Content-Type": "application/json"}
    if json_data is not None:
        resp.json.return_value = json_data
    return resp


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture()
def session() -> MagicMock:
    """A mock ``requests.Session`` with pre-configured headers dict."""
    s = MagicMock()
    s.headers = {}
    return s


@pytest.fixture()
def venafi_cfg_oauth(venafi_cfg: JsonDict) -> JsonDict:
    """Venafi configuration with OAuth auth method (from conftest)."""
    return venafi_cfg


@pytest.fixture()
def venafi_cfg_ldap(venafi_cfg: JsonDict) -> JsonDict:
    """Venafi configuration with LDAP auth method."""
    cfg = dict(venafi_cfg)
    cfg["auth_method"] = "ldap"
    return cfg


# ============================================================================
# Tests: _is_guid
# ============================================================================


class TestIsGuid:
    def test_valid_guid(self) -> None:
        assert _is_guid("a1b2c3d4-e5f6-7890-abcd-ef1234567890") is True

    def test_valid_guid_with_braces(self) -> None:
        assert _is_guid("{a1b2c3d4-e5f6-7890-abcd-ef1234567890}") is True

    def test_invalid_guid_wrong_segments(self) -> None:
        assert _is_guid("a1b2c3d4-e5f6-7890-abcd") is False

    def test_invalid_guid_wrong_lengths(self) -> None:
        assert _is_guid("a1b2c3d-e5f6-7890-abcd-ef1234567890") is False

    def test_empty_string(self) -> None:
        assert _is_guid("") is False

    def test_plain_string(self) -> None:
        assert _is_guid("\\VED\\Policy\\Certificates\\cert1") is False


# ============================================================================
# Tests: _split_pem_chain
# ============================================================================


class TestSplitPemChain:
    def test_single_cert(self) -> None:
        pem = b"-----BEGIN CERTIFICATE-----\nMIIB..leaf..\n-----END CERTIFICATE-----\n"
        leaf, chain = _split_pem_chain(pem)
        assert b"-----BEGIN CERTIFICATE-----" in leaf
        assert chain is None

    def test_two_certs(self) -> None:
        cert_a = b"-----BEGIN CERTIFICATE-----\nLEAFDATA\n-----END CERTIFICATE-----\n"
        cert_b = b"-----BEGIN CERTIFICATE-----\nCHAINDATA\n-----END CERTIFICATE-----\n"
        pem = cert_a + cert_b
        leaf, chain = _split_pem_chain(pem)
        assert b"LEAFDATA" in leaf
        assert chain is not None
        assert b"CHAINDATA" in chain

    def test_three_certs_chain_contains_two(self) -> None:
        certs = b""
        for name in (b"LEAF", b"INTER", b"ROOT"):
            certs += b"-----BEGIN CERTIFICATE-----\n" + name + b"\n-----END CERTIFICATE-----\n"
        leaf, chain = _split_pem_chain(certs)
        assert b"LEAF" in leaf
        assert chain is not None
        assert b"INTER" in chain
        assert b"ROOT" in chain

    def test_empty_data(self) -> None:
        leaf, chain = _split_pem_chain(b"")
        assert leaf == b""
        assert chain is None


# ============================================================================
# Tests: _raise_for_status
# ============================================================================


class TestRaiseForStatus:
    def test_ok_response_does_not_raise(self) -> None:
        resp = _mock_response(status_code=200)
        _raise_for_status(resp, "test context")

    def test_401_raises_auth_error(self) -> None:
        resp = _mock_response(status_code=401, ok=False)
        with pytest.raises(VenafiAuthenticationError, match="401"):
            _raise_for_status(resp, "test context")

    def test_403_raises_auth_error(self) -> None:
        resp = _mock_response(status_code=403, ok=False)
        with pytest.raises(VenafiAuthenticationError, match="403"):
            _raise_for_status(resp, "test context")

    def test_404_raises_not_found(self) -> None:
        resp = _mock_response(status_code=404, ok=False)
        with pytest.raises(VenafiCertificateNotFoundError, match="404"):
            _raise_for_status(resp, "test context")

    def test_500_raises_api_error(self) -> None:
        resp = _mock_response(status_code=500, ok=False, text="internal error")
        with pytest.raises(VenafiAPIError, match="unexpected response"):
            _raise_for_status(resp, "test context")


# ============================================================================
# Tests: _authenticate_oauth
# ============================================================================


class TestAuthenticateOAuth:
    def test_success(self, session: MagicMock, venafi_cfg_oauth: JsonDict) -> None:
        session.post.return_value = _mock_response(
            json_data={"access_token": "tok-abc-123"},
        )
        _authenticate_oauth(
            session,
            BASE_URL,
            "user",
            "pass",
            venafi_cfg_oauth,
            timeout=10,
        )
        assert session.headers["Authorization"] == "Bearer tok-abc-123"

    def test_401_raises(self, session: MagicMock, venafi_cfg_oauth: JsonDict) -> None:
        session.post.return_value = _mock_response(status_code=401, ok=False)
        with pytest.raises(VenafiAuthenticationError, match="401"):
            _authenticate_oauth(
                session,
                BASE_URL,
                "user",
                "bad",
                venafi_cfg_oauth,
                timeout=10,
            )

    def test_400_raises(self, session: MagicMock, venafi_cfg_oauth: JsonDict) -> None:
        session.post.return_value = _mock_response(
            status_code=400,
            ok=False,
            text="bad request body",
        )
        with pytest.raises(VenafiAuthenticationError, match="400"):
            _authenticate_oauth(
                session,
                BASE_URL,
                "user",
                "pass",
                venafi_cfg_oauth,
                timeout=10,
            )

    def test_unexpected_status_raises(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
    ) -> None:
        session.post.return_value = _mock_response(
            status_code=503,
            ok=False,
            text="service unavailable",
        )
        with pytest.raises(VenafiAuthenticationError, match="503"):
            _authenticate_oauth(
                session,
                BASE_URL,
                "user",
                "pass",
                venafi_cfg_oauth,
                timeout=10,
            )

    def test_missing_access_token_raises(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
    ) -> None:
        session.post.return_value = _mock_response(json_data={"no_token": "oops"})
        with pytest.raises(VenafiAuthenticationError, match="access_token"):
            _authenticate_oauth(
                session,
                BASE_URL,
                "user",
                "pass",
                venafi_cfg_oauth,
                timeout=10,
            )

    def test_uses_configured_client_id_and_scope(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
    ) -> None:
        session.post.return_value = _mock_response(
            json_data={"access_token": "tok"},
        )
        _authenticate_oauth(
            session,
            BASE_URL,
            "user",
            "pass",
            venafi_cfg_oauth,
            timeout=10,
        )
        call_kwargs = session.post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert payload["client_id"] == "certapi"
        assert payload["scope"] == "certificate:manage"


# ============================================================================
# Tests: _authenticate_ldap
# ============================================================================


class TestAuthenticateLDAP:
    def test_success(self, session: MagicMock) -> None:
        session.post.return_value = _mock_response(
            json_data={"APIKey": "apikey-xyz-789"},
        )
        _authenticate_ldap(session, BASE_URL, "user", "pass", timeout=10)
        assert session.headers["X-Venafi-Api-Key"] == "apikey-xyz-789"

    def test_401_raises(self, session: MagicMock) -> None:
        session.post.return_value = _mock_response(status_code=401, ok=False)
        with pytest.raises(VenafiLDAPAuthError, match="401"):
            _authenticate_ldap(session, BASE_URL, "user", "bad", timeout=10)

    def test_unexpected_status_raises(self, session: MagicMock) -> None:
        session.post.return_value = _mock_response(
            status_code=500,
            ok=False,
            text="internal error",
        )
        with pytest.raises(VenafiLDAPAuthError, match="500"):
            _authenticate_ldap(session, BASE_URL, "user", "pass", timeout=10)

    def test_missing_api_key_raises(self, session: MagicMock) -> None:
        session.post.return_value = _mock_response(json_data={"Nope": "nothing"})
        with pytest.raises(VenafiLDAPAuthError, match="APIKey"):
            _authenticate_ldap(session, BASE_URL, "user", "pass", timeout=10)


# ============================================================================
# Tests: authenticate (public)
# ============================================================================


class TestAuthenticate:
    @patch("certmesh.venafi_client.creds.resolve_venafi_credentials")
    @patch("certmesh.venafi_client._build_session")
    def test_oauth_path(
        self,
        mock_build: MagicMock,
        mock_creds: MagicMock,
        venafi_cfg_oauth: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        mock_session = MagicMock()
        mock_session.headers = {}
        mock_build.return_value = mock_session
        mock_creds.return_value = {"username": "alice", "password": "s3cret"}

        mock_session.post.return_value = _mock_response(
            json_data={"access_token": "tok"},
        )

        result = authenticate(venafi_cfg_oauth, vault_cfg, None)
        assert result is mock_session
        assert mock_session.headers["Authorization"] == "Bearer tok"

    @patch("certmesh.venafi_client.creds.resolve_venafi_credentials")
    @patch("certmesh.venafi_client._build_session")
    def test_ldap_path(
        self,
        mock_build: MagicMock,
        mock_creds: MagicMock,
        venafi_cfg_ldap: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        mock_session = MagicMock()
        mock_session.headers = {}
        mock_build.return_value = mock_session
        mock_creds.return_value = {"username": "bob", "password": "p@ss"}

        mock_session.post.return_value = _mock_response(
            json_data={"APIKey": "key-123"},
        )

        result = authenticate(venafi_cfg_ldap, vault_cfg, None)
        assert result is mock_session
        assert mock_session.headers["X-Venafi-Api-Key"] == "key-123"

    @patch("certmesh.venafi_client.creds.resolve_venafi_credentials")
    @patch("certmesh.venafi_client._build_session")
    def test_unsupported_auth_method_raises(
        self,
        mock_build: MagicMock,
        mock_creds: MagicMock,
        venafi_cfg_oauth: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        mock_build.return_value = MagicMock()
        mock_creds.return_value = {"username": "u", "password": "p"}
        venafi_cfg_oauth["auth_method"] = "kerberos"

        with pytest.raises(ConfigurationError, match="Unsupported"):
            authenticate(venafi_cfg_oauth, vault_cfg, None)

    @patch("certmesh.venafi_client.creds.resolve_venafi_credentials")
    @patch("certmesh.venafi_client._build_session")
    def test_missing_base_url_raises(
        self,
        mock_build: MagicMock,
        mock_creds: MagicMock,
        venafi_cfg_oauth: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        mock_build.return_value = MagicMock()
        mock_creds.return_value = {"username": "u", "password": "p"}
        venafi_cfg_oauth["base_url"] = ""

        with pytest.raises(ConfigurationError, match="base_url"):
            authenticate(venafi_cfg_oauth, vault_cfg, None)


# ============================================================================
# Tests: list_certificates
# ============================================================================

_CERT_ENTRY: JsonDict = {
    "Guid": "aaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "DN": "\\VED\\Policy\\Certificates\\test",
    "Name": "test.example.com",
    "CreatedOn": "2025-01-01T00:00:00Z",
    "SchemaClass": "X509 Server Certificate",
    "X509.NotAfter": "2026-01-01T00:00:00Z",
}


class TestListCertificates:
    def test_success(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
    ) -> None:
        session.get.return_value = _mock_response(
            json_data={"Certificates": [_CERT_ENTRY]},
        )
        results = list_certificates(session, venafi_cfg_oauth, limit=50, offset=0)
        assert len(results) == 1
        assert results[0].guid == "aaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        assert results[0].name == "test.example.com"

    def test_empty_list(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
    ) -> None:
        session.get.return_value = _mock_response(
            json_data={"Certificates": []},
        )
        results = list_certificates(session, venafi_cfg_oauth)
        assert results == []

    def test_api_error_raises(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
    ) -> None:
        session.get.return_value = _mock_response(
            status_code=500,
            ok=False,
            text="server error",
        )
        with pytest.raises(VenafiAPIError):
            list_certificates(session, venafi_cfg_oauth)

    def test_auth_expired_raises(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
    ) -> None:
        session.get.return_value = _mock_response(
            status_code=401,
            ok=False,
        )
        with pytest.raises(VenafiAuthenticationError):
            list_certificates(session, venafi_cfg_oauth)


# ============================================================================
# Tests: search_certificates
# ============================================================================


class TestSearchCertificates:
    def test_search_by_common_name(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
    ) -> None:
        session.post.return_value = _mock_response(
            json_data={"Certificates": [_CERT_ENTRY]},
        )
        results = search_certificates(
            session,
            venafi_cfg_oauth,
            common_name="test.example.com",
        )
        assert len(results) == 1
        call_kwargs = session.post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert payload["CN"] == "test.example.com"

    def test_search_by_thumbprint(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
    ) -> None:
        session.post.return_value = _mock_response(
            json_data={"Certificates": []},
        )
        results = search_certificates(
            session,
            venafi_cfg_oauth,
            thumbprint="AABB",
        )
        assert results == []
        call_kwargs = session.post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert payload["Thumbprint"] == "AABB"

    def test_search_multiple_filters(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
    ) -> None:
        session.post.return_value = _mock_response(
            json_data={"Certificates": [_CERT_ENTRY]},
        )
        search_certificates(
            session,
            venafi_cfg_oauth,
            common_name="test",
            key_size=2048,
            stage=500,
            issuer="CA",
        )
        call_kwargs = session.post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert payload["CN"] == "test"
        assert payload["KeySize"] == 2048
        assert payload["Stage"] == 500
        assert payload["Issuer"] == "CA"

    def test_search_omits_none_filters(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
    ) -> None:
        session.post.return_value = _mock_response(
            json_data={"Certificates": []},
        )
        search_certificates(session, venafi_cfg_oauth)
        call_kwargs = session.post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        # Only Limit and Offset should be present when all filters are None
        assert "CN" not in payload
        assert "Thumbprint" not in payload
        assert "Serial" not in payload

    def test_search_api_error(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
    ) -> None:
        session.post.return_value = _mock_response(
            status_code=500,
            ok=False,
            text="boom",
        )
        with pytest.raises(VenafiAPIError):
            search_certificates(session, venafi_cfg_oauth, common_name="x")


# ============================================================================
# Tests: describe_certificate
# ============================================================================


_DETAIL_RESPONSE: JsonDict = {
    "Guid": "11111111-2222-3333-4444-555555555555",
    "DN": "\\VED\\Policy\\Certificates\\web1",
    "Name": "web1.example.com",
    "CreatedOn": "2025-06-15T12:00:00Z",
    "Serial": "01:02:03:04",
    "Thumbprint": "AABB1122",
    "ValidFrom": "2025-06-15T00:00:00Z",
    "ValidTo": "2026-06-15T00:00:00Z",
    "Issuer": "CN=Corp CA",
    "Subject": "CN=web1.example.com",
    "KeyAlgorithm": "RSA",
    "KeySize": 2048,
    "SubjectAltNameDNS": ["web1.example.com", "www.example.com"],
    "Stage": 500,
    "Status": "OK",
    "InError": False,
}


class TestDescribeCertificate:
    def test_success(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
    ) -> None:
        session.get.return_value = _mock_response(json_data=_DETAIL_RESPONSE)

        detail = describe_certificate(
            session,
            venafi_cfg_oauth,
            certificate_guid="11111111-2222-3333-4444-555555555555",
        )
        assert detail.guid == "11111111-2222-3333-4444-555555555555"
        assert detail.serial_number == "01:02:03:04"
        assert detail.key_size == 2048
        assert detail.san_dns_names == ["web1.example.com", "www.example.com"]
        assert detail.stage == 500
        assert detail.in_error is False

    def test_san_as_comma_string(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
    ) -> None:
        data = dict(_DETAIL_RESPONSE)
        data["SubjectAltNameDNS"] = "a.example.com, b.example.com"
        session.get.return_value = _mock_response(json_data=data)

        detail = describe_certificate(
            session,
            venafi_cfg_oauth,
            certificate_guid="11111111-2222-3333-4444-555555555555",
        )
        assert detail.san_dns_names == ["a.example.com", "b.example.com"]

    def test_not_found(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
    ) -> None:
        session.get.return_value = _mock_response(status_code=404, ok=False)
        with pytest.raises(VenafiCertificateNotFoundError):
            describe_certificate(
                session,
                venafi_cfg_oauth,
                certificate_guid="nonexistent-guid",
            )

    def test_forbidden(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
    ) -> None:
        session.get.return_value = _mock_response(status_code=403, ok=False)
        with pytest.raises(VenafiAuthenticationError, match="403"):
            describe_certificate(
                session,
                venafi_cfg_oauth,
                certificate_guid="forbidden-guid",
            )


# ============================================================================
# Tests: revoke_certificate
# ============================================================================


class TestRevokeCertificate:
    def test_revoke_by_dn(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
    ) -> None:
        session.post.return_value = _mock_response(
            json_data={"Success": True},
        )
        result = revoke_certificate(
            session,
            venafi_cfg_oauth,
            certificate_dn="\\VED\\Policy\\cert1",
            reason=1,
            comments="compromised",
        )
        assert result["Success"] is True
        call_kwargs = session.post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert payload["CertificateDN"] == "\\VED\\Policy\\cert1"
        assert payload["Reason"] == 1
        assert payload["Comments"] == "compromised"

    def test_revoke_by_thumbprint(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
    ) -> None:
        session.post.return_value = _mock_response(
            json_data={"Success": True},
        )
        result = revoke_certificate(
            session,
            venafi_cfg_oauth,
            thumbprint="AABB1122",
        )
        assert result["Success"] is True

    def test_revoke_with_disable(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
    ) -> None:
        session.post.return_value = _mock_response(
            json_data={"Success": True},
        )
        revoke_certificate(
            session,
            venafi_cfg_oauth,
            certificate_dn="\\VED\\Policy\\cert1",
            disable=True,
        )
        call_kwargs = session.post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert payload["Disabled"] is True

    def test_missing_identifier_raises(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
    ) -> None:
        with pytest.raises(ConfigurationError, match="certificate_dn or thumbprint"):
            revoke_certificate(session, venafi_cfg_oauth)

    def test_revocation_rejected_by_api(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
    ) -> None:
        session.post.return_value = _mock_response(
            json_data={"Success": False, "Error": "Already revoked"},
        )
        with pytest.raises(VenafiAPIError, match="Already revoked"):
            revoke_certificate(
                session,
                venafi_cfg_oauth,
                certificate_dn="\\VED\\Policy\\cert1",
            )

    def test_revoke_api_error(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
    ) -> None:
        session.post.return_value = _mock_response(
            status_code=500,
            ok=False,
            text="server error",
        )
        with pytest.raises(VenafiAPIError):
            revoke_certificate(
                session,
                venafi_cfg_oauth,
                certificate_dn="\\VED\\Policy\\cert1",
            )


# ============================================================================
# Tests: request_certificate
# ============================================================================


class TestRequestCertificate:
    """Tests for the request_certificate function.

    Both server-side key (PKCS12) and client-side CSR download paths are
    exercised.
    """

    _subject = SubjectInfo(
        common_name="new.example.com",
        organisation="Acme",
        organisational_unit="IT",
        country="US",
        state="Maryland",
        locality="Baltimore",
        san_dns_names=["new.example.com"],
    )

    @patch("certmesh.venafi_client.cu.assemble_bundle")
    @patch("certmesh.venafi_client.cu.parse_pkcs12_bundle")
    @patch("certmesh.venafi_client._download_pkcs12")
    @patch("certmesh.venafi_client._poll_certificate_ready")
    @patch("certmesh.venafi_client._approve_workflow_tickets")
    @patch("certmesh.venafi_client._resolve_pkcs12_passphrase", return_value="pass")
    def test_server_side_key_success(
        self,
        mock_passphrase: MagicMock,
        mock_approve: MagicMock,
        mock_poll: MagicMock,
        mock_download: MagicMock,
        mock_parse: MagicMock,
        mock_assemble: MagicMock,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        session.post.return_value = _mock_response(
            json_data={
                "CertificateDN": "\\VED\\Policy\\Certs\\new",
                "Guid": "new-guid-1234",
            },
        )
        mock_download.return_value = b"pkcs12bytes"
        mock_parse.return_value = (b"cert_pem", b"key_pem", b"chain_pem")
        mock_bundle = MagicMock(spec=CertificateBundle)
        mock_assemble.return_value = mock_bundle

        result = request_certificate(
            session,
            venafi_cfg_oauth,
            vault_cfg,
            None,
            policy_dn="\\VED\\Policy\\Certs",
            subject=self._subject,
            use_csr=False,
        )

        assert result is mock_bundle
        mock_approve.assert_called_once()
        mock_poll.assert_called_once()
        mock_download.assert_called_once()
        mock_parse.assert_called_once()
        mock_assemble.assert_called_once()

    @patch("certmesh.venafi_client.cu.assemble_bundle")
    @patch("certmesh.venafi_client._split_pem_chain")
    @patch("certmesh.venafi_client._download_base64_cert")
    @patch("certmesh.venafi_client._poll_certificate_ready")
    @patch("certmesh.venafi_client._approve_workflow_tickets")
    @patch("certmesh.venafi_client.cu.csr_to_pem", return_value="CSR-PEM-DATA")
    @patch("certmesh.venafi_client.cu.build_csr")
    @patch("certmesh.venafi_client.cu.private_key_to_pem", return_value=b"KEY-PEM")
    @patch("certmesh.venafi_client.cu.generate_rsa_private_key")
    def test_client_side_csr_success(
        self,
        mock_keygen: MagicMock,
        mock_key_pem: MagicMock,
        mock_build_csr: MagicMock,
        mock_csr_pem: MagicMock,
        mock_approve: MagicMock,
        mock_poll: MagicMock,
        mock_dl_b64: MagicMock,
        mock_split: MagicMock,
        mock_assemble: MagicMock,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        session.post.return_value = _mock_response(
            json_data={
                "CertificateDN": "\\VED\\Policy\\Certs\\new",
                "Guid": "new-guid-csr",
            },
        )
        mock_dl_b64.return_value = "PEM-CERT-STRING"
        mock_split.return_value = (b"leaf_pem", b"chain_pem")
        mock_bundle = MagicMock(spec=CertificateBundle)
        mock_assemble.return_value = mock_bundle

        result = request_certificate(
            session,
            venafi_cfg_oauth,
            vault_cfg,
            None,
            policy_dn="\\VED\\Policy\\Certs",
            subject=self._subject,
            use_csr=True,
        )

        assert result is mock_bundle
        mock_keygen.assert_called_once()
        mock_build_csr.assert_called_once()
        mock_dl_b64.assert_called_once()
        mock_split.assert_called_once()
        # assemble_bundle should receive the leaf and client-generated key
        assemble_call = mock_assemble.call_args
        assert assemble_call.kwargs["private_key_pem"] == b"KEY-PEM"

    def test_request_api_error_on_submit(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        session.post.return_value = _mock_response(
            status_code=500,
            ok=False,
            text="boom",
        )
        with pytest.raises(VenafiAPIError):
            request_certificate(
                session,
                venafi_cfg_oauth,
                vault_cfg,
                None,
                policy_dn="\\VED\\Policy\\Certs",
                subject=self._subject,
            )

    def test_request_no_dn_in_response(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        session.post.return_value = _mock_response(
            json_data={"SomethingElse": "value"},
        )
        with pytest.raises(VenafiAPIError, match="CertificateDN"):
            request_certificate(
                session,
                venafi_cfg_oauth,
                vault_cfg,
                None,
                policy_dn="\\VED\\Policy\\Certs",
                subject=self._subject,
            )


# ============================================================================
# Tests: renew_and_download_certificate
# ============================================================================


class TestRenewAndDownloadCertificate:
    """Tests for the renew_and_download_certificate function.

    The inner function is wrapped in retry and circuit-breaker decorators so
    we mock the downstream helpers to avoid real HTTP.
    """

    _GUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

    @patch("certmesh.venafi_client.cu.assemble_bundle")
    @patch("certmesh.venafi_client.cu.parse_pkcs12_bundle")
    @patch("certmesh.venafi_client._download_pkcs12")
    @patch("certmesh.venafi_client._poll_certificate_ready")
    @patch("certmesh.venafi_client._approve_workflow_tickets")
    @patch("certmesh.venafi_client._resolve_pkcs12_passphrase", return_value="p@ss")
    def test_success_guid_based(
        self,
        mock_passphrase: MagicMock,
        mock_approve: MagicMock,
        mock_poll: MagicMock,
        mock_download: MagicMock,
        mock_parse: MagicMock,
        mock_assemble: MagicMock,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        # Renew POST returns success
        session.post.return_value = _mock_response(
            json_data={
                "Success": True,
                "CertificateDN": "\\VED\\Policy\\Certs\\web1",
            },
        )
        mock_download.return_value = b"p12data"
        mock_parse.return_value = (b"cert", b"key", b"chain")
        mock_bundle = MagicMock(spec=CertificateBundle)
        mock_bundle.common_name = "web1.example.com"
        mock_bundle.serial_number = "AABB"
        mock_assemble.return_value = mock_bundle

        result = renew_and_download_certificate(
            session,
            venafi_cfg_oauth,
            vault_cfg,
            None,
            certificate_guid=self._GUID,
        )

        assert result is mock_bundle
        mock_approve.assert_called_once()
        mock_poll.assert_called_once()
        mock_download.assert_called_once()

    @patch("certmesh.venafi_client.cu.assemble_bundle")
    @patch("certmesh.venafi_client.cu.parse_pkcs12_bundle")
    @patch("certmesh.venafi_client._download_pkcs12")
    @patch("certmesh.venafi_client._poll_certificate_ready")
    @patch("certmesh.venafi_client._approve_workflow_tickets")
    @patch("certmesh.venafi_client._resolve_dn_from_guid")
    @patch("certmesh.venafi_client._resolve_pkcs12_passphrase", return_value="p@ss")
    def test_resolves_dn_when_not_in_response(
        self,
        mock_passphrase: MagicMock,
        mock_resolve_dn: MagicMock,
        mock_approve: MagicMock,
        mock_poll: MagicMock,
        mock_download: MagicMock,
        mock_parse: MagicMock,
        mock_assemble: MagicMock,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        session.post.return_value = _mock_response(
            json_data={"Success": True},  # no CertificateDN
        )
        mock_resolve_dn.return_value = "\\VED\\Policy\\Certs\\web1"
        mock_download.return_value = b"p12"
        mock_parse.return_value = (b"c", b"k", b"ch")
        mock_bundle = MagicMock(spec=CertificateBundle)
        mock_bundle.common_name = "web1"
        mock_bundle.serial_number = "00"
        mock_assemble.return_value = mock_bundle

        renew_and_download_certificate(
            session,
            venafi_cfg_oauth,
            vault_cfg,
            None,
            certificate_guid=self._GUID,
        )

        mock_resolve_dn.assert_called_once()

    def test_renewal_rejected(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        session.post.return_value = _mock_response(
            json_data={"Success": False, "Error": "Certificate locked"},
        )
        with pytest.raises(VenafiAPIError, match="Certificate locked"):
            renew_and_download_certificate(
                session,
                venafi_cfg_oauth,
                vault_cfg,
                None,
                certificate_guid=self._GUID,
            )

    def test_renewal_api_error(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        session.post.return_value = _mock_response(
            status_code=500,
            ok=False,
            text="internal error",
        )
        with pytest.raises(VenafiAPIError):
            renew_and_download_certificate(
                session,
                venafi_cfg_oauth,
                vault_cfg,
                None,
                certificate_guid=self._GUID,
            )

    @patch("certmesh.venafi_client._poll_certificate_ready")
    @patch("certmesh.venafi_client._approve_workflow_tickets")
    def test_workflow_approval_failure_is_non_fatal(
        self,
        mock_approve: MagicMock,
        mock_poll: MagicMock,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
        vault_cfg: JsonDict,
    ) -> None:
        """Workflow approval failure should be logged but not re-raised."""
        session.post.return_value = _mock_response(
            json_data={
                "Success": True,
                "CertificateDN": "\\VED\\Policy\\cert",
            },
        )
        mock_approve.side_effect = VenafiWorkflowApprovalError("ticket fail")
        mock_poll.side_effect = VenafiPollingTimeoutError("timeout")

        # The function catches VenafiWorkflowApprovalError, but the poll
        # timeout will still propagate.
        with pytest.raises(VenafiPollingTimeoutError):
            renew_and_download_certificate(
                session,
                venafi_cfg_oauth,
                vault_cfg,
                None,
                certificate_guid=self._GUID,
            )

        # Verify that approve was called and its error was swallowed
        mock_approve.assert_called_once()


# ============================================================================
# Tests: workflow approval edge cases
# ============================================================================


class TestApproveWorkflowTickets:
    """Test _approve_workflow_tickets indirectly via mock HTTP calls."""

    def test_no_tickets(self, session: MagicMock, venafi_cfg_oauth: JsonDict) -> None:
        from certmesh.venafi_client import _approve_workflow_tickets

        session.post.return_value = _mock_response(
            json_data={"Tickets": []},
        )
        # Should return without raising
        _approve_workflow_tickets(
            session,
            BASE_URL,
            "\\VED\\Policy\\cert",
            venafi_cfg_oauth,
            timeout=10,
        )
        # Only the enumerate call, no approve call
        assert session.post.call_count == 1

    def test_approve_one_ticket(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
    ) -> None:
        from certmesh.venafi_client import _approve_workflow_tickets

        enumerate_resp = _mock_response(
            json_data={"Tickets": [{"Id": 42}]},
        )
        approve_resp = _mock_response(json_data={})

        session.post.side_effect = [enumerate_resp, approve_resp]

        _approve_workflow_tickets(
            session,
            BASE_URL,
            "\\VED\\Policy\\cert",
            venafi_cfg_oauth,
            timeout=10,
        )
        assert session.post.call_count == 2

    def test_approve_failure_raises(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
    ) -> None:
        from certmesh.venafi_client import _approve_workflow_tickets

        enumerate_resp = _mock_response(
            json_data={"Tickets": [{"Id": 7}]},
        )
        approve_resp = _mock_response(
            status_code=400,
            ok=False,
            text="denied",
        )

        session.post.side_effect = [enumerate_resp, approve_resp]

        with pytest.raises(VenafiWorkflowApprovalError, match="ticket 7"):
            _approve_workflow_tickets(
                session,
                BASE_URL,
                "\\VED\\Policy\\cert",
                venafi_cfg_oauth,
                timeout=10,
            )

    def test_enumerate_error_raises(
        self,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
    ) -> None:
        from certmesh.venafi_client import _approve_workflow_tickets

        session.post.return_value = _mock_response(
            status_code=500,
            ok=False,
            text="boom",
        )
        with pytest.raises(VenafiAPIError):
            _approve_workflow_tickets(
                session,
                BASE_URL,
                "\\VED\\Policy\\cert",
                venafi_cfg_oauth,
                timeout=10,
            )


# ============================================================================
# Tests: polling edge cases
# ============================================================================


class TestPollCertificateReady:
    @patch("certmesh.venafi_client.time.sleep")
    def test_ready_immediately(
        self,
        mock_sleep: MagicMock,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
    ) -> None:
        from certmesh.venafi_client import _poll_certificate_ready

        session.get.return_value = _mock_response(
            json_data={"Stage": 500, "Status": "OK"},
        )
        _poll_certificate_ready(
            session,
            BASE_URL,
            "\\VED\\Policy\\cert",
            venafi_cfg_oauth,
            timeout=10,
        )
        mock_sleep.assert_not_called()

    @patch("certmesh.venafi_client.time.sleep")
    def test_becomes_ready_after_one_poll(
        self,
        mock_sleep: MagicMock,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
    ) -> None:
        from certmesh.venafi_client import _poll_certificate_ready

        not_ready = _mock_response(json_data={"Stage": 200, "Status": "Pending"})
        ready = _mock_response(json_data={"Stage": 500, "Status": "OK"})
        session.get.side_effect = [not_ready, ready]

        _poll_certificate_ready(
            session,
            BASE_URL,
            "\\VED\\Policy\\cert",
            venafi_cfg_oauth,
            timeout=10,
        )

    @patch("certmesh.venafi_client.time.sleep")
    def test_timeout_raises(
        self,
        mock_sleep: MagicMock,
        session: MagicMock,
        venafi_cfg_oauth: JsonDict,
    ) -> None:
        from certmesh.venafi_client import _poll_certificate_ready

        # Always return not-ready
        session.get.return_value = _mock_response(
            json_data={"Stage": 100, "Status": "Pending"},
        )

        # Use very short max_wait so we exceed it quickly
        cfg = dict(venafi_cfg_oauth)
        cfg["polling"] = {"interval_seconds": 1, "max_wait_seconds": 2}

        with pytest.raises(VenafiPollingTimeoutError, match="did not reach ready"):
            _poll_certificate_ready(
                session,
                BASE_URL,
                "\\VED\\Policy\\cert",
                cfg,
                timeout=10,
            )


# ============================================================================
# Tests: download helpers
# ============================================================================


class TestDownloadPkcs12:
    def test_json_response_with_cert_data(self, session: MagicMock) -> None:
        from certmesh.venafi_client import _download_pkcs12

        cert_b64 = base64.b64encode(b"PKCS12BINARYDATA").decode()
        session.post.return_value = _mock_response(
            json_data={"CertificateData": cert_b64},
            headers={"Content-Type": "application/json"},
        )
        result = _download_pkcs12(
            session,
            BASE_URL,
            "\\VED\\cert",
            "pass",
            timeout=10,
        )
        assert result == b"PKCS12BINARYDATA"

    def test_binary_response(self, session: MagicMock) -> None:
        from certmesh.venafi_client import _download_pkcs12

        session.post.return_value = _mock_response(
            content=b"BINARYP12",
            headers={"Content-Type": "application/x-pkcs12"},
        )
        result = _download_pkcs12(
            session,
            BASE_URL,
            "\\VED\\cert",
            "pass",
            timeout=10,
        )
        assert result == b"BINARYP12"

    def test_json_response_missing_cert_data(self, session: MagicMock) -> None:
        from certmesh.venafi_client import _download_pkcs12

        session.post.return_value = _mock_response(
            json_data={"Nope": "nothing"},
            headers={"Content-Type": "application/json"},
        )
        with pytest.raises(VenafiAPIError, match="CertificateData"):
            _download_pkcs12(
                session,
                BASE_URL,
                "\\VED\\cert",
                "pass",
                timeout=10,
            )

    def test_private_key_denied(self, session: MagicMock) -> None:
        from certmesh.venafi_client import _download_pkcs12

        session.post.return_value = _mock_response(
            status_code=400,
            ok=False,
            text="Private key export denied by policy",
        )
        with pytest.raises(VenafiPrivateKeyExportError, match="denied"):
            _download_pkcs12(
                session,
                BASE_URL,
                "\\VED\\cert",
                "pass",
                timeout=10,
            )

    def test_generic_400_error(self, session: MagicMock) -> None:
        from certmesh.venafi_client import _download_pkcs12

        session.post.return_value = _mock_response(
            status_code=400,
            ok=False,
            text="something else entirely",
        )
        with pytest.raises(VenafiAPIError):
            _download_pkcs12(
                session,
                BASE_URL,
                "\\VED\\cert",
                "pass",
                timeout=10,
            )


class TestDownloadBase64Cert:
    def test_json_response_success(self, session: MagicMock) -> None:
        from certmesh.venafi_client import _download_base64_cert

        session.post.return_value = _mock_response(
            json_data={"CertificateData": "BASE64PEMSTRING"},
            headers={"Content-Type": "application/json"},
        )
        result = _download_base64_cert(
            session,
            BASE_URL,
            "\\VED\\cert",
            timeout=10,
        )
        assert result == "BASE64PEMSTRING"

    def test_text_response(self, session: MagicMock) -> None:
        from certmesh.venafi_client import _download_base64_cert

        session.post.return_value = _mock_response(
            text="-----BEGIN CERTIFICATE-----\nDATA\n-----END CERTIFICATE-----",
            headers={"Content-Type": "text/plain"},
        )
        result = _download_base64_cert(
            session,
            BASE_URL,
            "\\VED\\cert",
            timeout=10,
        )
        assert "BEGIN CERTIFICATE" in result

    def test_missing_cert_data_in_json(self, session: MagicMock) -> None:
        from certmesh.venafi_client import _download_base64_cert

        session.post.return_value = _mock_response(
            json_data={"Empty": True},
            headers={"Content-Type": "application/json"},
        )
        with pytest.raises(VenafiAPIError, match="CertificateData"):
            _download_base64_cert(
                session,
                BASE_URL,
                "\\VED\\cert",
                timeout=10,
            )


# ============================================================================
# Tests: _resolve_pkcs12_passphrase
# ============================================================================


class TestResolvePkcs12Passphrase:
    @patch.dict("os.environ", {"TEST_PKCS12_PASSPHRASE": "mypass"})
    def test_resolves_from_env(self, venafi_cfg_oauth: JsonDict) -> None:
        from certmesh.venafi_client import _resolve_pkcs12_passphrase

        result = _resolve_pkcs12_passphrase(venafi_cfg_oauth)
        assert result == "mypass"

    @patch.dict("os.environ", {}, clear=True)
    def test_missing_passphrase_raises(self, venafi_cfg_oauth: JsonDict) -> None:
        from certmesh.venafi_client import _resolve_pkcs12_passphrase

        with pytest.raises(ConfigurationError, match="passphrase"):
            _resolve_pkcs12_passphrase(venafi_cfg_oauth)


# ============================================================================
# Tests: _resolve_dn_from_guid
# ============================================================================


class TestResolveDnFromGuid:
    def test_success(self, session: MagicMock) -> None:
        from certmesh.venafi_client import _resolve_dn_from_guid

        session.get.return_value = _mock_response(
            json_data={"DN": "\\VED\\Policy\\cert1"},
        )
        dn = _resolve_dn_from_guid(session, BASE_URL, "some-guid", timeout=10)
        assert dn == "\\VED\\Policy\\cert1"

    def test_empty_dn_raises(self, session: MagicMock) -> None:
        from certmesh.venafi_client import _resolve_dn_from_guid

        session.get.return_value = _mock_response(json_data={"DN": ""})
        with pytest.raises(VenafiCertificateNotFoundError, match="resolve DN"):
            _resolve_dn_from_guid(session, BASE_URL, "bad-guid", timeout=10)

    def test_404_raises(self, session: MagicMock) -> None:
        from certmesh.venafi_client import _resolve_dn_from_guid

        session.get.return_value = _mock_response(status_code=404, ok=False)
        with pytest.raises(VenafiCertificateNotFoundError):
            _resolve_dn_from_guid(session, BASE_URL, "no-guid", timeout=10)
