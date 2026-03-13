"""Tests for certmesh.acm_client -- ACM and ACM-PCA operations."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import botocore.exceptions
import pytest

from certmesh.acm_client import (
    ACMCertificateDetail,
    ACMCertificateSummary,
    ACMValidationRecord,
    arn_short_id,
    delete_certificate,
    describe_certificate,
    export_and_persist,
    export_certificate,
    get_private_certificate,
    get_validation_records,
    issue_private_certificate,
    list_certificates,
    list_private_certificates,
    renew_certificate,
    request_certificate,
    revoke_private_certificate,
    wait_for_issuance,
)
from certmesh.exceptions import (
    ACMError,
    ACMExportError,
    ACMPrivateCAError,
    ACMRequestError,
    ACMValidationError,
)

JsonDict = dict[str, Any]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SAMPLE_CERT_ARN = "arn:aws:acm:us-east-1:123456789012:certificate/abcd-1234"
_SAMPLE_CA_ARN = "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/test-ca-id"
_SAMPLE_DOMAIN = "example.com"


def _make_client_error(
    code: str = "ValidationException",
    message: str = "Something went wrong",
    operation: str = "TestOperation",
) -> botocore.exceptions.ClientError:
    """Build a botocore ClientError for test assertions."""
    return botocore.exceptions.ClientError(
        {"Error": {"Code": code, "Message": message}},
        operation,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def acm_cfg_with_ca(acm_cfg: JsonDict) -> JsonDict:
    """Return acm_cfg with a non-empty private CA ARN."""
    cfg = dict(acm_cfg)
    cfg["private_ca"] = {
        **acm_cfg.get("private_ca", {}),
        "ca_arn": _SAMPLE_CA_ARN,
    }
    return cfg


@pytest.fixture()
def mock_acm_client() -> MagicMock:
    """A MagicMock standing in for the boto3 ACM client."""
    return MagicMock()


@pytest.fixture()
def mock_pca_client() -> MagicMock:
    """A MagicMock standing in for the boto3 ACM-PCA client."""
    return MagicMock()


# ============================================================================
# arn_short_id
# ============================================================================


class TestArnShortId:
    def test_extracts_uuid_from_arn(self) -> None:
        result = arn_short_id("arn:aws:acm:us-east-1:123456789012:certificate/abcd-1234")
        assert result == "abcd-1234"

    def test_extracts_uuid_from_pca_arn(self) -> None:
        result = arn_short_id(
            "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/ca-uuid-5678"
        )
        assert result == "ca-uuid-5678"

    def test_returns_whole_string_when_no_slash(self) -> None:
        assert arn_short_id("no-slash-here") == "no-slash-here"

    def test_empty_string(self) -> None:
        assert arn_short_id("") == ""

    def test_trailing_slash(self) -> None:
        # "something/" splits into ["something", ""] => returns ""
        assert arn_short_id("something/") == ""


# ============================================================================
# request_certificate
# ============================================================================


class TestRequestCertificate:
    @patch("certmesh.acm_client._build_acm_client")
    def test_basic_request(self, mock_build: MagicMock, acm_cfg: JsonDict) -> None:
        mock_client = MagicMock()
        mock_build.return_value = mock_client
        mock_client.request_certificate.return_value = {
            "CertificateArn": _SAMPLE_CERT_ARN,
        }

        arn = request_certificate(acm_cfg, _SAMPLE_DOMAIN)

        assert arn == _SAMPLE_CERT_ARN
        mock_client.request_certificate.assert_called_once()
        call_kwargs = mock_client.request_certificate.call_args[1]
        assert call_kwargs["DomainName"] == _SAMPLE_DOMAIN
        assert call_kwargs["ValidationMethod"] == "DNS"
        assert call_kwargs["KeyAlgorithm"] == "RSA_2048"

    @patch("certmesh.acm_client._build_acm_client")
    def test_with_sans_and_tags(self, mock_build: MagicMock, acm_cfg: JsonDict) -> None:
        mock_client = MagicMock()
        mock_build.return_value = mock_client
        mock_client.request_certificate.return_value = {
            "CertificateArn": _SAMPLE_CERT_ARN,
        }

        sans = ["www.example.com", "api.example.com"]
        tags = [{"Key": "env", "Value": "test"}]

        arn = request_certificate(
            acm_cfg,
            _SAMPLE_DOMAIN,
            subject_alternative_names=sans,
            tags=tags,
        )

        assert arn == _SAMPLE_CERT_ARN
        call_kwargs = mock_client.request_certificate.call_args[1]
        assert call_kwargs["SubjectAlternativeNames"] == sans
        assert call_kwargs["Tags"] == tags

    @patch("certmesh.acm_client._build_acm_client")
    def test_with_idempotency_token(self, mock_build: MagicMock, acm_cfg: JsonDict) -> None:
        mock_client = MagicMock()
        mock_build.return_value = mock_client
        mock_client.request_certificate.return_value = {
            "CertificateArn": _SAMPLE_CERT_ARN,
        }

        request_certificate(acm_cfg, _SAMPLE_DOMAIN, idempotency_token="my-token")
        call_kwargs = mock_client.request_certificate.call_args[1]
        assert call_kwargs["IdempotencyToken"] == "my-token"

    @patch("certmesh.acm_client._build_acm_client")
    def test_override_validation_method(self, mock_build: MagicMock, acm_cfg: JsonDict) -> None:
        mock_client = MagicMock()
        mock_build.return_value = mock_client
        mock_client.request_certificate.return_value = {
            "CertificateArn": _SAMPLE_CERT_ARN,
        }

        request_certificate(acm_cfg, _SAMPLE_DOMAIN, validation_method="EMAIL")
        call_kwargs = mock_client.request_certificate.call_args[1]
        assert call_kwargs["ValidationMethod"] == "EMAIL"

    @patch("certmesh.acm_client._build_acm_client")
    def test_override_key_algorithm(self, mock_build: MagicMock, acm_cfg: JsonDict) -> None:
        mock_client = MagicMock()
        mock_build.return_value = mock_client
        mock_client.request_certificate.return_value = {
            "CertificateArn": _SAMPLE_CERT_ARN,
        }

        request_certificate(acm_cfg, _SAMPLE_DOMAIN, key_algorithm="EC_prime256v1")
        call_kwargs = mock_client.request_certificate.call_args[1]
        assert call_kwargs["KeyAlgorithm"] == "EC_prime256v1"

    def test_invalid_validation_method_raises(self, acm_cfg: JsonDict) -> None:
        with pytest.raises(ACMRequestError, match="Invalid validation method"):
            request_certificate(acm_cfg, _SAMPLE_DOMAIN, validation_method="INVALID")

    def test_invalid_key_algorithm_raises(self, acm_cfg: JsonDict) -> None:
        with pytest.raises(ACMRequestError, match="Invalid key algorithm"):
            request_certificate(acm_cfg, _SAMPLE_DOMAIN, key_algorithm="INVALID_ALGO")

    @patch("certmesh.acm_client._build_acm_client")
    def test_client_error_raises_acm_request_error(
        self, mock_build: MagicMock, acm_cfg: JsonDict
    ) -> None:
        mock_client = MagicMock()
        mock_build.return_value = mock_client
        mock_client.request_certificate.side_effect = _make_client_error(
            code="LimitExceededException", message="Too many certificates"
        )

        with pytest.raises(ACMRequestError, match="LimitExceededException"):
            request_certificate(acm_cfg, _SAMPLE_DOMAIN)


# ============================================================================
# describe_certificate
# ============================================================================


class TestDescribeCertificate:
    @patch("certmesh.acm_client._build_acm_client")
    def test_returns_detail_dataclass(self, mock_build: MagicMock, acm_cfg: JsonDict) -> None:
        mock_client = MagicMock()
        mock_build.return_value = mock_client

        now = datetime.now(timezone.utc)
        mock_client.describe_certificate.return_value = {
            "Certificate": {
                "CertificateArn": _SAMPLE_CERT_ARN,
                "DomainName": _SAMPLE_DOMAIN,
                "SubjectAlternativeNames": [_SAMPLE_DOMAIN],
                "Status": "ISSUED",
                "Type": "AMAZON_ISSUED",
                "KeyAlgorithm": "RSA_2048",
                "Serial": "aa:bb:cc",
                "Issuer": "Amazon",
                "NotBefore": now,
                "NotAfter": now,
                "CreatedAt": now,
                "RenewalEligibility": "ELIGIBLE",
                "InUseBy": ["arn:aws:elb:us-east-1:123456789012:loadbalancer/my-lb"],
                "FailureReason": "",
            },
        }

        detail = describe_certificate(acm_cfg, _SAMPLE_CERT_ARN)

        assert isinstance(detail, ACMCertificateDetail)
        assert detail.certificate_arn == _SAMPLE_CERT_ARN
        assert detail.domain_name == _SAMPLE_DOMAIN
        assert detail.status == "ISSUED"
        assert detail.type == "AMAZON_ISSUED"
        assert detail.serial == "aa:bb:cc"
        assert detail.not_before == now
        assert detail.renewal_eligibility == "ELIGIBLE"
        assert len(detail.in_use_by) == 1

    @patch("certmesh.acm_client._build_acm_client")
    def test_handles_minimal_response(self, mock_build: MagicMock, acm_cfg: JsonDict) -> None:
        mock_client = MagicMock()
        mock_build.return_value = mock_client
        mock_client.describe_certificate.return_value = {"Certificate": {}}

        detail = describe_certificate(acm_cfg, _SAMPLE_CERT_ARN)

        assert detail.certificate_arn == _SAMPLE_CERT_ARN
        assert detail.domain_name == ""
        assert detail.status == ""

    @patch("certmesh.acm_client._build_acm_client")
    def test_client_error_raises_acm_error(self, mock_build: MagicMock, acm_cfg: JsonDict) -> None:
        mock_client = MagicMock()
        mock_build.return_value = mock_client
        mock_client.describe_certificate.side_effect = _make_client_error(
            code="ResourceNotFoundException",
            message="Certificate not found",
        )

        with pytest.raises(ACMError, match="ResourceNotFoundException"):
            describe_certificate(acm_cfg, _SAMPLE_CERT_ARN)


# ============================================================================
# list_certificates
# ============================================================================


class TestListCertificates:
    @patch("certmesh.acm_client._build_acm_client")
    def test_returns_summaries(self, mock_build: MagicMock, acm_cfg: JsonDict) -> None:
        mock_client = MagicMock()
        mock_build.return_value = mock_client

        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "CertificateSummaryList": [
                    {
                        "CertificateArn": _SAMPLE_CERT_ARN,
                        "DomainName": _SAMPLE_DOMAIN,
                        "Status": "ISSUED",
                        "KeyAlgorithm": "RSA_2048",
                        "Type": "AMAZON_ISSUED",
                        "InUse": True,
                    },
                ],
            },
        ]

        results = list_certificates(acm_cfg)

        assert len(results) == 1
        assert isinstance(results[0], ACMCertificateSummary)
        assert results[0].certificate_arn == _SAMPLE_CERT_ARN
        assert results[0].in_use is True

    @patch("certmesh.acm_client._build_acm_client")
    def test_with_status_filter(self, mock_build: MagicMock, acm_cfg: JsonDict) -> None:
        mock_client = MagicMock()
        mock_build.return_value = mock_client

        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {"CertificateSummaryList": []},
        ]

        list_certificates(acm_cfg, statuses=["ISSUED", "PENDING_VALIDATION"])

        call_kwargs = mock_paginator.paginate.call_args[1]
        assert call_kwargs["CertificateStatuses"] == [
            "ISSUED",
            "PENDING_VALIDATION",
        ]

    @patch("certmesh.acm_client._build_acm_client")
    def test_max_items_stops_early(self, mock_build: MagicMock, acm_cfg: JsonDict) -> None:
        mock_client = MagicMock()
        mock_build.return_value = mock_client

        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "CertificateSummaryList": [
                    {
                        "CertificateArn": f"arn:cert/{i}",
                        "DomainName": f"d{i}.example.com",
                        "Status": "ISSUED",
                        "KeyAlgorithm": "RSA_2048",
                        "Type": "AMAZON_ISSUED",
                        "InUse": False,
                    }
                    for i in range(5)
                ],
            },
        ]

        results = list_certificates(acm_cfg, max_items=2)

        assert len(results) == 2

    @patch("certmesh.acm_client._build_acm_client")
    def test_multiple_pages(self, mock_build: MagicMock, acm_cfg: JsonDict) -> None:
        mock_client = MagicMock()
        mock_build.return_value = mock_client

        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "CertificateSummaryList": [
                    {
                        "CertificateArn": "arn:cert/1",
                        "DomainName": "a.example.com",
                        "Status": "ISSUED",
                        "KeyAlgorithm": "RSA_2048",
                        "Type": "AMAZON_ISSUED",
                        "InUse": False,
                    },
                ],
            },
            {
                "CertificateSummaryList": [
                    {
                        "CertificateArn": "arn:cert/2",
                        "DomainName": "b.example.com",
                        "Status": "PENDING_VALIDATION",
                        "KeyAlgorithm": "EC_prime256v1",
                        "Type": "AMAZON_ISSUED",
                        "InUse": False,
                    },
                ],
            },
        ]

        results = list_certificates(acm_cfg)

        assert len(results) == 2
        assert results[0].domain_name == "a.example.com"
        assert results[1].domain_name == "b.example.com"

    @patch("certmesh.acm_client._build_acm_client")
    def test_empty_result(self, mock_build: MagicMock, acm_cfg: JsonDict) -> None:
        mock_client = MagicMock()
        mock_build.return_value = mock_client

        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {"CertificateSummaryList": []},
        ]

        results = list_certificates(acm_cfg)
        assert results == []

    @patch("certmesh.acm_client._build_acm_client")
    def test_client_error_raises_acm_error(self, mock_build: MagicMock, acm_cfg: JsonDict) -> None:
        mock_client = MagicMock()
        mock_build.return_value = mock_client

        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.side_effect = _make_client_error(
            code="AccessDeniedException", message="Denied"
        )

        with pytest.raises(ACMError, match="AccessDeniedException"):
            list_certificates(acm_cfg)


# ============================================================================
# export_certificate
# ============================================================================


class TestExportCertificate:
    @patch("certmesh.acm_client.cu.assemble_bundle")
    @patch("certmesh.acm_client._build_acm_client")
    def test_successful_export(
        self,
        mock_build: MagicMock,
        mock_assemble: MagicMock,
        acm_cfg: JsonDict,
    ) -> None:
        mock_client = MagicMock()
        mock_build.return_value = mock_client
        mock_client.export_certificate.return_value = {
            "Certificate": "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----",
            "PrivateKey": "-----BEGIN RSA PRIVATE KEY-----\nMOCK\n-----END RSA PRIVATE KEY-----",
            "CertificateChain": "-----BEGIN CERTIFICATE-----\nCHAIN\n-----END CERTIFICATE-----",
        }
        mock_bundle = MagicMock()
        mock_bundle.common_name = "example.com"
        mock_bundle.serial_number = "AABB"
        mock_assemble.return_value = mock_bundle

        result = export_certificate(acm_cfg, _SAMPLE_CERT_ARN, b"mypasswd")

        assert result is mock_bundle
        mock_client.export_certificate.assert_called_once_with(
            CertificateArn=_SAMPLE_CERT_ARN, Passphrase=b"mypasswd"
        )
        mock_assemble.assert_called_once()
        assemble_kwargs = mock_assemble.call_args[1]
        assert assemble_kwargs["source_id"] == "abcd-1234"

    @patch("certmesh.acm_client._build_acm_client")
    def test_export_no_chain(
        self,
        mock_build: MagicMock,
        acm_cfg: JsonDict,
        self_signed_cert_pem: bytes,
        private_key_pem: bytes,
    ) -> None:
        mock_client = MagicMock()
        mock_build.return_value = mock_client
        mock_client.export_certificate.return_value = {
            "Certificate": self_signed_cert_pem.decode("utf-8"),
            "PrivateKey": private_key_pem.decode("utf-8"),
            "CertificateChain": "",
        }

        result = export_certificate(acm_cfg, _SAMPLE_CERT_ARN, b"mypasswd")

        assert result.common_name == "test.example.com"

    def test_short_passphrase_raises(self, acm_cfg: JsonDict) -> None:
        with pytest.raises(ACMExportError, match="at least 4 bytes"):
            export_certificate(acm_cfg, _SAMPLE_CERT_ARN, b"ab")

    def test_empty_passphrase_raises(self, acm_cfg: JsonDict) -> None:
        with pytest.raises(ACMExportError, match="at least 4 bytes"):
            export_certificate(acm_cfg, _SAMPLE_CERT_ARN, b"")

    @patch("certmesh.acm_client._build_acm_client")
    def test_client_error_raises_export_error(
        self, mock_build: MagicMock, acm_cfg: JsonDict
    ) -> None:
        mock_client = MagicMock()
        mock_build.return_value = mock_client
        mock_client.export_certificate.side_effect = _make_client_error(
            code="ResourceNotFoundException",
            message="Certificate not found",
        )

        with pytest.raises(ACMExportError, match="ResourceNotFoundException"):
            export_certificate(acm_cfg, _SAMPLE_CERT_ARN, b"passwd")

    @patch("certmesh.acm_client._build_acm_client")
    def test_empty_certificate_body_raises(self, mock_build: MagicMock, acm_cfg: JsonDict) -> None:
        mock_client = MagicMock()
        mock_build.return_value = mock_client
        mock_client.export_certificate.return_value = {
            "Certificate": "",
            "PrivateKey": "KEY",
            "CertificateChain": "CHAIN",
        }

        with pytest.raises(ACMExportError, match="empty certificate"):
            export_certificate(acm_cfg, _SAMPLE_CERT_ARN, b"passwd")

    @patch("certmesh.acm_client._build_acm_client")
    def test_empty_private_key_raises(self, mock_build: MagicMock, acm_cfg: JsonDict) -> None:
        mock_client = MagicMock()
        mock_build.return_value = mock_client
        mock_client.export_certificate.return_value = {
            "Certificate": "CERT",
            "PrivateKey": "",
            "CertificateChain": "CHAIN",
        }

        with pytest.raises(ACMExportError, match="empty private key"):
            export_certificate(acm_cfg, _SAMPLE_CERT_ARN, b"passwd")


# ============================================================================
# delete_certificate
# ============================================================================


class TestDeleteCertificate:
    @patch("certmesh.acm_client._build_acm_client")
    def test_successful_delete(self, mock_build: MagicMock, acm_cfg: JsonDict) -> None:
        mock_client = MagicMock()
        mock_build.return_value = mock_client

        delete_certificate(acm_cfg, _SAMPLE_CERT_ARN)

        mock_client.delete_certificate.assert_called_once_with(CertificateArn=_SAMPLE_CERT_ARN)

    @patch("certmesh.acm_client._build_acm_client")
    def test_client_error_raises_acm_error(self, mock_build: MagicMock, acm_cfg: JsonDict) -> None:
        mock_client = MagicMock()
        mock_build.return_value = mock_client
        mock_client.delete_certificate.side_effect = _make_client_error(
            code="ResourceInUseException",
            message="Certificate is in use",
        )

        with pytest.raises(ACMError, match="ResourceInUseException"):
            delete_certificate(acm_cfg, _SAMPLE_CERT_ARN)


# ============================================================================
# renew_certificate
# ============================================================================


class TestRenewCertificate:
    @patch("certmesh.acm_client._build_acm_client")
    def test_successful_renew(self, mock_build: MagicMock, acm_cfg: JsonDict) -> None:
        mock_client = MagicMock()
        mock_build.return_value = mock_client

        renew_certificate(acm_cfg, _SAMPLE_CERT_ARN)

        mock_client.renew_certificate.assert_called_once_with(CertificateArn=_SAMPLE_CERT_ARN)

    @patch("certmesh.acm_client._build_acm_client")
    def test_client_error_raises_acm_error(self, mock_build: MagicMock, acm_cfg: JsonDict) -> None:
        mock_client = MagicMock()
        mock_build.return_value = mock_client
        mock_client.renew_certificate.side_effect = _make_client_error(
            code="InvalidArnException",
            message="Invalid ARN",
        )

        with pytest.raises(ACMError, match="InvalidArnException"):
            renew_certificate(acm_cfg, _SAMPLE_CERT_ARN)


# ============================================================================
# get_validation_records
# ============================================================================


class TestGetValidationRecords:
    @patch("certmesh.acm_client.describe_certificate")
    def test_returns_dns_records(self, mock_describe: MagicMock, acm_cfg: JsonDict) -> None:
        mock_describe.return_value = ACMCertificateDetail(
            certificate_arn=_SAMPLE_CERT_ARN,
            domain_name=_SAMPLE_DOMAIN,
            status="PENDING_VALIDATION",
            raw={
                "DomainValidationOptions": [
                    {
                        "DomainName": _SAMPLE_DOMAIN,
                        "ValidationMethod": "DNS",
                        "ValidationStatus": "PENDING_VALIDATION",
                        "ResourceRecord": {
                            "Name": "_acme.example.com",
                            "Type": "CNAME",
                            "Value": "_validation.acm.aws",
                        },
                    },
                ],
            },
        )

        records = get_validation_records(acm_cfg, _SAMPLE_CERT_ARN)

        assert len(records) == 1
        assert isinstance(records[0], ACMValidationRecord)
        assert records[0].domain_name == _SAMPLE_DOMAIN
        assert records[0].validation_method == "DNS"
        assert records[0].resource_record_name == "_acme.example.com"
        assert records[0].resource_record_type == "CNAME"

    @patch("certmesh.acm_client.describe_certificate")
    def test_returns_email_records(self, mock_describe: MagicMock, acm_cfg: JsonDict) -> None:
        mock_describe.return_value = ACMCertificateDetail(
            certificate_arn=_SAMPLE_CERT_ARN,
            domain_name=_SAMPLE_DOMAIN,
            status="PENDING_VALIDATION",
            raw={
                "DomainValidationOptions": [
                    {
                        "DomainName": _SAMPLE_DOMAIN,
                        "ValidationMethod": "EMAIL",
                        "ValidationStatus": "PENDING_VALIDATION",
                        "ValidationEmails": [
                            "admin@example.com",
                            "postmaster@example.com",
                        ],
                    },
                ],
            },
        )

        records = get_validation_records(acm_cfg, _SAMPLE_CERT_ARN)

        assert len(records) == 1
        assert records[0].validation_method == "EMAIL"
        assert "admin@example.com" in records[0].validation_emails

    @patch("certmesh.acm_client.describe_certificate")
    def test_multiple_domains(self, mock_describe: MagicMock, acm_cfg: JsonDict) -> None:
        mock_describe.return_value = ACMCertificateDetail(
            certificate_arn=_SAMPLE_CERT_ARN,
            domain_name=_SAMPLE_DOMAIN,
            status="PENDING_VALIDATION",
            raw={
                "DomainValidationOptions": [
                    {
                        "DomainName": "example.com",
                        "ValidationMethod": "DNS",
                        "ValidationStatus": "PENDING_VALIDATION",
                        "ResourceRecord": {
                            "Name": "_a.example.com",
                            "Type": "CNAME",
                            "Value": "_v1.acm.aws",
                        },
                    },
                    {
                        "DomainName": "www.example.com",
                        "ValidationMethod": "DNS",
                        "ValidationStatus": "PENDING_VALIDATION",
                        "ResourceRecord": {
                            "Name": "_b.www.example.com",
                            "Type": "CNAME",
                            "Value": "_v2.acm.aws",
                        },
                    },
                ],
            },
        )

        records = get_validation_records(acm_cfg, _SAMPLE_CERT_ARN)
        assert len(records) == 2

    @patch("certmesh.acm_client.describe_certificate")
    def test_no_validation_options_raises(
        self, mock_describe: MagicMock, acm_cfg: JsonDict
    ) -> None:
        mock_describe.return_value = ACMCertificateDetail(
            certificate_arn=_SAMPLE_CERT_ARN,
            domain_name=_SAMPLE_DOMAIN,
            status="ISSUED",
            raw={},
        )

        with pytest.raises(ACMValidationError, match="No DomainValidationOptions"):
            get_validation_records(acm_cfg, _SAMPLE_CERT_ARN)

    @patch("certmesh.acm_client.describe_certificate")
    def test_describe_failure_raises_validation_error(
        self, mock_describe: MagicMock, acm_cfg: JsonDict
    ) -> None:
        mock_describe.side_effect = ACMError("describe failed")

        with pytest.raises(ACMValidationError, match="Failed to retrieve validation records"):
            get_validation_records(acm_cfg, _SAMPLE_CERT_ARN)


# ============================================================================
# wait_for_issuance
# ============================================================================


class TestWaitForIssuance:
    @patch("certmesh.acm_client.time.sleep")
    @patch("certmesh.acm_client.describe_certificate")
    def test_returns_immediately_when_issued(
        self,
        mock_describe: MagicMock,
        mock_sleep: MagicMock,
        acm_cfg: JsonDict,
    ) -> None:
        mock_describe.return_value = ACMCertificateDetail(
            certificate_arn=_SAMPLE_CERT_ARN,
            domain_name=_SAMPLE_DOMAIN,
            status="ISSUED",
        )

        detail = wait_for_issuance(acm_cfg, _SAMPLE_CERT_ARN)

        assert detail.status == "ISSUED"
        mock_sleep.assert_not_called()

    @patch("certmesh.acm_client.time.sleep")
    @patch("certmesh.acm_client.describe_certificate")
    def test_polls_until_issued(
        self,
        mock_describe: MagicMock,
        mock_sleep: MagicMock,
        acm_cfg: JsonDict,
    ) -> None:
        pending_detail = ACMCertificateDetail(
            certificate_arn=_SAMPLE_CERT_ARN,
            domain_name=_SAMPLE_DOMAIN,
            status="PENDING_VALIDATION",
        )
        issued_detail = ACMCertificateDetail(
            certificate_arn=_SAMPLE_CERT_ARN,
            domain_name=_SAMPLE_DOMAIN,
            status="ISSUED",
        )
        mock_describe.side_effect = [pending_detail, pending_detail, issued_detail]

        detail = wait_for_issuance(acm_cfg, _SAMPLE_CERT_ARN)

        assert detail.status == "ISSUED"
        assert mock_sleep.call_count == 2
        # Check interval from config (polling.interval_seconds = 1)
        mock_sleep.assert_called_with(1)

    @patch("certmesh.acm_client.time.sleep")
    @patch("certmesh.acm_client.describe_certificate")
    def test_raises_on_failed_status(
        self,
        mock_describe: MagicMock,
        mock_sleep: MagicMock,
        acm_cfg: JsonDict,
    ) -> None:
        mock_describe.return_value = ACMCertificateDetail(
            certificate_arn=_SAMPLE_CERT_ARN,
            domain_name=_SAMPLE_DOMAIN,
            status="FAILED",
            failure_reason="CAA check failed",
        )

        with pytest.raises(ACMValidationError, match="terminal status 'FAILED'"):
            wait_for_issuance(acm_cfg, _SAMPLE_CERT_ARN)

    @patch("certmesh.acm_client.time.sleep")
    @patch("certmesh.acm_client.describe_certificate")
    def test_raises_on_revoked_status(
        self,
        mock_describe: MagicMock,
        mock_sleep: MagicMock,
        acm_cfg: JsonDict,
    ) -> None:
        mock_describe.return_value = ACMCertificateDetail(
            certificate_arn=_SAMPLE_CERT_ARN,
            domain_name=_SAMPLE_DOMAIN,
            status="REVOKED",
        )

        with pytest.raises(ACMValidationError, match="terminal status 'REVOKED'"):
            wait_for_issuance(acm_cfg, _SAMPLE_CERT_ARN)

    @patch("certmesh.acm_client.time.sleep")
    @patch("certmesh.acm_client.describe_certificate")
    def test_timeout_raises(
        self,
        mock_describe: MagicMock,
        mock_sleep: MagicMock,
        acm_cfg: JsonDict,
    ) -> None:
        # Config has max_wait_seconds=5, interval_seconds=1.
        # After 5 iterations of sleep(1), elapsed reaches 5 and we exit the
        # while loop. describe is then called once more in the exception message.
        pending = ACMCertificateDetail(
            certificate_arn=_SAMPLE_CERT_ARN,
            domain_name=_SAMPLE_DOMAIN,
            status="PENDING_VALIDATION",
        )
        # 5 calls inside the loop + 1 call in the timeout exception message
        mock_describe.side_effect = [pending] * 6

        with pytest.raises(ACMValidationError, match="Timed out after 5s"):
            wait_for_issuance(acm_cfg, _SAMPLE_CERT_ARN)

    @patch("certmesh.acm_client.time.sleep")
    @patch("certmesh.acm_client.describe_certificate")
    def test_override_interval_and_max_wait(
        self,
        mock_describe: MagicMock,
        mock_sleep: MagicMock,
        acm_cfg: JsonDict,
    ) -> None:
        pending = ACMCertificateDetail(
            certificate_arn=_SAMPLE_CERT_ARN,
            domain_name=_SAMPLE_DOMAIN,
            status="PENDING_VALIDATION",
        )
        issued = ACMCertificateDetail(
            certificate_arn=_SAMPLE_CERT_ARN,
            domain_name=_SAMPLE_DOMAIN,
            status="ISSUED",
        )
        mock_describe.side_effect = [pending, issued]

        detail = wait_for_issuance(
            acm_cfg,
            _SAMPLE_CERT_ARN,
            interval_seconds=2,
            max_wait_seconds=60,
        )

        assert detail.status == "ISSUED"
        mock_sleep.assert_called_once_with(2)

    @patch("certmesh.acm_client.time.sleep")
    @patch("certmesh.acm_client.describe_certificate")
    def test_validation_timed_out_is_terminal(
        self,
        mock_describe: MagicMock,
        mock_sleep: MagicMock,
        acm_cfg: JsonDict,
    ) -> None:
        mock_describe.return_value = ACMCertificateDetail(
            certificate_arn=_SAMPLE_CERT_ARN,
            domain_name=_SAMPLE_DOMAIN,
            status="VALIDATION_TIMED_OUT",
        )

        with pytest.raises(ACMValidationError, match="terminal status 'VALIDATION_TIMED_OUT'"):
            wait_for_issuance(acm_cfg, _SAMPLE_CERT_ARN)


# ============================================================================
# issue_private_certificate
# ============================================================================


class TestIssuePrivateCertificate:
    @patch("certmesh.acm_client._build_acm_pca_client")
    def test_successful_issue(self, mock_build: MagicMock, acm_cfg_with_ca: JsonDict) -> None:
        mock_pca = MagicMock()
        mock_build.return_value = mock_pca
        issued_arn = "arn:aws:acm-pca:us-east-1:123456789012:certificate/issued-cert-id"
        mock_pca.issue_certificate.return_value = {
            "CertificateArn": issued_arn,
        }

        csr = "-----BEGIN CERTIFICATE REQUEST-----\nMOCK\n-----END CERTIFICATE REQUEST-----"
        result = issue_private_certificate(acm_cfg_with_ca, csr)

        assert result == issued_arn
        call_kwargs = mock_pca.issue_certificate.call_args[1]
        assert call_kwargs["CertificateAuthorityArn"] == _SAMPLE_CA_ARN
        assert call_kwargs["SigningAlgorithm"] == "SHA256WITHRSA"
        assert call_kwargs["Validity"] == {"Value": 365, "Type": "DAYS"}

    @patch("certmesh.acm_client._build_acm_pca_client")
    def test_with_override_params(self, mock_build: MagicMock, acm_cfg_with_ca: JsonDict) -> None:
        mock_pca = MagicMock()
        mock_build.return_value = mock_pca
        mock_pca.issue_certificate.return_value = {
            "CertificateArn": "arn:cert/new",
        }

        custom_ca_arn = "arn:aws:acm-pca:us-west-2:999:certificate-authority/custom"
        result = issue_private_certificate(
            acm_cfg_with_ca,
            "CSR_PEM",
            ca_arn=custom_ca_arn,
            signing_algorithm="SHA384WITHRSA",
            validity_days=90,
            template_arn="arn:aws:acm-pca:::template/EndEntityCertificate/V1",
            idempotency_token="my-token",
        )

        assert result == "arn:cert/new"
        call_kwargs = mock_pca.issue_certificate.call_args[1]
        assert call_kwargs["CertificateAuthorityArn"] == custom_ca_arn
        assert call_kwargs["SigningAlgorithm"] == "SHA384WITHRSA"
        assert call_kwargs["Validity"]["Value"] == 90
        assert call_kwargs["TemplateArn"] == ("arn:aws:acm-pca:::template/EndEntityCertificate/V1")
        assert call_kwargs["IdempotencyToken"] == "my-token"

    def test_missing_ca_arn_raises(self, acm_cfg: JsonDict) -> None:
        with pytest.raises(ACMPrivateCAError, match="Private CA ARN is required"):
            issue_private_certificate(acm_cfg, "CSR_PEM")

    @patch("certmesh.acm_client._build_acm_pca_client")
    def test_client_error_raises(self, mock_build: MagicMock, acm_cfg_with_ca: JsonDict) -> None:
        mock_pca = MagicMock()
        mock_build.return_value = mock_pca
        mock_pca.issue_certificate.side_effect = _make_client_error(
            code="MalformedCSRException",
            message="CSR is malformed",
        )

        with pytest.raises(ACMPrivateCAError, match="MalformedCSRException"):
            issue_private_certificate(acm_cfg_with_ca, "BAD_CSR")


# ============================================================================
# get_private_certificate
# ============================================================================


class TestGetPrivateCertificate:
    @patch("certmesh.acm_client._build_acm_pca_client")
    def test_successful_get(self, mock_build: MagicMock, acm_cfg_with_ca: JsonDict) -> None:
        mock_pca = MagicMock()
        mock_build.return_value = mock_pca
        mock_pca.get_certificate.return_value = {
            "Certificate": "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----",
            "CertificateChain": "-----BEGIN CERTIFICATE-----\nCHAIN\n-----END CERTIFICATE-----",
        }

        cert_pem, chain_pem = get_private_certificate(acm_cfg_with_ca, _SAMPLE_CERT_ARN)

        assert "CERT" in cert_pem
        assert "CHAIN" in chain_pem
        mock_pca.get_certificate.assert_called_once_with(
            CertificateAuthorityArn=_SAMPLE_CA_ARN,
            CertificateArn=_SAMPLE_CERT_ARN,
        )

    @patch("certmesh.acm_client._build_acm_pca_client")
    def test_with_custom_ca_arn(self, mock_build: MagicMock, acm_cfg_with_ca: JsonDict) -> None:
        mock_pca = MagicMock()
        mock_build.return_value = mock_pca
        mock_pca.get_certificate.return_value = {
            "Certificate": "CERT_PEM",
            "CertificateChain": "CHAIN_PEM",
        }

        custom_ca = "arn:aws:acm-pca:eu-west-1:999:certificate-authority/other"
        get_private_certificate(acm_cfg_with_ca, _SAMPLE_CERT_ARN, ca_arn=custom_ca)

        call_kwargs = mock_pca.get_certificate.call_args[1]
        assert call_kwargs["CertificateAuthorityArn"] == custom_ca

    def test_missing_ca_arn_raises(self, acm_cfg: JsonDict) -> None:
        with pytest.raises(ACMPrivateCAError, match="Private CA ARN is required"):
            get_private_certificate(acm_cfg, _SAMPLE_CERT_ARN)

    @patch("certmesh.acm_client._build_acm_pca_client")
    def test_request_in_progress_exception(
        self, mock_build: MagicMock, acm_cfg_with_ca: JsonDict
    ) -> None:
        mock_pca = MagicMock()
        mock_build.return_value = mock_pca
        mock_pca.get_certificate.side_effect = _make_client_error(
            code="RequestInProgressException",
            message="Certificate not yet available",
        )

        with pytest.raises(ACMPrivateCAError, match="issuance is still in progress"):
            get_private_certificate(acm_cfg_with_ca, _SAMPLE_CERT_ARN)

    @patch("certmesh.acm_client._build_acm_pca_client")
    def test_generic_client_error(self, mock_build: MagicMock, acm_cfg_with_ca: JsonDict) -> None:
        mock_pca = MagicMock()
        mock_build.return_value = mock_pca
        mock_pca.get_certificate.side_effect = _make_client_error(
            code="ResourceNotFoundException",
            message="Not found",
        )

        with pytest.raises(ACMPrivateCAError, match="ResourceNotFoundException"):
            get_private_certificate(acm_cfg_with_ca, _SAMPLE_CERT_ARN)

    @patch("certmesh.acm_client._build_acm_pca_client")
    def test_empty_certificate_raises(
        self, mock_build: MagicMock, acm_cfg_with_ca: JsonDict
    ) -> None:
        mock_pca = MagicMock()
        mock_build.return_value = mock_pca
        mock_pca.get_certificate.return_value = {
            "Certificate": "",
            "CertificateChain": "CHAIN",
        }

        with pytest.raises(ACMPrivateCAError, match="empty certificate"):
            get_private_certificate(acm_cfg_with_ca, _SAMPLE_CERT_ARN)


# ============================================================================
# revoke_private_certificate
# ============================================================================


class TestRevokePrivateCertificate:
    @patch("certmesh.acm_client._build_acm_pca_client")
    def test_successful_revoke(self, mock_build: MagicMock, acm_cfg_with_ca: JsonDict) -> None:
        mock_pca = MagicMock()
        mock_build.return_value = mock_pca

        revoke_private_certificate(
            acm_cfg_with_ca,
            _SAMPLE_CERT_ARN,
            "AA:BB:CC:DD",
        )

        mock_pca.revoke_certificate.assert_called_once_with(
            CertificateAuthorityArn=_SAMPLE_CA_ARN,
            CertificateSerial="AA:BB:CC:DD",
            RevocationReason="UNSPECIFIED",
        )

    @patch("certmesh.acm_client._build_acm_pca_client")
    def test_with_custom_reason(self, mock_build: MagicMock, acm_cfg_with_ca: JsonDict) -> None:
        mock_pca = MagicMock()
        mock_build.return_value = mock_pca

        revoke_private_certificate(
            acm_cfg_with_ca,
            _SAMPLE_CERT_ARN,
            "AA:BB",
            "KEY_COMPROMISE",
        )

        call_kwargs = mock_pca.revoke_certificate.call_args[1]
        assert call_kwargs["RevocationReason"] == "KEY_COMPROMISE"

    @patch("certmesh.acm_client._build_acm_pca_client")
    def test_with_custom_ca_arn(self, mock_build: MagicMock, acm_cfg_with_ca: JsonDict) -> None:
        mock_pca = MagicMock()
        mock_build.return_value = mock_pca

        custom_ca = "arn:custom-ca"
        revoke_private_certificate(
            acm_cfg_with_ca,
            _SAMPLE_CERT_ARN,
            "AA:BB",
            ca_arn=custom_ca,
        )

        call_kwargs = mock_pca.revoke_certificate.call_args[1]
        assert call_kwargs["CertificateAuthorityArn"] == custom_ca

    def test_missing_ca_arn_raises(self, acm_cfg: JsonDict) -> None:
        with pytest.raises(ACMPrivateCAError, match="Private CA ARN is required"):
            revoke_private_certificate(acm_cfg, _SAMPLE_CERT_ARN, "AA:BB")

    @patch("certmesh.acm_client._build_acm_pca_client")
    def test_client_error_raises(self, mock_build: MagicMock, acm_cfg_with_ca: JsonDict) -> None:
        mock_pca = MagicMock()
        mock_build.return_value = mock_pca
        mock_pca.revoke_certificate.side_effect = _make_client_error(
            code="InvalidStateException",
            message="Certificate cannot be revoked",
        )

        with pytest.raises(ACMPrivateCAError, match="InvalidStateException"):
            revoke_private_certificate(acm_cfg_with_ca, _SAMPLE_CERT_ARN, "AA:BB")


# ============================================================================
# list_private_certificates
# ============================================================================


class TestListPrivateCertificates:
    @patch("certmesh.acm_client._build_acm_client")
    def test_returns_private_certs_for_matching_ca(
        self, mock_build: MagicMock, acm_cfg_with_ca: JsonDict
    ) -> None:
        mock_client = MagicMock()
        mock_build.return_value = mock_client

        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "CertificateSummaryList": [
                    {
                        "CertificateArn": "arn:cert/1",
                        "DomainName": "private.example.com",
                        "Type": "PRIVATE",
                        "CertificateAuthorityArn": _SAMPLE_CA_ARN,
                        "Status": "ISSUED",
                    },
                    {
                        "CertificateArn": "arn:cert/2",
                        "DomainName": "public.example.com",
                        "Type": "AMAZON_ISSUED",
                        "Status": "ISSUED",
                    },
                    {
                        "CertificateArn": "arn:cert/3",
                        "DomainName": "private2.example.com",
                        "Type": "PRIVATE",
                        "CertificateAuthorityArn": _SAMPLE_CA_ARN,
                        "Status": "ISSUED",
                    },
                    {
                        "CertificateArn": "arn:cert/4",
                        "DomainName": "other-ca.example.com",
                        "Type": "PRIVATE",
                        "CertificateAuthorityArn": "arn:aws:acm-pca:us-east-1:000:ca/other",
                        "Status": "ISSUED",
                    },
                ],
            },
        ]

        results = list_private_certificates(acm_cfg_with_ca)

        assert len(results) == 2
        assert all(r["Type"] == "PRIVATE" for r in results)
        assert all(r["CertificateAuthorityArn"] == _SAMPLE_CA_ARN for r in results)

    @patch("certmesh.acm_client._build_acm_client")
    def test_describe_fallback_when_ca_arn_absent(
        self, mock_build: MagicMock, acm_cfg_with_ca: JsonDict
    ) -> None:
        """When CertificateAuthorityArn is absent, describe_certificate is used."""
        mock_client = MagicMock()
        mock_build.return_value = mock_client

        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "CertificateSummaryList": [
                    {
                        "CertificateArn": "arn:cert/1",
                        "DomainName": "private.example.com",
                        "Type": "PRIVATE",
                        "Status": "ISSUED",
                    },
                    {
                        "CertificateArn": "arn:cert/2",
                        "DomainName": "other-ca.example.com",
                        "Type": "PRIVATE",
                        "Status": "ISSUED",
                    },
                ],
            },
        ]
        mock_client.describe_certificate.side_effect = [
            {"Certificate": {"CertificateAuthorityArn": _SAMPLE_CA_ARN}},
            {"Certificate": {"CertificateAuthorityArn": "arn:aws:acm-pca:other-ca"}},
        ]

        results = list_private_certificates(acm_cfg_with_ca)

        assert len(results) == 1
        assert results[0]["CertificateArn"] == "arn:cert/1"
        assert mock_client.describe_certificate.call_count == 2

    @patch("certmesh.acm_client._build_acm_client")
    def test_describe_fallback_skips_on_error(
        self, mock_build: MagicMock, acm_cfg_with_ca: JsonDict
    ) -> None:
        """When describe_certificate fails, the certificate is skipped."""
        mock_client = MagicMock()
        mock_build.return_value = mock_client

        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "CertificateSummaryList": [
                    {
                        "CertificateArn": "arn:cert/1",
                        "DomainName": "private.example.com",
                        "Type": "PRIVATE",
                        "Status": "ISSUED",
                    },
                ],
            },
        ]
        mock_client.describe_certificate.side_effect = _make_client_error(
            code="AccessDeniedException",
            message="Access denied",
        )

        results = list_private_certificates(acm_cfg_with_ca)

        assert len(results) == 0

    @patch("certmesh.acm_client._build_acm_client")
    def test_max_items_limits(self, mock_build: MagicMock, acm_cfg_with_ca: JsonDict) -> None:
        mock_client = MagicMock()
        mock_build.return_value = mock_client

        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "CertificateSummaryList": [
                    {
                        "CertificateArn": f"arn:cert/{i}",
                        "DomainName": f"p{i}.example.com",
                        "Type": "PRIVATE",
                        "CertificateAuthorityArn": _SAMPLE_CA_ARN,
                        "Status": "ISSUED",
                    }
                    for i in range(5)
                ],
            },
        ]

        results = list_private_certificates(acm_cfg_with_ca, max_items=3)
        assert len(results) == 3

    def test_missing_ca_arn_raises(self, acm_cfg: JsonDict) -> None:
        with pytest.raises(ACMPrivateCAError, match="Private CA ARN is required"):
            list_private_certificates(acm_cfg)

    @patch("certmesh.acm_client._build_acm_client")
    def test_client_error_raises(self, mock_build: MagicMock, acm_cfg_with_ca: JsonDict) -> None:
        mock_client = MagicMock()
        mock_build.return_value = mock_client

        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.side_effect = _make_client_error(
            code="AccessDeniedException",
            message="Access denied",
        )

        with pytest.raises(ACMPrivateCAError, match="AccessDeniedException"):
            list_private_certificates(acm_cfg_with_ca)

    @patch("certmesh.acm_client._build_acm_client")
    def test_empty_result(self, mock_build: MagicMock, acm_cfg_with_ca: JsonDict) -> None:
        mock_client = MagicMock()
        mock_build.return_value = mock_client

        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {"CertificateSummaryList": []},
        ]

        results = list_private_certificates(acm_cfg_with_ca)
        assert results == []


# ============================================================================
# export_and_persist
# ============================================================================


class TestExportAndPersist:
    @patch("certmesh.acm_client.cu.persist_bundle")
    @patch("certmesh.acm_client.export_certificate")
    def test_successful_export_and_persist(
        self,
        mock_export: MagicMock,
        mock_persist: MagicMock,
        acm_cfg: JsonDict,
    ) -> None:
        mock_bundle = MagicMock()
        mock_export.return_value = mock_bundle
        mock_persist.return_value = {"cert": "/tmp/cert.pem", "key": "/tmp/key.pem"}

        result = export_and_persist(acm_cfg, _SAMPLE_CERT_ARN, b"password")

        assert result == {"cert": "/tmp/cert.pem", "key": "/tmp/key.pem"}
        mock_export.assert_called_once_with(acm_cfg, _SAMPLE_CERT_ARN, b"password")
        mock_persist.assert_called_once_with(
            mock_bundle,
            acm_cfg.get("output", {}),
            vault_client=None,
        )

    @patch("certmesh.acm_client.cu.persist_bundle")
    @patch("certmesh.acm_client.export_certificate")
    def test_with_vault_client(
        self,
        mock_export: MagicMock,
        mock_persist: MagicMock,
        acm_cfg: JsonDict,
    ) -> None:
        mock_bundle = MagicMock()
        mock_export.return_value = mock_bundle
        mock_persist.return_value = {"vault": "secret/certs/test"}
        mock_vault = MagicMock()

        result = export_and_persist(
            acm_cfg, _SAMPLE_CERT_ARN, b"password", vault_client=mock_vault
        )

        assert result == {"vault": "secret/certs/test"}
        mock_persist.assert_called_once_with(
            mock_bundle,
            acm_cfg.get("output", {}),
            vault_client=mock_vault,
        )

    @patch("certmesh.acm_client.export_certificate")
    def test_export_failure_propagates(
        self,
        mock_export: MagicMock,
        acm_cfg: JsonDict,
    ) -> None:
        mock_export.side_effect = ACMExportError("Export failed")

        with pytest.raises(ACMExportError, match="Export failed"):
            export_and_persist(acm_cfg, _SAMPLE_CERT_ARN, b"password")


# ============================================================================
# Edge cases and data model tests
# ============================================================================


class TestDataModels:
    def test_acm_certificate_summary_defaults(self) -> None:
        summary = ACMCertificateSummary(
            certificate_arn="arn:test",
            domain_name="example.com",
            status="ISSUED",
            key_algorithm="RSA_2048",
            type="AMAZON_ISSUED",
            in_use=False,
        )
        assert summary.not_after is None
        assert summary.not_before is None

    def test_acm_certificate_detail_defaults(self) -> None:
        detail = ACMCertificateDetail(
            certificate_arn="arn:test",
            domain_name="example.com",
        )
        assert detail.status == ""
        assert detail.subject_alternative_names == []
        assert detail.in_use_by == []
        assert detail.raw == {}
        assert detail.not_before is None

    def test_acm_validation_record_defaults(self) -> None:
        record = ACMValidationRecord(
            domain_name="example.com",
            validation_method="DNS",
            validation_status="PENDING_VALIDATION",
        )
        assert record.resource_record_name == ""
        assert record.resource_record_type == ""
        assert record.resource_record_value == ""
        assert record.validation_emails == []
