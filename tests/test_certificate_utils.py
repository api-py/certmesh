"""Tests for certmesh.certificate_utils."""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from certmesh.certificate_utils import (
    CertificateBundle,
    SubjectInfo,
    assemble_bundle,
    build_csr,
    csr_to_pem,
    generate_rsa_private_key,
    parse_pkcs12_bundle,
    persist_bundle,
    private_key_to_pem,
)
from certmesh.exceptions import (
    CertificateExportError,
    KeyGenerationError,
    PKCS12ParseError,
)

JsonDict = dict[str, Any]


class TestGenerateRSAPrivateKey:
    @pytest.mark.parametrize("key_size", [2048, 3072, 4096])
    def test_valid_key_sizes(self, key_size: int) -> None:
        key = generate_rsa_private_key(key_size)
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == key_size

    def test_invalid_key_size_raises(self) -> None:
        with pytest.raises(KeyGenerationError, match="Unsupported"):
            generate_rsa_private_key(1024)


class TestPrivateKeyToPEM:
    def test_pem_output(self, rsa_private_key: rsa.RSAPrivateKey) -> None:
        pem = private_key_to_pem(rsa_private_key)
        assert pem.startswith(b"-----BEGIN RSA PRIVATE KEY-----")
        assert pem.endswith(b"-----END RSA PRIVATE KEY-----\n")


class TestBuildCSR:
    def test_basic_csr(self, rsa_private_key: rsa.RSAPrivateKey) -> None:
        subject = SubjectInfo(
            common_name="test.example.com",
            organisation="Test Org",
            country="US",
        )
        csr = build_csr(rsa_private_key, subject)
        assert csr is not None
        pem = csr_to_pem(csr)
        assert "BEGIN CERTIFICATE REQUEST" in pem

    def test_csr_with_sans(self, rsa_private_key: rsa.RSAPrivateKey) -> None:
        subject = SubjectInfo(
            common_name="test.example.com",
            san_dns_names=["api.example.com", "web.example.com"],
        )
        csr = build_csr(rsa_private_key, subject)
        pem = csr_to_pem(csr)
        assert "BEGIN CERTIFICATE REQUEST" in pem

    def test_csr_no_sans_uses_cn(self, rsa_private_key: rsa.RSAPrivateKey) -> None:
        subject = SubjectInfo(common_name="test.example.com")
        csr = build_csr(rsa_private_key, subject)
        assert csr is not None


class TestParsePKCS12Bundle:
    def test_valid_bundle(self, pkcs12_bundle: bytes) -> None:
        cert_pem, key_pem, chain_pem = parse_pkcs12_bundle(pkcs12_bundle, "testpass")
        assert b"BEGIN CERTIFICATE" in cert_pem
        assert b"BEGIN RSA PRIVATE KEY" in key_pem
        # No chain certs in our test bundle
        assert chain_pem is None

    def test_wrong_passphrase_raises(self, pkcs12_bundle: bytes) -> None:
        with pytest.raises(PKCS12ParseError, match="passphrase"):
            parse_pkcs12_bundle(pkcs12_bundle, "wrong")

    def test_invalid_data_raises(self) -> None:
        with pytest.raises(PKCS12ParseError):
            parse_pkcs12_bundle(b"not-pkcs12", "pass")


class TestAssembleBundle:
    def test_basic_assembly(
        self,
        self_signed_cert_pem: bytes,
        private_key_pem: bytes,
    ) -> None:
        bundle = assemble_bundle(
            cert_pem=self_signed_cert_pem,
            private_key_pem=private_key_pem,
            chain_pem=None,
            source_id="test-123",
        )
        assert bundle.common_name == "test.example.com"
        assert bundle.source_id == "test-123"
        assert bundle.certificate_pem.startswith("-----BEGIN CERTIFICATE-----")
        assert bundle.serial_number
        assert isinstance(bundle.not_after, datetime)
        assert bundle.certificate_pem_b64

    def test_with_chain(
        self,
        self_signed_cert_pem: bytes,
        private_key_pem: bytes,
    ) -> None:
        bundle = assemble_bundle(
            cert_pem=self_signed_cert_pem,
            private_key_pem=private_key_pem,
            chain_pem=self_signed_cert_pem,  # reuse as fake chain
            source_id="test-456",
        )
        assert bundle.chain_pem is not None

    def test_invalid_cert_pem_raises(self, private_key_pem: bytes) -> None:
        with pytest.raises(CertificateExportError):
            assemble_bundle(
                cert_pem=b"not-a-cert",
                private_key_pem=private_key_pem,
                chain_pem=None,
                source_id="bad",
            )


class TestPersistBundle:
    def _make_bundle(
        self,
        self_signed_cert_pem: bytes,
        private_key_pem: bytes,
    ) -> CertificateBundle:
        return assemble_bundle(
            cert_pem=self_signed_cert_pem,
            private_key_pem=private_key_pem,
            chain_pem=self_signed_cert_pem,
            source_id="test-789",
        )

    def test_filesystem_persistence(
        self,
        tmp_path: Path,
        self_signed_cert_pem: bytes,
        private_key_pem: bytes,
    ) -> None:
        bundle = self._make_bundle(self_signed_cert_pem, private_key_pem)
        output_cfg: JsonDict = {
            "destination": "filesystem",
            "base_path": str(tmp_path / "certs"),
            "cert_filename": "{order_id}_cert.pem",
            "key_filename": "{order_id}_key.pem",
            "chain_filename": "{order_id}_chain.pem",
        }
        result = persist_bundle(bundle, output_cfg)
        assert "filesystem_cert" in result
        assert "filesystem_key" in result
        assert "filesystem_chain" in result

        cert_path = Path(result["filesystem_cert"])
        key_path = Path(result["filesystem_key"])
        assert cert_path.exists()
        assert key_path.exists()
        # Key should have restricted permissions
        assert oct(os.stat(key_path).st_mode)[-3:] == "600"
