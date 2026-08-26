from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import (
    ExtendedKeyUsageOID,
    NameOID,
)

OUT = Path("/out")

now = datetime.now(timezone.utc)

# ============================================================
# Test CA
# ============================================================

ca_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

ca_name = x509.Name([
    x509.NameAttribute(
        NameOID.COMMON_NAME,
        "Gate17 Test CA"
    )
])

ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - timedelta(minutes=5))
    .not_valid_after(now + timedelta(days=1))
    .add_extension(
        x509.BasicConstraints(
            ca=True,
            path_length=0
        ),
        critical=True
    )
    .sign(
        ca_key,
        hashes.SHA256()
    )
)

# ============================================================
# service.test server certificate
# ============================================================

server_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

server_name = x509.Name([
    x509.NameAttribute(
        NameOID.COMMON_NAME,
        "service.test"
    )
])

server_cert = (
    x509.CertificateBuilder()
    .subject_name(server_name)
    .issuer_name(ca_name)
    .public_key(server_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - timedelta(minutes=5))
    .not_valid_after(now + timedelta(days=1))
    .add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("service.test"),
            x509.IPAddress(
                ip_address("172.18.0.139")
            ),
        ]),
        critical=False
    )
    .add_extension(
        x509.BasicConstraints(
            ca=False,
            path_length=None
        ),
        critical=True
    )
    .add_extension(
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH
        ]),
        critical=False
    )
    .sign(
        ca_key,
        hashes.SHA256()
    )
)

(OUT / "ca.pem").write_bytes(
    ca_cert.public_bytes(
        serialization.Encoding.PEM
    )
)

(OUT / "server.pem").write_bytes(
    server_cert.public_bytes(
        serialization.Encoding.PEM
    )
)

(OUT / "server.key").write_bytes(
    server_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
)

print("TLS_CA_CREATED: PASS")
print("TLS_SERVER_CERT_CREATED: PASS")
print("TLS_SAN_DNS=service.test")
print("TLS_SAN_IP=172.18.0.139")
