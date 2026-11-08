import datetime as dt
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID

from phishguard.config import Config
from phishguard.intel import IntelStore


@pytest.fixture
def cfg():
    return Config(db_path=":memory:", ct_enabled=False, allow_private=False)


@pytest.fixture
def store():
    return IntelStore(":memory:", reports_per_hour=5)


def is_prime(n, k=12):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2; r += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def rand_prime(bits):
    while True:
        c = random.getrandbits(bits) | (3 << (bits - 2)) | 1
        if is_prime(c):
            return c


def next_prime(n):
    n += 1
    if n % 2 == 0:
        n += 1
    while not is_prime(n):
        n += 2
    return n


def make_cert(cn="localhost", key=None, days_old=100, valid_days=90, self_signed=True, hash_alg=None, sans=None, issuer_cn=None, issuer_key=None):
    key = key or rsa.generate_private_key(65537, 2048)
    now = dt.datetime.now(dt.timezone.utc)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    iss = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)])
    b = (x509.CertificateBuilder().subject_name(subj).issuer_name(iss).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=days_old))
         .not_valid_after(now - dt.timedelta(days=days_old) + dt.timedelta(days=valid_days)))
    b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in (sans or [cn])]), False)
    cert = b.sign(issuer_key or key, hash_alg or hashes.SHA256())
    return cert, key
