"""
tests/test_ioc_classifier.py
[US-02] Testes unitários do IoC Classifier centralizado.

Execução:
    pytest tests/test_ioc_classifier.py -v

Cobertura esperada: > 90% do ioc_classifier.py
"""

import pytest
import sys
import os

# Garante que o módulo é encontrado independente de onde pytest é rodado
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.utils.ioc_classifier import (
    classify, is_valid, is_private_ip, get_hash_type,
    classify_many, from_log_parser_result, IoCType
)


# ══════════════════════════════════════════════════════════════
# Testes: classify() — casos normais
# ══════════════════════════════════════════════════════════════

class TestClassifyIP:
    def test_ip_simples(self):
        assert classify("8.8.8.8") == IoCType.IP

    def test_ip_cloudflare(self):
        assert classify("1.1.1.1") == IoCType.IP

    def test_ip_privado_192(self):
        assert classify("192.168.1.1") == IoCType.IP  # é IP, mesmo que privado

    def test_ip_privado_10(self):
        assert classify("10.0.0.1") == IoCType.IP

    def test_ip_loopback(self):
        assert classify("127.0.0.1") == IoCType.IP

    def test_ip_broadcast(self):
        # 999 não é octeto válido → UNKNOWN
        assert classify("999.999.999.999") == IoCType.UNKNOWN

    def test_ip_octeto_invalido(self):
        assert classify("256.1.1.1") == IoCType.UNKNOWN


class TestClassifyDomain:
    def test_dominio_simples(self):
        assert classify("google.com") == IoCType.DOMAIN

    def test_dominio_com_subdominio(self):
        assert classify("evil.malware.ru") == IoCType.DOMAIN

    def test_dominio_br(self):
        assert classify("guiadasegurancadigital.com.br") == IoCType.DOMAIN

    def test_dominio_com_www(self):
        assert classify("www.google.com") == IoCType.DOMAIN

    # CASO CRÍTICO: era classificado como IP pela heurística "." in value
    def test_dominio_nao_e_ip(self):
        result = classify("malware.example.com")
        assert result == IoCType.DOMAIN
        assert result != IoCType.IP

    def test_dominio_com_hifen(self):
        assert classify("my-domain.com") == IoCType.DOMAIN


class TestClassifyURL:
    def test_url_http(self):
        assert classify("http://evil.com/payload") == IoCType.URL

    def test_url_https(self):
        assert classify("https://phishing.site/login") == IoCType.URL

    def test_url_com_path(self):
        assert classify("https://evil.com/path?q=1&r=2") == IoCType.URL

    # URL deve ter prioridade sobre Domain
    def test_url_prioridade_sobre_domain(self):
        result = classify("https://google.com")
        assert result == IoCType.URL
        assert result != IoCType.DOMAIN


class TestClassifyHash:
    def test_md5(self):
        assert classify("d41d8cd98f00b204e9800998ecf8427e") == IoCType.HASH

    def test_sha1(self):
        assert classify("da39a3ee5e6b4b0d3255bfef95601890afd80709") == IoCType.HASH

    def test_sha256(self):
        assert classify(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ) == IoCType.HASH

    def test_hash_maiusculas(self):
        assert classify("D41D8CD98F00B204E9800998ECF8427E") == IoCType.HASH

    def test_hash_tamanho_errado(self):
        # 31 chars — não é MD5
        assert classify("d41d8cd98f00b204e9800998ecf842") == IoCType.UNKNOWN


class TestClassifyEmail:
    def test_email_simples(self):
        assert classify("user@evil.com") == IoCType.EMAIL

    def test_email_com_subdominio(self):
        assert classify("admin@mail.evil.ru") == IoCType.EMAIL

    def test_email_com_ponto_no_user(self):
        assert classify("first.last@domain.com") == IoCType.EMAIL

    # Email deve ter prioridade sobre Domain
    def test_email_nao_e_domain(self):
        result = classify("user@evil.com")
        assert result == IoCType.EMAIL
        assert result != IoCType.DOMAIN


class TestClassifyUnknown:
    def test_string_vazia(self):
        assert classify("") == IoCType.UNKNOWN

    def test_apenas_espacos(self):
        assert classify("   ") == IoCType.UNKNOWN

    def test_caracteres_invalidos(self):
        assert classify("not_an_ioc!!") == IoCType.UNKNOWN

    def test_numero_solto(self):
        assert classify("12345") == IoCType.UNKNOWN

    def test_texto_livre(self):
        assert classify("isso não é um ioc") == IoCType.UNKNOWN


# ══════════════════════════════════════════════════════════════
# Testes: is_valid()
# ══════════════════════════════════════════════════════════════

class TestIsValid:
    def test_ip_valido(self):
        assert is_valid("8.8.8.8") is True

    def test_dominio_valido(self):
        assert is_valid("google.com") is True

    def test_invalido(self):
        assert is_valid("not_ioc!!") is False

    def test_vazio(self):
        assert is_valid("") is False


# ══════════════════════════════════════════════════════════════
# Testes: is_private_ip()
# ══════════════════════════════════════════════════════════════

class TestIsPrivateIP:
    def test_ip_privado_192(self):
        assert is_private_ip("192.168.0.1") is True

    def test_ip_privado_10(self):
        assert is_private_ip("10.10.10.10") is True

    def test_ip_privado_172(self):
        assert is_private_ip("172.16.0.1") is True

    def test_ip_loopback(self):
        assert is_private_ip("127.0.0.1") is True

    def test_ip_publico(self):
        assert is_private_ip("8.8.8.8") is False

    def test_dominio_nao_e_ip(self):
        assert is_private_ip("google.com") is False

    def test_broadcast(self):
        assert is_private_ip("255.255.255.255") is True


# ══════════════════════════════════════════════════════════════
# Testes: get_hash_type()
# ══════════════════════════════════════════════════════════════

class TestGetHashType:
    def test_md5(self):
        assert get_hash_type("d41d8cd98f00b204e9800998ecf8427e") == "MD5"

    def test_sha1(self):
        assert get_hash_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "SHA1"

    def test_sha256(self):
        assert get_hash_type(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ) == "SHA256"

    def test_desconhecido(self):
        assert get_hash_type("not_a_hash") == "Unknown"


# ══════════════════════════════════════════════════════════════
# Testes: classify_many()
# ══════════════════════════════════════════════════════════════

class TestClassifyMany:
    def test_lista_mista(self):
        values = ["8.8.8.8", "google.com", "d41d8cd98f00b204e9800998ecf8427e"]
        results = classify_many(values)
        assert len(results) == 3
        assert results[0]["type"] == "IP"
        assert results[1]["type"] == "Domain"
        assert results[2]["type"] == "Hash"

    def test_ip_privado_marcado(self):
        results = classify_many(["192.168.1.1"])
        assert results[0]["private"] is True

    def test_ip_publico_nao_marcado(self):
        results = classify_many(["8.8.8.8"])
        assert results[0]["private"] is False

    def test_lista_vazia(self):
        assert classify_many([]) == []


# ══════════════════════════════════════════════════════════════
# Testes: from_log_parser_result()
# ══════════════════════════════════════════════════════════════

class TestFromLogParserResult:
    def test_resultado_completo(self):
        parsed = {
            "ips":     ["8.8.8.8", "192.168.1.1"],
            "urls":    ["https://evil.com/payload"],
            "domains": ["malware.ru"],
            "hashes":  ["d41d8cd98f00b204e9800998ecf8427e"],
        }
        results = from_log_parser_result(parsed)
        types = [r["type"] for r in results]
        assert "IP" in types
        assert "URL" in types
        assert "Domain" in types
        assert "Hash" in types

    def test_ip_privado_identificado(self):
        parsed = {"ips": ["192.168.1.1"], "urls": [], "domains": [], "hashes": []}
        results = from_log_parser_result(parsed)
        assert results[0]["private"] is True

    def test_hash_com_tipo(self):
        parsed = {
            "ips": [], "urls": [], "domains": [],
            "hashes": ["d41d8cd98f00b204e9800998ecf8427e"]
        }
        results = from_log_parser_result(parsed)
        assert results[0]["hash_type"] == "MD5"

    def test_resultado_vazio(self):
        parsed = {"ips": [], "urls": [], "domains": [], "hashes": []}
        assert from_log_parser_result(parsed) == []


# ══════════════════════════════════════════════════════════════
# Testes parametrizados — casos reais de logs
# ══════════════════════════════════════════════════════════════

@pytest.mark.parametrize("value,expected", [
    # IPs
    ("8.8.8.8",                                   IoCType.IP),
    ("1.1.1.1",                                   IoCType.IP),
    ("45.33.32.156",                              IoCType.IP),
    # Domínios — incluindo os que falhavam com "." in value
    ("google.com",                                IoCType.DOMAIN),
    ("www.google.com",                            IoCType.DOMAIN),
    ("evil.malware.ru",                           IoCType.DOMAIN),
    ("guiadasegurancadigital.com.br",             IoCType.DOMAIN),
    # URLs
    ("https://evil.com/path",                     IoCType.URL),
    ("http://phish.io/login?user=x",              IoCType.URL),
    # Hashes
    ("d41d8cd98f00b204e9800998ecf8427e",          IoCType.HASH),
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709",  IoCType.HASH),
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", IoCType.HASH),
    # Email
    ("user@evil.com",                             IoCType.EMAIL),
    ("admin@mail.phish.ru",                       IoCType.EMAIL),
    # UNKNOWN
    ("not_an_ioc!!",                              IoCType.UNKNOWN),
    ("",                                          IoCType.UNKNOWN),
    ("256.1.1.1",                                 IoCType.UNKNOWN),
])
def test_classify_parametrizado(value, expected):
    assert classify(value) == expected
