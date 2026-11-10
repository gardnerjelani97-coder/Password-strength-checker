import urllib.error

import pytest

import password_checker as pc

# SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
PASSWORD_PREFIX = "5BAA6"
PASSWORD_SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"

COMMON = {"password", "letmein", "qwerty123"}
STRONG = "Tr0ub4dor&Horse!"


class FakeResponse:
    """Minimal stand-in for the object returned by urllib.request.urlopen."""

    def __init__(self, body):
        self._body = body.encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


# ---------- check_password ----------


def test_strong_password_has_no_problems():
    assert pc.check_password(STRONG, COMMON) == []


def test_common_password_is_flagged_case_insensitively():
    assert "commonly used password" in pc.check_password("PassWord", COMMON)


def test_short_password_is_flagged():
    problems = pc.check_password("Ab1!", COMMON)
    assert f"shorter than {pc.MIN_LENGTH} characters" in problems


@pytest.mark.parametrize(
    "password, expected",
    [
        ("tr0ub4dor&horse!", "no uppercase letter"),
        ("Troubadour&Horse!", "no number"),
        ("Tr0ub4dorHorseXY", "no special character"),
    ],
)
def test_each_missing_rule_is_reported(password, expected):
    assert expected in pc.check_password(password, COMMON)


def test_all_problems_are_reported_together():
    problems = pc.check_password("abc", COMMON)
    assert len(problems) == 4  # short, no uppercase, no number, no special


def test_empty_password_fails():
    assert pc.check_password("", COMMON) != []


# ---------- load_common_passwords ----------


def test_load_common_passwords_normalises_and_skips_blanks(tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("Password\n  LetMeIn  \n\n\nqwerty123\n", encoding="utf-8")
    assert pc.load_common_passwords(wordlist) == {"password", "letmein", "qwerty123"}


def test_load_common_passwords_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        pc.load_common_passwords(tmp_path / "nope.txt")


# ---------- parse_range_response ----------


def test_parse_range_response_finds_suffix():
    body = f"0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n{PASSWORD_SUFFIX}:10434004\r\n"
    assert pc.parse_range_response(body, PASSWORD_SUFFIX) == 10434004


def test_parse_range_response_returns_zero_when_absent():
    body = "0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2"
    assert pc.parse_range_response(body, PASSWORD_SUFFIX) == 0


def test_parse_range_response_handles_padding_entries():
    body = f"{PASSWORD_SUFFIX}:0\r\n"
    assert pc.parse_range_response(body, PASSWORD_SUFFIX) == 0


# ---------- get_breach_count (network mocked) ----------


def test_get_breach_count_sends_only_the_hash_prefix(monkeypatch):
    seen = {}

    def fake_urlopen(request, timeout=None):
        seen["url"] = request.full_url
        return FakeResponse(f"{PASSWORD_SUFFIX}:42\r\n")

    monkeypatch.setattr(pc.urllib.request, "urlopen", fake_urlopen)

    assert pc.get_breach_count("password") == 42
    assert seen["url"] == pc.HIBP_URL + PASSWORD_PREFIX
    # Neither the password nor the rest of the hash may be sent.
    assert "password" not in seen["url"].lower().replace("pwnedpasswords", "")
    assert PASSWORD_SUFFIX not in seen["url"]


def test_get_breach_count_not_found(monkeypatch):
    monkeypatch.setattr(
        pc.urllib.request,
        "urlopen",
        lambda request, timeout=None: FakeResponse("0018A45C4D1DEF81644B54AB7F969B88D65:3"),
    )
    assert pc.get_breach_count("password") == 0


def test_get_breach_count_wraps_network_errors(monkeypatch):
    def boom(request, timeout=None):
        raise urllib.error.URLError("no internet")

    monkeypatch.setattr(pc.urllib.request, "urlopen", boom)
    with pytest.raises(pc.BreachCheckError):
        pc.get_breach_count("password")


def test_get_breach_count_wraps_timeouts(monkeypatch):
    def slow(request, timeout=None):
        raise TimeoutError("timed out")

    monkeypatch.setattr(pc.urllib.request, "urlopen", slow)
    with pytest.raises(pc.BreachCheckError):
        pc.get_breach_count("password")


# ---------- main (command-line behaviour) ----------


@pytest.fixture
def wordlist(tmp_path):
    path = tmp_path / "words.txt"
    path.write_text("password\nletmein\n", encoding="utf-8")
    return str(path)


def test_main_strong_password_offline_exits_zero(monkeypatch, wordlist, capsys):
    monkeypatch.setattr(pc.getpass, "getpass", lambda prompt="": STRONG)
    assert pc.main(["--offline", "--wordlist", wordlist]) == 0
    assert "Strong password" in capsys.readouterr().out


def test_main_weak_password_exits_one_and_lists_problems(monkeypatch, wordlist, capsys):
    monkeypatch.setattr(pc.getpass, "getpass", lambda prompt="": "abc")
    assert pc.main(["--offline", "--wordlist", wordlist]) == 1
    out = capsys.readouterr().out
    assert "Weak password" in out
    assert "no number" in out


def test_main_flags_breached_password(monkeypatch, wordlist, capsys):
    monkeypatch.setattr(pc.getpass, "getpass", lambda prompt="": STRONG)
    monkeypatch.setattr(pc, "get_breach_count", lambda password: 1234)
    assert pc.main(["--wordlist", wordlist]) == 1
    assert "1,234 known data breaches" in capsys.readouterr().out


def test_main_survives_breach_check_failure(monkeypatch, wordlist, capsys):
    def fail(password):
        raise pc.BreachCheckError("offline")

    monkeypatch.setattr(pc.getpass, "getpass", lambda prompt="": STRONG)
    monkeypatch.setattr(pc, "get_breach_count", fail)
    assert pc.main(["--wordlist", wordlist]) == 0
    out = capsys.readouterr().out
    assert "Could not check Have I Been Pwned" in out
    assert "Strong password" in out


def test_main_offline_never_calls_the_network(monkeypatch, wordlist):
    def should_not_run(password):
        raise AssertionError("network check ran in --offline mode")

    monkeypatch.setattr(pc.getpass, "getpass", lambda prompt="": STRONG)
    monkeypatch.setattr(pc, "get_breach_count", should_not_run)
    assert pc.main(["--offline", "--wordlist", wordlist]) == 0


def test_main_missing_wordlist_exits_two(tmp_path, capsys):
    assert pc.main(["--wordlist", str(tmp_path / "missing.txt")]) == 2
    assert "Wordlist not found" in capsys.readouterr().out
