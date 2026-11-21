"""Current-user Secret Service storage (GNOME Keyring, KWallet); no plaintext fallback.

Uses libsecret's `secret-tool`. The secret travels over stdin and stdout only,
never in command arguments or the environment.
"""

import re
import shutil
import subprocess
import sys

SERVICE = "ai.auday.workflow-link.experimental"


class CredentialError(Exception):
    pass


def _attributes(profile):
    if not isinstance(profile, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", profile):
        raise CredentialError("invalid_profile_name")
    return ["service", SERVICE, "account", profile]


def _tool():
    if not sys.platform.startswith("linux"):
        raise CredentialError("linux_secret_service_required")
    # A fixed system path keeps a user PATH entry from receiving the secret.
    for candidate in ("/usr/bin/secret-tool", "/bin/secret-tool"):
        if shutil.which(candidate):
            return candidate
    raise CredentialError("secret_tool_missing_install_libsecret_tools")


def _run(arguments, data=None):
    try:
        return subprocess.run([_tool(), *arguments], input=data, capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        raise CredentialError("secret_service_unavailable") from None


def save_secret(password, profile):
    data = password.encode("utf-8")
    if not data or len(data) > 2560 or b"\n" in data:
        raise CredentialError("invalid_credential")
    result = _run(["store", "--label=Auday workflow link (" + profile + ")", *_attributes(profile)], data)
    if result.returncode:
        raise CredentialError("secret_service_save_failed")


def read_secret(profile):
    result = _run(["lookup", *_attributes(profile)])
    if result.returncode or not result.stdout:
        raise CredentialError("pair_on_local_terminal_first")
    if len(result.stdout) > 2560:
        raise CredentialError("invalid_credential")
    try:
        return result.stdout.decode("utf-8").rstrip("\n")
    except UnicodeError:
        raise CredentialError("invalid_credential") from None


def delete_secret(profile):
    """Used only to clean up an explicitly chosen disposable test credential."""
    if _run(["clear", *_attributes(profile)]).returncode:
        raise CredentialError("secret_service_delete_failed")
