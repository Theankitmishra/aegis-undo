"""Native macOS / Linux Desktop Security Alert Notifier (Zero shell=True, Zero Injection)."""

from __future__ import annotations

import os
import platform
import re
import subprocess


def _sanitize_text(text: str, max_len: int = 140) -> str:
    cleaned = re.sub(r'["\\`\n\r\t]', " ", text)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:max_len]


class DesktopAlertNotifier:
    """
    Dispatches native OS desktop notifications (macOS Notification Center via `/usr/bin/osascript`
    or Linux `notify-send`) when a developer or AI coding agent introduces a security weakness.
    """

    def __init__(self, enabled: bool = True) -> None:
        env_disabled = os.environ.get("AEGIS_DISABLE_DESKTOP_NOTIFY", "0") == "1"
        self.enabled = enabled and not env_disabled
        self._system = platform.system()

    def send_alert(self, title: str, subtitle: str, message: str, sound: bool = True) -> bool:
        if not self.enabled:
            return False

        safe_title = _sanitize_text(title, 60)
        safe_sub = _sanitize_text(subtitle, 70)
        safe_msg = _sanitize_text(message, 150)

        try:
            if self._system == "Darwin" and os.path.exists("/usr/bin/osascript"):
                sound_clause = ' sound name "Ping"' if sound else ""
                apple_script = (
                    f'display notification "{safe_msg}" '
                    f'with title "{safe_title}" '
                    f'subtitle "{safe_sub}"{sound_clause}'
                )
                subprocess.run(
                    ["/usr/bin/osascript", "-e", apple_script],
                    shell=False,
                    env={"PATH": "/usr/bin:/bin"},
                    capture_output=True,
                    timeout=3,
                    check=False,
                )
                return True

            if self._system == "Linux" and os.path.exists("/usr/bin/notify-send"):
                subprocess.run(
                    ["/usr/bin/notify-send", "-u", "critical", f"{safe_title}: {safe_sub}", safe_msg],
                    shell=False,
                    env={"PATH": "/usr/bin:/bin"},
                    capture_output=True,
                    timeout=3,
                    check=False,
                )
                return True
        except Exception:
            return False
        return False
