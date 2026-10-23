import functools
import ipaddress
import re
import time
from typing import Any, Callable


def audit_logger(func: Callable[..., Any]) -> Callable[..., Any]:
    """
    Декоратор для аудита функций ИБ-анализа.
    Замеряет время выполнения, логирует обнаружение угроз и перехватывает ошибки.
    """
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        started_at = time.perf_counter()
        try:
            result = func(*args, **kwargs)
        except Exception as error:
            elapsed = time.perf_counter() - started_at
            print(
                f"[AUDIT] {func.__name__} failed after {elapsed:.4f}s: {error}"
            )
            return False

        if result is True or isinstance(result, SecurityEvent):
            elapsed = time.perf_counter() - started_at
            print(
                f"[AUDIT] Threat detected by {func.__name__} "
                f"after {elapsed:.4f}s: {result}"
            )
        return result

    return wrapper


class SecurityEvent:
    """Класс события безопасности ИБ."""

    def __init__(
        self,
        timestamp: str,
        source_ip: str,
        event_type: str,
        severity: int = 1,
    ) -> None:
        self.timestamp = timestamp
        self.source_ip = source_ip
        self.event_type = event_type
        self.severity = severity

    @property
    def severity(self) -> int:
        return self._severity

    @severity.setter
    def severity(self, value: int) -> None:
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 5:
            raise ValueError("Severity must be an integer between 1 and 5")
        self._severity = value

    @property
    def is_critical(self) -> bool:
        """Возвращает True, если уровень угрозы >= 4."""
        return self.severity >= 4

    @classmethod
    def from_syslog(cls, raw_line: str) -> "SecurityEvent":
        """Создает объект события из строки syslog."""
        match = re.search(
            r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
            r"\s+\[(?P<event_type>[^\]]+)\]"
            r"(?P<message>.*?)"
            r"\b(?P<source_ip>(?:\d{1,3}\.){3}\d{1,3})\b",
            raw_line,
        )
        if match is None:
            raise ValueError("Syslog line must contain a timestamp, event type, and IPv4 address")

        source_ip = str(ipaddress.IPv4Address(match.group("source_ip")))
        message = match.group("message").lower()
        if re.search(r"sqli|sql.?injection|attack|exploit|malware", message):
            severity = 5
        elif re.search(r"failed\s+login|login\s+failed|authentication\s+failure", message):
            severity = 3
        else:
            severity = 1

        return cls(
            timestamp=match.group("timestamp"),
            source_ip=source_ip,
            event_type=match.group("event_type").strip(),
            severity=severity,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecurityEvent":
        """Создает объект из словаря."""
        return cls(
            timestamp=data["timestamp"],
            source_ip=data["source_ip"],
            event_type=data["event_type"],
            severity=data.get("severity", 1),
        )

    def __repr__(self) -> str:
        return (
            f"SecurityEvent(ip='{self.source_ip}', type='{self.event_type}', "
            f"severity={self.severity})"
        )


class IPUtils:
    """Утилиты для работы с IPv4-адресами."""

    @staticmethod
    def is_private(ip: str) -> bool:
        """
        Проверяет частные диапазоны IPv4: RFC1918 и loopback.
        """
        address = ipaddress.IPv4Address(ip)
        private_networks = (
            ipaddress.IPv4Network("10.0.0.0/8"),
            ipaddress.IPv4Network("172.16.0.0/12"),
            ipaddress.IPv4Network("192.168.0.0/16"),
            ipaddress.IPv4Network("127.0.0.0/8"),
        )
        return any(address in network for network in private_networks)

    @staticmethod
    def mask_ip(ip: str) -> str:
        """Маскирует последний октет IPv4-адреса."""
        address = ipaddress.IPv4Address(ip)
        return f"{address.exploded.rsplit('.', 1)[0]}.***"


class BlacklistManager:
    """Менеджер заблокированных IP-адресов."""

    def __init__(self, initial_ips: list[str] | None = None) -> None:
        self._blocked_ips: set[str] = set(initial_ips) if initial_ips else set()

    def add_ip(self, ip: str) -> None:
        self._blocked_ips.add(ip)

    def remove_ip(self, ip: str) -> None:
        self._blocked_ips.discard(ip)

    def __contains__(self, ip: str) -> bool:
        return ip in self._blocked_ips

    def __len__(self) -> int:
        return len(self._blocked_ips)

    def __repr__(self) -> str:
        return f"BlacklistManager(blocked_count={len(self._blocked_ips)})"
