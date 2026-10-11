import ipaddress
from enum import StrEnum
from pydantic import BaseModel, Field, field_validator, model_validator


class ProxyProtocol(StrEnum):
    HTTP = "http"
    HTTPS = "https"
    SOCKS5 = "socks5"
    SOCKS5H = "socks5h"


class ProxyRecord(BaseModel):
    host: str = Field(min_length=1)
    port: int = Field(ge=1, le=65535)
    username: str | None = Field(default=None)
    password: str | None = Field(default=None)
    protocol: ProxyProtocol = Field(default=ProxyProtocol.HTTP)

    @field_validator("host")
    @classmethod
    def validate_host_ip_or_fqdn(cls, value: str) -> str:
        cleaned: str = value.strip()
        try:
            ipaddress.ip_address(cleaned)
            return cleaned
        except ValueError:
            if "." in cleaned and not cleaned.endswith("."):
                return cleaned
            raise ValueError(f"Invalid host address: {value}")

    @classmethod
    def parse_raw_line(cls, raw_line: str, default_protocol: ProxyProtocol = ProxyProtocol.HTTP) -> "ProxyRecord":
        line: str = raw_line.strip()
        if not line:
            raise ValueError("Empty proxy string encountered")

        protocol: ProxyProtocol = default_protocol
        if "://" in line:
            scheme, rest = line.split("://", 1)
            try:
                protocol = ProxyProtocol(scheme.lower())
            except ValueError:
                protocol = default_protocol
            line = rest

        parts: list[str] = line.split(":")
        if len(parts) == 4:
            if "@" in parts[1]:
                user_part, host = parts[1].split("@", 1)
                return cls(
                    host=host,
                    port=int(parts[2]),
                    username=parts[0],
                    password=user_part,
                    protocol=protocol
                )
            return cls(
                host=parts[0],
                port=int(parts[1]),
                username=parts[2],
                password=parts[3],
                protocol=protocol
            )
        elif len(parts) == 2:
            return cls(
                host=parts[0],
                port=int(parts[1]),
                username=None,
                password=None,
                protocol=protocol
            )
        elif "@" in line:
            auth_part, host_port = line.split("@", 1)
            auth_subparts = auth_part.split(":", 1)
            user = auth_subparts[0]
            password = auth_subparts[1] if len(auth_subparts) > 1 else None
            host_port_subparts = host_port.split(":", 1)
            return cls(
                host=host_port_subparts[0],
                port=int(host_port_subparts[1]),
                username=user,
                password=password,
                protocol=protocol
            )

        raise ValueError(f"Unsupported proxy string pattern: {raw_line}")

    @property
    def export_format(self) -> str:
        if self.username and self.password:
            return f"{self.host}:{self.port}:{self.username}:{self.password}"
        return f"{self.host}:{self.port}"

    @property
    def connection_url(self) -> str:
        if self.username and self.password:
            return f"{self.protocol.value}://{self.username}:{self.password}@{self.host}:{self.port}"
        return f"{self.protocol.value}://{self.host}:{self.port}"