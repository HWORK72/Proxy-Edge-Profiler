import aiohttp
from models.telemetry import ASNVerificationResult
from core.logger import app_logger


class ASNValidator:
    QUERY_API_TEMPLATE: str = "https://ipinfo.io/{ip}/json"

    DATACENTER_ASN_KEYWORDS: set[str] = {
        "HETZNER", "OVH", "DIGITALOCEAN", "CHOOPA", "VULTR", "AMAZON",
        "AWS", "GOOGLE", "MICROSOFT", "AZURE", "LINODE", "AKAMAI",
        "FASTLY", "CLOUDFLARE", "DATACAMP", "M247", "COGENT", "LEASENAME",
        "HIVELOCITY", "CONTABO", "SERVERIUS", "SELECTEL", "QUADRANET",
        "EQUINIX", "INAP", "HOSTINGER", "NAMECHEAP", "RACKSPACE"
    }

    @classmethod
    async def verify_ip_asn(
        cls,
        ip_address: str,
        claimed_type: str = "Residential",
        timeout_seconds: float = 5.0
    ) -> ASNVerificationResult:
        query_url: str = cls.QUERY_API_TEMPLATE.format(ip=ip_address)

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(query_url, timeout=aiohttp.ClientTimeout(total=timeout_seconds)) as response:
                    if response.status == 200:
                        data = await response.json()
                        org_raw: str = data.get("org", "Unknown").upper()

                        asn_number: int | None = None
                        if org_raw.startswith("AS"):
                            raw_parts = org_raw.split(" ", 1)
                            asn_digits = "".join(filter(str.isdigit, raw_parts[0]))
                            if asn_digits:
                                asn_number = int(asn_digits)

                        is_datacenter: bool = any(keyword in org_raw for keyword in cls.DATACENTER_ASN_KEYWORDS)
                        actual_type: str = "Datacenter / Hosting" if is_datacenter else "Residential / ISP"

                        is_spoofed: bool = (claimed_type.lower() == "residential") and is_datacenter
                        fraud_penalty: float = 55.0 if is_spoofed else 0.0

                        return ASNVerificationResult(
                            asn_number=asn_number,
                            as_organization=org_raw,
                            claimed_type=claimed_type,
                            actual_type=actual_type,
                            is_spoofed_residential=is_spoofed,
                            fraud_penalty_score=fraud_penalty
                        )
        except Exception as error:
            app_logger.debug(f"ASN resolution error for {ip_address}: {error}")

        return ASNVerificationResult(
            asn_number=None,
            as_organization="Unresolved ASN",
            claimed_type=claimed_type,
            actual_type="Unverified",
            is_spoofed_residential=False,
            fraud_penalty_score=10.0
        )