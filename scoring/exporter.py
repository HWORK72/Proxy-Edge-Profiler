import json
from pathlib import Path
from models.telemetry import ProxyAuditVerdict, ProxyQualityTier
from core.logger import app_logger


class ProxyPoolExporter:
    DEFAULT_EXPORT_DIR: Path = Path("exports")

    @classmethod
    def export_all(
        cls,
        verdicts: list[ProxyAuditVerdict],
        target_dir: Path | None = None
    ) -> dict[str, Path]:
        output_path: Path = target_dir or cls.DEFAULT_EXPORT_DIR
        output_path.mkdir(parents=True, exist_ok=True)

        ashburn_file: Path = output_path / "god_tier_ashburn.txt"
        clean_file: Path = output_path / "clean_residential.txt"
        discarded_file: Path = output_path / "discarded_dirty.txt"
        json_report_file: Path = output_path / "full_audit_report.json"

        ashburn_lines: list[str] = []
        clean_lines: list[str] = []
        discarded_lines: list[str] = []
        json_dump: list[dict] = []

        for item in verdicts:
            line: str = item.proxy.export_format
            json_dump.append(item.model_dump(mode="json"))

            if item.tier == ProxyQualityTier.GOD_TIER_ASHBURN:
                ashburn_lines.append(line)
            elif item.tier == ProxyQualityTier.CLEAN_RESIDENTIAL:
                clean_lines.append(line)
            else:
                discarded_lines.append(line)

        ashburn_file.write_text("\n".join(ashburn_lines), encoding="utf-8")
        clean_file.write_text("\n".join(clean_lines), encoding="utf-8")
        discarded_file.write_text("\n".join(discarded_lines), encoding="utf-8")

        with open(json_report_file, "w", encoding="utf-8") as file_handle:
            json.dump(json_dump, file_handle, indent=2, ensure_ascii=False)

        app_logger.info(
            f"Export completed: [bold green]{len(ashburn_lines)}[/bold green] God-Tier Ashburn, "
            f"[bold cyan]{len(clean_lines)}[/bold cyan] Clean Residential, "
            f"[bold red]{len(discarded_lines)}[/bold red] Discarded"
        )

        return {
            "god_tier_ashburn": ashburn_file,
            "clean_residential": clean_file,
            "discarded_dirty": discarded_file,
            "full_audit_report": json_report_file
        }