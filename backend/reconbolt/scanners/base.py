"""Abstract base class for all scanner modules."""

from __future__ import annotations

import asyncio
import shutil
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Optional

from reconbolt.config import get_settings
from reconbolt.engine.events import EventEmitter, ScanPhase
from reconbolt.models.findings import BaseFinding
from reconbolt.models.scan import ScanConfig


class BaseScanner(ABC):
    """Interface that all scanner modules must implement.

    Each scanner:
    - Receives a ScanConfig and EventEmitter
    - Produces a list of typed findings
    - Reports progress via the event emitter
    - Can check for required dependencies before running
    """

    # Subclasses should set this to their corresponding ScanPhase
    phase: ScanPhase = ScanPhase.INITIALIZING

    def __init__(self, config: ScanConfig, emitter: EventEmitter) -> None:
        self.config = config
        self.emitter = emitter
        self.settings = get_settings()

    @abstractmethod
    async def scan(self, **kwargs: Any) -> list[BaseFinding]:
        """Execute the scan and return findings.

        This is the main entry point. Subclasses must implement this.
        """
        ...

    def check_dependencies(self) -> list[str]:
        """Check for required dependencies. Return list of missing ones.

        Override in subclasses that need external tools.
        """
        return []

    # --- Utility Methods ---

    @staticmethod
    def find_executable(name: str) -> Optional[str]:
        """Find an executable in PATH or common locations."""
        path = shutil.which(name)
        if path:
            return path

        common_locations = [
            Path.home() / ".local" / "bin",
            Path.home() / "go" / "bin",
            Path("/usr/local/bin"),
        ]
        for location in common_locations:
            exe_path = location / name
            if exe_path.is_file() and exe_path.stat().st_mode & 0o111:
                return str(exe_path)
        return None

    async def run_command(self, cmd: list[str], tool_name: str, timeout: Optional[int] = None) -> Optional[str]:
        """Run an external command asynchronously and return its stdout."""
        timeout = timeout or self.settings.cmd_timeout
        self.emitter.command(self.phase, f"$ {' '.join(cmd)}")

        try:
            process = await asyncio.to_thread(
                subprocess.run,
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
            )
            if process.returncode != 0:
                self.emitter.warning(
                    self.phase,
                    f"{tool_name} exited with code {process.returncode}: {process.stderr.strip()[:200]}",
                )
            return process.stdout

        except FileNotFoundError:
            self.emitter.error(self.phase, f"{tool_name} not found. Ensure it is installed and in PATH.")
        except subprocess.TimeoutExpired:
            self.emitter.error(self.phase, f"{tool_name} timed out after {timeout}s.")
        except Exception as e:
            self.emitter.error(self.phase, f"Error running {tool_name}: {e}")
        return None
