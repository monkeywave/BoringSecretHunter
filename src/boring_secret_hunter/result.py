"""Analysis result data structures."""

import json
from dataclasses import dataclass, field, asdict
from typing import List, Optional


@dataclass
class FunctionMatch:
    """A single matched function from the analysis."""

    label: str = ""
    ghidra_offset: str = ""
    ida_offset: str = ""
    byte_pattern: str = ""


@dataclass
class AnalysisResult:
    """Result from analyzing a single binary."""

    binary_name: str = ""
    binary_path: str = ""
    architecture: str = ""
    binary_type: str = ""
    tls_library_type: str = ""
    functions: List[FunctionMatch] = field(default_factory=list)
    success: bool = False
    error: Optional[str] = None
    raw_output: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


@dataclass
class BatchResult:
    """Result from analyzing multiple binaries."""

    results: List[AnalysisResult] = field(default_factory=list)
    total: int = 0
    successful: int = 0

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "successful": self.successful,
            "results": [r.to_dict() for r in self.results],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
