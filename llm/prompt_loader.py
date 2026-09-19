"""
llm/prompt_loader.py

Loads versioned prompt files from the prompts/ directory.
Prompts are plain text files — no templating engine, just string .format().

Directory layout:
    prompts/
        account-summary/
            v1.txt   ← system prompt for the account-summary task
            v2.txt   ← iterate and compare with run_evals.py
        outreach-draft/
            v1.txt
"""

from pathlib import Path

_PROMPTS_DIR = Path(__file__).parent.parent / "prompts"


def load(name: str, version: int = 1) -> str:
    """
    Load a prompt by name and version.

    Args:
        name:    subdirectory name under prompts/ (e.g. 'account-summary')
        version: integer version number (maps to v{n}.txt)

    Returns:
        The prompt text as a string.

    Raises:
        FileNotFoundError if the prompt file doesn't exist.
    """
    path = _PROMPTS_DIR / name / f"v{version}.txt"
    if not path.exists():
        available = sorted(_PROMPTS_DIR.glob(f"{name}/v*.txt"))
        hint = f"  Available: {[p.name for p in available]}" if available else ""
        raise FileNotFoundError(f"Prompt not found: {path}{hint}")
    return path.read_text(encoding="utf-8").strip()


def latest_version(name: str) -> int:
    """Return the highest version number available for a prompt name."""
    versions = sorted(_PROMPTS_DIR.glob(f"{name}/v*.txt"))
    if not versions:
        raise FileNotFoundError(f"No prompts found for '{name}'")
    return max(int(p.stem[1:]) for p in versions)
