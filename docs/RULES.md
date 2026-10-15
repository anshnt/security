# Writing detection rules

Aegis evaluates two kinds of content rules:

1. **Aegis-Lite JSON rules.** These need no native dependency and always run. They live in
   `aegis/data/rules/*.json` (bundled) and `<data>/signatures/rules/*.json` (yours or downloaded). A rule
   in a later file overrides a bundled rule with the same id.
2. **YARA rules.** These run when `yara-python` is installed. They live in `aegis/data/yara/*.yar` and
   `<data>/signatures/yara/**/*.yar`; `aegis update` adds the YARA Forge core set. Use `meta: severity = "high"`
   and `description` so findings are labelled well.

## Aegis-Lite format

```json
{
  "id": "MY-001",
  "name": "Example dropper",
  "severity": "high",
  "category": "malware",
  "description": "What it is and why it matters.",
  "mitre": ["T1105"],
  "file_types": ["script", "text", "ps1"],
  "strings": {
    "a": {"text": "DownloadFile", "nocase": true},
    "b": {"regex": "https?://[^\\s]+\\.exe"},
    "c": {"hex": "4D 5A ?? 00"},
    "d": {"text": "evil", "wide": true}
  },
  "condition": "(a and b) or c or 2 of (a,b,d)"
}
```

* `file_types`: `any`, `pe`, `elf`, `macho`, `script`, `office`, `pdf`, `lnk`, `archive`, `text`, `other`,
  or bare extensions such as `ps1`.
* String modifiers: `nocase`, `wide` (also matches UTF-16LE), `ascii` (default true).
* Conditions support `and`, `or`, `not`, parentheses, `any`, `all`, `N of them`, `N of (a,b)`,
  `any of (...)` and `all of (...)`.
* Up to 32 MB of each file is inspected.

Test a rule against a sample:

```
aegis check-file sample.bin
```

Then add a unit test in `tests/` that builds the sample at runtime, so the repository never contains
live malware.
