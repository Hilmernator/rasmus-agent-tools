"""Validate the collection without dependencies or network access."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    'asd-ste100', 'code-validation', 'diagnosing-bugs',
    'doubt-driven-development', 'local-security-review', 'ponytail',
    'prototype', 'qa-only', 'tdd', 'interview-me', 'review-bugs', 'security-audit',
}


def validate(root):
    manifest = json.loads((root / 'plugin.json').read_text())
    assert manifest['name'] == 'rasmus-agent-tools'
    assert re.fullmatch(r'\d+\.\d+\.\d+', manifest['version'])
    for host in ('.codex-plugin', '.claude-plugin'):
        overlay = json.loads((root / host / 'plugin.json').read_text())
        for key in ('name', 'version', 'description', 'author'):
            assert overlay[key] == manifest[key], f'Manifest mismatch: {host}: {key}'
    skills = list((root / 'skills').glob('*/SKILL.md'))
    assert {p.parent.name for p in skills} == EXPECTED
    assert len(list((root / 'skills').rglob('SKILL.md'))) == len(EXPECTED)
    for path in skills:
        text = path.read_text()
        assert text.startswith('---\n'), path
        header = text.split('---', 2)[1]
        assert re.search(r'^name: ' + re.escape(path.parent.name) + r'$', header, re.M), path
        assert re.search(r'^description: .+', header, re.M), path
    for path in root.rglob('*'):
        assert not path.is_symlink(), f'External dependency: {path}'
        if path.suffix != '.md':
            continue
        text = path.read_text()
        assert '/Users/' not in text, f'Machine-specific path: {path}'
        for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)', text):
            if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*:', target) or target.startswith('#'):
                continue
            target = target.split('#')[0]
            if target:
                assert (path.parent / target).exists(), f'Broken link: {path}: {target}'
    security = root / 'skills/local-security-review'
    assert (security / 'references/setup.md').is_file()
    for name in ('sast', 'sca', 'secrets'):
        assert (security / f'scripts/setup_{name}.py').is_file()
    audit = root / 'skills/security-audit'
    for name in ('report-schema.json', 'validate-findings.cjs', 'validate-coverage-ledger.cjs', 'LICENSE'):
        assert (audit / name).is_file(), f'Missing audit dependency: {name}'
    return len(skills)


if __name__ == '__main__':
    print(f'Package valid: {validate(ROOT)} skills, local links, manifest, and security setup dependencies.')
