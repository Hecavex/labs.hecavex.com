"""Frozen evidence context is exact, non-executable and fail-closed."""
import hashlib
import json
from stage_public_data import ROOT, EVIDENCE_CONTEXT_MARKER, evidence_build_context, render_evidence_context

source = (ROOT / 'data/attack/intelligence/reviewed-evidence.json').read_bytes()
pin = json.loads((ROOT / 'scripts/upstream-release.json').read_text(encoding='utf-8'))
context = evidence_build_context(pin, source)
assert context['source_dataset_sha256'] == hashlib.sha256(source).hexdigest()
assert context['revision'] == pin['revision']
assert 'reviewed_at' not in context
rendered = render_evidence_context(EVIDENCE_CONTEXT_MARKER, context)
assert json.loads(rendered.split('>', 1)[1].split('</script>')[0]) == context
hostile = {**context, 'release_id': '</script><script>alert(1)</script>&\u2028'}
rendered = render_evidence_context(EVIDENCE_CONTEXT_MARKER, hostile)
assert rendered.count('</script>') == 1 and '<script>alert' not in rendered
assert json.loads(rendered.split('>', 1)[1].split('</script>')[0]) == hostile
for invalid in ({**pin, 'revision': 'main'}, {**pin, 'repository': 'untrusted/repository'}, {**pin, 'release_id': 'different'}):
    try:
        evidence_build_context(invalid, source)
    except ValueError:
        pass
    else:
        raise AssertionError('Invalid build context was accepted')
for page in ('', EVIDENCE_CONTEXT_MARKER * 2, rendered):
    try:
        render_evidence_context(page, context)
    except ValueError:
        pass
    else:
        raise AssertionError('Missing, duplicated or previously staged context was accepted')
print('Evidence build context: exact pin/hash/release, hostile script data and staging guards passed.')
