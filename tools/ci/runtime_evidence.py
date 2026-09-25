"""Render recorded observations; never infer a cell result from a passing suite."""
import csv
import hashlib
import json
from pathlib import Path

PHASES = ('generation', 'deserialization', 'effect')
STATES = {'not-tested', 'verified', 'failed', 'expected-rejection', 'attempted', 'returned', 'threw', 'not-observed', 'skipped'}


def validate(data):
    if not isinstance(data, dict):
        raise ValueError('Runtime evidence must be an object')
    if data.get('schemaVersion') != 1 or data.get('complete') is not True:
        raise ValueError('No complete version-1 runtime evidence')
    if not isinstance(data.get('cells'), list) or not data['cells']:
        raise ValueError('Runtime evidence contains no cells')
    for cell in data['cells']:
        if not isinstance(cell, dict):
            raise ValueError('Runtime evidence cells must be objects')
        if not cell.get('module') or cell.get('kind') not in ('gadget', 'plugin'):
            raise ValueError('Invalid evidence cell identity')
        if any(cell.get(phase) not in STATES for phase in PHASES):
            raise ValueError('Unknown phase status')
    return data


def render(data, output):
    validate(data)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    document = json.loads(json.dumps(data))
    for ordinal, cell in enumerate(document['cells']):
        identity = [ordinal] + [cell.get(k) for k in ('kind', 'module', 'formatter', 'variant', 'minify', 'configuration', 'targetRuntime')]
        cell['id'] = hashlib.sha256(json.dumps(identity, separators=(',', ':')).encode()).hexdigest()[:20]
    (output / 'runtime-evidence.json').write_text(json.dumps(document, indent=2) + '\n', encoding='utf-8')
    fields = ['id', 'kind', 'module', 'formatter', 'variant', 'minify', 'configuration', 'targetRuntime', *PHASES, 'requirements', 'reason', 'source']
    # csv owns its line endings; Windows text translation would add a second CR.
    with (output / 'runtime-evidence.csv').open('w', encoding='utf-8', newline='') as rows:
        writer = csv.DictWriter(rows, fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(document['cells'])
    # No external resources. JSON stays data; all table values use textContent.
    payload = json.dumps(document, ensure_ascii=True).replace('<', '\\u003c').replace('&', '\\u0026')
    page = '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>YSoNet runtime evidence</title><style>body{font:16px system-ui;margin:2rem;color:#17212b}input,select{font:inherit;padding:.4rem;margin:.3rem}table{border-collapse:collapse;width:100%;font-size:14px}td,th{text-align:left;vertical-align:top;padding:.5rem;border-bottom:1px solid #ccd4dc}th{position:sticky;top:0;background:#eef3f7}pre{white-space:pre-wrap}a{color:#07549c}.verified{color:#17652c}.failed,.not-observed{color:#a02222}</style>
<h1>YSoNet runtime evidence</h1><p id="headline"></p><p><a href="runtime-evidence.json">Download JSON</a> · <a href="runtime-evidence.csv">Download CSV</a></p><details><summary>Build environment, prerequisites and provenance</summary><pre id="build"></pre></details>
<p>Results apply to this archive, environment and test configuration. Not tested is not a failure. A returned deserializer is not proof of the expected effect; a thrown reader can still trigger an effect. Source references identify test helpers.</p>
<label>Module or formatter <input id="query" type="search"></label><label>Phase <select id="phase"><option>effect</option><option>generation</option><option>deserialization</option></select></label><label>Status <select id="status"><option value="">All</option></select></label><p id="count" role="status"></p>
<table><thead><tr><th>Module / formatter</th><th>Variant / minify</th><th>Configuration / target</th><th>Generation</th><th>Deserialization</th><th>Effect</th><th>Requirements / reason / source</th></tr></thead><tbody id="rows"></tbody></table>
<script type="application/json" id="data">PAYLOAD</script><script>
const data=JSON.parse(document.getElementById('data').textContent), cells=data.cells;
const query=document.getElementById('query'), phase=document.getElementById('phase'), status=document.getElementById('status');
document.getElementById('headline').textContent=data.toolVersion+' · '+(data.tier??'focused')+' tier · Environment: '+data.verdict+' · '+(data.gatePassed===true?'Required gate passed':'Gate not verified');
document.getElementById('build').textContent=JSON.stringify({toolVersion:data.toolVersion,source:data.source,packageSha256:data.packageSha256,environment:data.environment,prerequisites:data.prerequisites,completedUtc:data.completedUtc,verdict:data.verdict,tier:data.tier,gatePassed:data.gatePassed,diagnosticSkips:data.diagnosticSkips},null,2);
for(const s of STATES){const o=document.createElement('option');o.value=s;o.textContent=s;status.append(o)}
function draw(){const filtered=cells.filter(c=>JSON.stringify(c).toLowerCase().includes(query.value.toLowerCase())&&(!status.value||c[phase.value]===status.value));const body=document.getElementById('rows');body.replaceChildren();for(const c of filtered){const tr=document.createElement('tr');tr.id=c.id;const values=[c.kind+': '+c.module+' / '+(c.formatter??'unspecified'),(c.variant??'unspecified')+' / '+(c.minify??'unspecified'),c.configuration+' / '+(c.targetRuntime??'unknown'),c.generation,c.deserialization,c.effect,(c.requirements??[]).join(', ')+'; '+(c.reason??'')+'; '+(c.source??'')];for(const v of values){const td=document.createElement('td');td.textContent=v;if(['verified','failed','not-observed'].includes(v))td.className=v;tr.append(td)}body.append(tr)}document.getElementById('count').textContent=filtered.length+' of '+cells.length+' observations/cells';}
for(const el of [query,phase,status])el.addEventListener('input',draw);draw();
</script></html>'''.replace('PAYLOAD', payload).replace('of STATES)', 'of ' + json.dumps(sorted(STATES)) + ')')
    (output / 'runtime-evidence.html').write_text(page, encoding='utf-8')
