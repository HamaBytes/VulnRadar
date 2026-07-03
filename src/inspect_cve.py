import sys
from pathlib import Path

# Ensure project root is on sys.path so package imports work when running this file directly
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.config.database import init_db, db_session_ro
from src.config.config import Config
import src.models
# ensure specific model modules are loaded so SQLAlchemy registries resolve
import src.models.cvss_models
import src.models.epss
import src.models.osv
import src.models.exploit
import src.models.github_advisory
import src.models.vendor_advisory

from src.models.cve import Cve
import json

init_db()

cve_id = 1
with db_session_ro() as db:
    c = db.query(Cve).filter(Cve.id == cve_id).first()
    if not c:
        print(f"CVE id={cve_id} not found")
        raise SystemExit(1)

    out = c.to_dict()

    out['tags'] = [t.value for t in c.tags]
    out['descriptions'] = [{ 'lang': d.lang, 'value': d.value } for d in c.descriptions]
    out['cvss_v2_metrics'] = []
    for m in c.cvss_v2_metrics:
        d = None
        if m.cvss_data:
            d = {
                'version': m.cvss_data.version,
                'vector_string': m.cvss_data.vector_string,
                'base_score': float(m.cvss_data.base_score) if m.cvss_data.base_score is not None else None,
            }
        out['cvss_v2_metrics'].append({
            'source': m.source,
            'metric_type': m.metric_type,
            'base_severity': m.base_severity,
            'cvss_data': d,
        })

    out['cvss_v31_metrics'] = []
    try:
        for m in c.cvss_v31_metrics:
            d = None
            if m.cvss_data:
                d = {k: getattr(m.cvss_data, k) for k in ['version','vector_string','base_score','base_severity'] if hasattr(m.cvss_data, k)}
            out['cvss_v31_metrics'].append({'source': m.source, 'metric_type': m.metric_type, 'cvss_data': d})
    except Exception:
        out['cvss_v31_metrics'] = None

    out['cvss_v40_metrics'] = []
    try:
        for m in c.cvss_v40_metrics:
            d = None
            if m.cvss_data:
                d = {k: getattr(m.cvss_data, k) for k in ['version','vector_string','base_score','base_severity'] if hasattr(m.cvss_data, k)}
            out['cvss_v40_metrics'].append({'source': m.source, 'metric_type': m.metric_type, 'cvss_data': d})
    except Exception:
        out['cvss_v40_metrics'] = None

    out['weaknesses'] = []
    for w in c.weaknesses:
        out['weaknesses'].append({'source': w.source, 'type': w.weakness_type, 'descriptions': [{'lang': d.lang, 'value': d.value} for d in w.descriptions]})

    out['configurations'] = []
    for cfg in c.configurations:
        nodes = []
        for n in cfg.nodes:
            cpes = [ { 'criteria': cp.criteria, 'vulnerable': cp.vulnerable } for cp in n.cpe_matches ]
            nodes.append({'operator': n.operator, 'negate': n.negate, 'cpe_matches': cpes})
        out['configurations'].append({'nodes': nodes})

    out['references'] = [ {'url': r.url, 'source': r.source} for r in c.references ]
    out['epss'] = [ {'epss_score': float(e.epss_score) if e.epss_score is not None else None, 'percentile': float(e.percentile) if e.percentile is not None else None} for e in c.epss ]
    out['exploit_references'] = [ {'source': e.source, 'url': e.url, 'title': e.title} for e in c.exploit_references ]

    out['osv_records'] = []
    for o in c.osv_records:
        out['osv_records'].append({'osv_id': o.osv_id, 'summary': o.summary, 'severities': o.severities, 'references': [{'url': r.url, 'title': r.title} for r in o.references]})

    out['github_advisories'] = []
    for g in c.github_advisories:
        out['github_advisories'].append({'summary': g.summary, 'severity': g.severity, 'package_name': g.package_name, 'references': [{'url': r.url, 'source': r.source} for r in g.references]})

    out['vendor_advisories'] = []
    for v in c.vendor_advisories:
        out['vendor_advisories'].append({'vendor': v.vendor, 'is_available': v.is_available, 'sources': v.sources, 'details': v.details})

    print(json.dumps(out, indent=2, default=str))
