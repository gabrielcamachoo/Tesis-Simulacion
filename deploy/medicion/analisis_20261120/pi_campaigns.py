"""Cobertura por campaña de las alertas de Kali en la Pi (medición H2, 19-11-2026).
Uso: python3 pi_campaigns.py ../resultados/h2_20261119/detect_live/alerts_pi_h2.jsonl.gz [salida.json]"""
import json, gzip, re, collections as C, sys
A = [json.loads(l) for l in gzip.open(sys.argv[1], 'rt')]
K = sorted([a for a in A if a['rule_id'] != 'NORMAL' and a.get('source', '').startswith('192.168.5.160')],
           key=lambda a: a['timestamp_utc'])
W = [('02:08:03', '02:28:08'), ('02:35:37', '02:56:08'), ('03:07:46', '03:28:08')]
def rep(a):
    t = a['timestamp_utc'][11:19]
    return next((i for i, (x, y) in enumerate(W, 1) if x <= t <= y), None)
def key(a):
    m = re.match(r'ANOM-(A\d\d)', a.get('message_control_id') or '')
    return m.group(1) if m else (a.get('message_control_id') or 'N/A')[:8]
keys = [key(a) for a in K]
# inicio de campaña: primer mensaje de preparación (DUP-SEED / N/A) que precede a un bloque nuevo de A15
starts = []
for i, k in enumerate(keys):
    if k == 'A15' and (i == 0 or keys[i - 1] != 'A15'):
        j = i
        while j > 0 and keys[j - 1] in ('DUP-SEED', 'N/A') and (not starts or j - 1 > starts[-1]):
            j -= 1
        starts.append(j)
camps = [K[s:e] for s, e in zip(starts, starts[1:] + [len(K)])]
pre = K[:starts[0]]
EXP = {  # escenario: (clave del MSH-10 con que aparece la alerta, regla esperada)
    'A01': ('A01', 'R-ID-001'), 'A02': ('DUP-SEED', 'R-SEQ-001'), 'A03': ('DUP-SEED', 'R-SEQ-002'),
    'A04': ('A04', 'R-TIME-001'), 'A05': ('N/A', 'R-MLLP-001:incompleta'), 'A06': ('N/A', 'R-MLLP-001:antes'),
    'A07': ('N/A', 'R-HL7-001'), 'A08': ('A08', 'R-HL7-003'), 'A09': ('A09', 'R-HL7-002'),
    'A10': ('A10', 'R-OBX-003'), 'A11': ('A11', 'R-OBX-002'), 'A12': ('A12', 'R-TIME-002'),
    'A13': ('A13', 'R-TIME-002'), 'A15': ('A15', 'R-MLLP-001'), 'A16': ('A16', 'R-ID-001')}
def tag(a):
    r = a['rule_id']
    if r == 'R-MLLP-001' and key(a) == 'N/A':
        r += ':incompleta' if 'incompleta' in a['reason'] else ':antes' if 'antes del inicio' in a['reason'] else ':otro'
    return (key(a), r)
hit = C.Counter(); full = 0
for c in camps:
    pairs = {tag(a) for a in c}
    ok = [s for s, pr in EXP.items() if pr in pairs]
    hit.update(ok); full += len(ok) == len(EXP)
n = len(camps)
out = {
    'alertas_kali': len(K), 'antes_de_la_primera_campana': len(pre),
    'campanas': n, 'por_repeticion': dict(sorted(C.Counter(rep(c[0]) for c in camps).items())),
    'alertas_por_campana': [min(map(len, camps)), round(sum(map(len, camps)) / n, 1), max(map(len, camps))],
    'cobertura_regla_esperada': {s: f'{hit[s]}/{n}' for s in EXP},
    'campanas_con_todas_las_reglas_esperadas': full,
    'campanas_con_todas_salvo_A15': sum(1 for c in camps if all(EXP[s] in {tag(a) for a in c} for s in EXP if s != 'A15')),
    'reglas_que_disparo_A15': C.Counter(a['rule_id'] for a in K if key(a) == 'A15').most_common(),
    'R-NET-001_en_cada_campana': sum(any(a['rule_id'] == 'R-NET-001' for a in c) for c in camps),
}
print(json.dumps(out, indent=1, ensure_ascii=False))
if len(sys.argv) > 2:
    json.dump(out, open(sys.argv[2], 'w'), indent=1, ensure_ascii=False)
