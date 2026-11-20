"""Diagnóstico del crecimiento de memoria del detector en vivo.

Repite en el PC los dos pcap que capturó detect_live en la Pi el 19-11-2026 y mide, a lo largo
del tráfico, el tamaño de las estructuras del motor y la memoria asignada (tracemalloc).
Uso: LAB_AUTHORIZED=YES [LIBERAR_SESIONES=1] python memdiag.py <repo> <salida.json> <pcap1> [<pcap2> ...]
Con LIBERAR_SESIONES=1 se libera el estado del motor de cada sesión cuando se cierra su flujo TCP
(prueba de la causa; no cambia el código del repositorio).
"""
import sys, os, json, time, tracemalloc, gc
from pathlib import Path

repo = Path(sys.argv[1]).resolve()
out_json = Path(sys.argv[2])
pcaps = sys.argv[3:]
sys.path.insert(0, str(repo))
os.chdir(repo)

tracemalloc.start(1)
import detect_live as dl
from run_experiment import write_lab_config

outdir = Path('/tmp/memdiag_out'); outdir.mkdir(exist_ok=True)
cfg = write_lab_config(outdir)
det = dl.LiveDetector(outdir, cfg, repo / 'baseline.yaml', repo / 'config' / 'rules.yaml',
                      label='memdiag', port=1550, anonymize=True, extra_allowed_ips=['192.168.5.114'])
eng = det.engine
if os.environ.get('LIBERAR_SESIONES') == '1':
    _orig_close = det._close_flow
    def _close_and_release(key, ts):
        fl = det.flows.get(key)
        _orig_close(key, ts)
        if fl is not None:
            eng.sessions.pop(f"live:{fl.idx}:{fl.src_ip}:{fl.src_port}", None)
    det._close_flow = _close_and_release

def sizes():
    ss = eng.sessions.values()
    return {
        'sesiones_motor': len(eng.sessions),
        'ids_por_sesion': sum(len(s.seen_control_ids) for s in ss),
        'hashes_por_sesion': sum(len(s.seen_content_hashes) for s in ss),
        'hashes_globales': len(eng.global_content_hashes),
        'ids_globales': len(eng.global_control_ids),
        'flujos_tcp_abiertos': len(det.flows),
    }

samples = []
state = {'n': 0, 'snap0': None, 'last_ts': None}
STEP = 20000

def on_header(linktype, snaplen):
    pass

def on_packet(ts, data):
    det.feed_packet(ts, data)
    state['n'] += 1
    state['last_ts'] = ts
    if state['n'] % STEP == 0:
        cur, peak = tracemalloc.get_traced_memory()
        samples.append({'paquetes': state['n'], 'ts_utc': time.strftime('%H:%M:%S', time.gmtime(ts)),
                        'tracemalloc_mb': round(cur / 2**20, 2), **sizes()})
        # instantánea de referencia al empezar la carga (primer ataque, 02:08 UTC)
        if state['snap0'] is None and time.gmtime(ts).tm_hour == 2 and time.gmtime(ts).tm_min >= 8:
            gc.collect(); state['snap0'] = tracemalloc.take_snapshot()

t0 = time.time()
for p in pcaps:
    with open(p, 'rb') as f:
        dl.read_pcap_stream(f, on_header, on_packet)
gc.collect()
cur, peak = tracemalloc.get_traced_memory()
samples.append({'paquetes': state['n'], 'ts_utc': time.strftime('%H:%M:%S', time.gmtime(state['last_ts'])),
                'tracemalloc_mb': round(cur / 2**20, 2), **sizes()})
snap1 = tracemalloc.take_snapshot()
top = []
for st in snap1.compare_to(state['snap0'], 'lineno')[:12]:
    fr = st.traceback[0]
    top.append({'archivo': os.path.relpath(fr.filename, repo) if str(repo) in fr.filename else fr.filename,
                'linea': fr.lineno, 'crecimiento_kb': round(st.size_diff / 1024, 1), 'bloques': st.count_diff})
s = det.summary(final=True)
res = {'pcaps': [os.path.basename(p) for p in pcaps], 'paquetes': state['n'], 'segundos_cpu': round(time.time() - t0, 1),
       'alertas_por_ip': {ip: sum(v.values()) for ip, v in s.get('alertas_por_ip_y_regla', {}).items()},
       'alertas_por_regla': s.get('alertas_por_regla'), 'muestras': samples, 'top_crecimiento': top}
json.dump(res, open(out_json, 'w'), indent=1, ensure_ascii=False)
print(json.dumps({k: res[k] for k in ('paquetes', 'segundos_cpu', 'alertas_por_ip')}, ensure_ascii=False))
print(json.dumps(samples[::max(1, len(samples) // 12)] + samples[-1:], ensure_ascii=False, indent=0))
print(json.dumps(top, ensure_ascii=False, indent=0))
