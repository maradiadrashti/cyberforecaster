# Integration Plan — ML Models into Live Capture Pipeline

> **STATUS: DESIGN ONLY — DO NOT IMPLEMENT**
> This plan is for review and approval before any code touches the existing
> capture pipeline files.

## Overview

Two ML models need to be integrated into the live capture pipeline:
1. **Flow Classifier** — runs on every flow in real-time (~1-2ms per prediction)
2. **Stage Forecaster** — runs periodically per host (~10ms per host, async)

---

## 1. Where predict_flow() Would Be Called

### File: `capture-service/capture_server.py`
### Location: Inside `_capture_loop()` → `process_packet()` → after flow aggregation

The exact insertion point is after the flow cache is updated:

```python
# EXISTING CODE (DO NOT MODIFY):
key = _build_flow_key(pkt)
if key:
    with flow_lock:
        if key in flow_cache:
            flow_cache[key]["packet_count"] += 1
            flow_cache[key]["byte_count"] += event["length"]
            flow_cache[key]["last_seen"] = event["timestamp"]
        else:
            flow_cache[key] = { ... }

# --- PROPOSED MINIMAL DIFF (flagged for review) ---
# After flow is aggregated, classify it:
if key and key in flow_cache:
    flow = flow_cache[key]
    # Lazy-load model on first call
    if not hasattr(process_packet, '_classifier_loaded'):
        try:
            from models.flow_classifier_infer import predict_flow
            process_packet._predict_flow = predict_flow
            process_packet._classifier_loaded = True
        except Exception:
            process_packet._classifier_loaded = True  # Don't retry

    if hasattr(process_packet, '_predict_flow'):
        try:
            label, confidence = process_packet._predict_flow(flow)
            flow['ml_label'] = label
            flow['ml_confidence'] = confidence
        except Exception:
            pass  # Never let ML failure break capture
```

### Minimal diff size: ~15 lines added inside `process_packet()`
### Risk: Near-zero — try/except wrapped, model load is lazy, capture continues
###            regardless of ML status.

---

## 2. How the Stage Forecaster Runs Per Host

### Location: New background task in `capture-server`

The stage forecaster should run as a periodic background task, NOT inline in
the packet processing path.

### Approach: Asyncio periodic task

```python
# NEW CODE (separate from existing capture logic):

import asyncio

_stage_forecaster = None

async def _stage_forecast_loop():
    """Periodically run stage forecaster per active host."""
    while True:
        try:
            await asyncio.sleep(5)  # Every 5 seconds
            
            # Lazy-load
            if _stage_forecaster is None:
                from models.stage_forecaster_infer import forecast_host
                _stage_forecaster = forecast_host
            
            # Get recent flows per host from flow_cache
            with flow_lock:
                host_flows = {}
                for flow in flow_cache.values():
                    src = flow.get('src_ip', '')
                    if src and src != 'unknown':
                        if src not in host_flows:
                            host_flows[src] = []
                        host_flows[src].append(flow)
            
            # Forecast each host (up to 20 most active)
            forecasts = {}
            for ip, flows in sorted(host_flows.items(),
                                     key=lambda x: len(x[1]),
                                     reverse=True)[:20]:
                recent = flows[-10:]  # Last 10 flows
                try:
                    forecast = _stage_forecaster(ip, recent)
                    forecasts[ip] = forecast
                except Exception:
                    pass
            
            # Broadcast forecasts to WebSocket clients
            if forecasts and _main_loop and not _main_loop.is_closed():
                msg = json.dumps({"type": "stage_forecasts", "data": forecasts})
                async def _send_forecasts(message):
                    for ws in list(connected_clients):
                        try:
                            await ws.send_text(message)
                        except Exception:
                            pass
                _main_loop.call_soon_threadsafe(
                    lambda m=msg: asyncio.ensure_future(
                        _send_forecasts(m), loop=_main_loop
                    )
                )
        except Exception as e:
            print(f"[StageForecast] Error: {e}")

@app.on_event("startup")
async def _start_forecast_loop():
    asyncio.create_task(_stage_forecast_loop())
```

### Why asyncio (not threading):
- The GRU model uses PyTorch which has GIL concerns with threading
- asyncio.sleep(5) yields to the event loop without blocking
- The flow_lock is only held briefly to snapshot the cache
- Inference on 20 hosts × 10ms = 200ms total, runs every 5s

### Does NOT block the event loop because:
- Model inference is fast (~10ms per host)
- We limit to 20 most active hosts
- Total computation: ~200ms every 5s = 4% CPU

---

## 3. Versioned Model File Naming Scheme

### Pattern: `<model_name>_v<version>.<ext>`

```
models/
├── flow_classifier_v1.joblib
├── flow_label_encoder_v1.joblib
├── flow_classifier_v1_meta.json
├── stage_forecaster_v1.pth
├── stage_forecaster_v1_meta.json
├── flow_classifier_infer.py      # Always latest
└── stage_forecaster_infer.py     # Always latest
```

### Hot-swap strategy:

1. **Model files are loaded lazily** (on first prediction request).
   To hot-swap:
   - Delete the old model files
   - Place new model files with incremented version
   - Set `_classifier_loaded = False` to force reload

2. **Metadata JSON** contains the version and compatibility info.
   The inference modules read metadata at load time.

3. **Backward compatibility:**
   - Old models remain as `_v<N>.joblib` until explicitly removed
   - The `flow_classifier_infer.py` always loads `v1` by default
   - To switch versions: update the path in `*_infer.py` or pass version as arg

4. **Rollback:** If new model has issues, replace with previous version files
   and trigger a reload. No server restart needed (just set loaded=False).

### Version increment criteria:
- Feature schema change → major version (v2)
- Hyperparameter change → minor version (v1.1)
- More training data only → patch version (v1.1)

---

## Summary of Touch Points

| File | Change | Lines | Risk |
|------|--------|-------|------|
| `capture_server.py` | Add ML classification after flow aggregation | ~15 | Very low (try/except) |
| `capture_server.py` | Add forecast background task | ~40 | Low (isolated task) |
| `capture_server.py` | Add startup hook for forecast loop | ~3 | None |

### What we DON'T change:
- Packet capture flow (_capture_loop, sniff, AsyncSniffer)
- Thread-safety patterns (_queue_put_on_loop, call_soon_threadsafe)
- WebSocket handling (ws/live, connected_clients)
- Flow aggregation (flow_cache, flow_lock)
- Event loop management (_main_loop, set_loop)

---

> **AWAITING REVIEW AND APPROVAL BEFORE IMPLEMENTATION**
