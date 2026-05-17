# AoIP-Scope Test Suite

This directory contains automated test utilities and simulated test vectors to verify the correctness of the AoIP packet analyzer and decoding engine.

---

## 1. Simulated Test Vector Generator (`generate_test_pcaps.py`)

Rather than committing huge binary PCAP files to Git, we use [generate_test_pcaps.py](./generate_test_pcaps.py) to dynamically construct lightweight, precise test vectors.

### How to Generate Test PCAPs
Before running analysis test suites, generate the test vectors:
```bash
python tests/generate_test_pcaps.py
```

This command automatically generates the following simulated PCAP files under `tests/`:
- `test_dante_mdns.pcap`: Simulated Dante discovery packets (mDNS).
- `test_igmp_timeout.pcap`: Simulated IGMP membership report timeout sequences.
- `test_payload_errors.pcap`: 120ms of audio packets containing active sound (normal PCM), 2ms of clipped audio (max scale), and 12ms of absolute silence (all zeros).

---

## 2. Running Analysis Tests
To verify the engine's diagnostics using the generated test vectors:
```bash
python aoip_scope.py analyze tests/test_payload_errors.pcap
```
The analysis report will output detected audio clipping, silence periods, PTP grandmaster changes, and stream sample rates seamlessly in the console Rich UI.
