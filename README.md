# LAD Collector

Self-contained log collector for the Log Anomaly Detector project. It
collects authorization, network, syslog, service, event-log and database
events on Linux and Windows, normalizes them into the shared event envelope,
redacts secrets, buffers them, and ships batches to the ingestion API.

## Layout

```text
collectors/
├── __init__.py
├── __main__.py              # python -m collectors
├── main.py                  # collector entry point
├── run.py                   # standalone launcher from inside this dir
├── core/                    # shared engine, classifier, config, runtime
├── linux/                   # journald + Linux file sources
├── windows/                 # Windows Event Log + file sources
├── app_adapters/            # app adapter interface + file tailer
├── tests/                   # dependency-free unittest suite
├── tools/                   # local mock ingestion API
├── docs/                    # source coverage + status
├── requirements.txt
├── .gitignore
└── var/                     # runtime output (git-ignored)
```

## Run

From the directory that contains `collectors/`:

```bash
python3 -m collectors
```

If this directory itself is the repository root, run it from inside:

```bash
python3 run.py
```

Configure the ingestion endpoint and token with environment variables:

```bash
LAD_COLLECTOR_ENDPOINT=http://localhost:8080/api/v1/events/batch \
LAD_COLLECTOR_TOKEN=your-token \
python3 -m collectors
```

## Tests

From the directory that contains `collectors/`:

```bash
python3 -m unittest discover -s collectors/tests -t . -v
```

If this directory itself is the repository root, run from inside:

```bash
python3 -m unittest discover -s tests -t . -v
```

## Local mock API

```bash
python3 -m collectors.tools.mock_receiver
```

The mock receiver writes batches to `collectors/var/received_events.jsonl`.

## Requirements

- Python 3.10+
- Linux: `systemd-python` and permission to read the journal
  (`systemd-journal`, `adm`, or root).
- Windows: `pywin32`; run as Administrator for the `Security` channel.

See `docs/COLLECTOR_SOURCES.md` for source coverage, host prerequisites, and
all configuration variables.
