# LLM security-test sender

This small, dependency-free program periodically sends synthetic chat messages to an HTTP API. Each JSON body follows this shape:

```json
{
  "messages": [
    {"role": "user", "content": "..."}
  ],
  "metadata": {},
  "config": {}
}
```

The JSON and message content are generated afresh for every request. Each rule has five distinct message variants. Every five minutes, the default random mode selects one rule and one of its five variants, then sends one message. Use sequential mode to cycle through rules in order.

The catalog in `sender.py` contains 60 variants across the documented AI Defense rules, including Code Detection, Harassment, Hate Speech, PCI, PHI, PII, Prompt Injection, Profanity, Sexual Content & Exploitation, Social Division & Polarization, and Violence & Public Safety Threats. It also retains the supplied suspicious-URL example as an additional test. Rule labels are local metadata only; they are not added to the API body.

## Run locally

The supplied Cisco AI Defense endpoint is the default. Set `API_ENDPOINT` only when using a different endpoint:

```sh
AI_DEFENSE_API_KEY='your-key' \
POST_INTERVAL_SECONDS=300 \
python sender.py
```

For a single request:

```sh
AI_DEFENSE_API_KEY='your-key' python sender.py --once
```

Stop continuous mode with `Ctrl-C`. Messages are selected randomly by default. Set `MESSAGE_MODE=sequential` to cycle through rules in order.

## Configuration

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `API_ENDPOINT` | Cisco AI Defense chat inspection URL | POST URL override |
| `POST_INTERVAL_SECONDS` | `300` | Delay between requests |
| `HTTP_TIMEOUT_SECONDS` | `10` | Request timeout |
| `MESSAGE_MODE` | `random` | `sequential` or `random` |
| `MESSAGE_BATCH_SIZE` | `1` | Number of generated messages per request |
| `ALIGN_TO_HOUR` | `false` | Optional top-of-hour scheduling |
| `AI_DEFENSE_API_KEY` | none | Value for `X-Cisco-AI-Defense-API-Key` |
| `EXTRA_HEADERS_JSON` | none | Optional JSON object, e.g. `{"X-API-Key":"abc"}` |
| `LOG_LEVEL` | `INFO` | Python logging level |

The default headers match the Bruno request: `Accept: */*`, `Content-Type: application/json`, and `Connection: keep-alive`. Set `AI_DEFENSE_API_KEY` to send `X-Cisco-AI-Defense-API-Key`. Values in `EXTRA_HEADERS_JSON` override defaults and can supply additional headers. `ALIGN_TO_HOUR=true` or `--align-to-hour` can be used when a top-of-hour schedule is preferred.

## Run with Docker Compose

Set the API key in your shell or in a local `.env` file. The `.env` file is ignored by Git.

```sh
export AI_DEFENSE_API_KEY='your-key'
docker compose up -d --build
```

Compose builds the image, starts the sender, and restarts it unless manually stopped. The service uses the Cisco endpoint, random rule selection, one message per request, and a five-minute interval by default.

View logs:

```sh
docker compose logs -f llm-security-sender
```

Check health:

```sh
docker compose ps
```

Stop the service:

```sh
docker compose down
```

To override defaults, set environment variables before starting, for example:

```sh
MESSAGE_MODE=sequential \
MESSAGE_BATCH_SIZE=1 \
POST_INTERVAL_SECONDS=300 \
docker compose up -d --build
```

The Compose health check reports `healthy` only after an API request records HTTP `200`; startup, network errors, and non-200 responses report `unhealthy`. The container also overwrites `/app/health_status.json` after each attempt with the latest status and request payload, which is useful for checking the last test message sent.

## Test

```sh
python -m unittest discover -s tests -v
```
