# HTTP/HTTPS Traffic Analyzer

A defensive traffic-analysis tool for authorized testing environments. Captures and analyzes HTTP/HTTPS traffic with passive WAF/CDN and anti-bot/CAPTCHA detection.

## Features

- **Request Explorer**: Full HTTP request/response metadata (headers, status, timing, redirects)
- **Cookie Analysis**: Track cookie lifecycle and relationships between requests
- **TLS/Encryption Metadata**: SNI, ALPN, cipher suite, certificate details (when intercepted)
- **WAF/CDN Detection**: Passive, evidence-based identification of services like Cloudflare, AWS CloudFront, Akamai, etc.
- **Anti-Bot/CAPTCHA Detection**: Identify challenge pages, browser verification, reCAPTCHA, etc.
- **Keep-Alive / Connection Analysis**: Track HTTP/2 multiplexing and connection reuse
- **Search & Filtering**: Global search across URLs, paths, headers, cookie names
- **Export**: JSON, CSV, HAR, and HTML report formats

## Safety Boundary

This tool **detects, does not bypass**. It:

- ✓ Identifies WAF/CDN services passively
- ✓ Flags anti-bot and CAPTCHA systems
- ✓ Shows TLS handshake metadata (SNI, cipher suite)
- ✗ Does **not** implement WAF bypass techniques
- ✗ Does **not** solve, automate, or defeat CAPTCHA
- ✗ Does **not** replay or extract authentication tokens
- ✗ Does **not** perform credential stuffing or brute-force

## Installation

### Requirements

- Python 3.9+
- Windows, macOS, or Linux

### Quick Start

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the application**:
   ```bash
   python main.py
   ```
   or on Windows:
   ```bash
   run.bat
   ```

3. **Configure your browser/app's proxy**:
   - HTTP Proxy: `127.0.0.1:8080`
   - HTTPS Proxy: `127.0.0.1:8080`

4. **(Optional) Enable HTTPS content visibility**:
   - For decrypted HTTPS traffic, install mitmproxy's CA certificate in your own device's trust store:
     - Location: `~/.mitmproxy/mitmproxy-ca-cert.pem` (or `%USERPROFILE%\.mitmproxy` on Windows)
     - Import into your OS/browser's trusted root CA store
   - Without this step, only TLS handshake metadata is visible (no decrypted content)

## Usage

### Running the GUI

```bash
python main.py [--port 8080]
```

### Running capture-only (headless)

```bash
python main.py --no-gui --port 8080
```

### Command-line options

- `--port PORT` — Local proxy port (default: 8080)
- `--no-gui` — Capture mode without UI (for scripting/CI)

## Project Structure

```
traffic_analyzer/
├── main.py                    # Entry point
├── requirements.txt           # Dependencies
├── run.bat                    # Windows launcher
├── README.md                  # This file
│
├── capture/
│   └── proxy_addon.py         # mitmproxy integration
├── parsers/
│   └── http_parser.py         # HTTP request/response normalization
├── cookies/
│   └── cookie_analyzer.py     # Cookie parsing & relationship tracking
├── tls/
│   └── tls_parser.py          # TLS metadata extraction
├── waf_detection/
│   └── detector.py            # WAF/CDN passive detection
├── antibot_detection/
│   └── detector.py            # Anti-bot/CAPTCHA passive detection
├── connection_analysis/
│   └── analyzer.py            # Keep-alive / multiplexing analysis
├── storage/
│   ├── redaction.py           # Redaction system (core privacy logic)
│   └── storage.py             # In-memory + SQLite persistence
├── exporters/
│   └── exporter.py            # JSON, CSV, HAR, HTML export
├── ui/
│   ├── main_window.py         # Main application window
│   ├── request_details.py     # Request Explorer tab
│   ├── cookie_view.py         # Cookie Analysis tab
│   ├── tls_view.py            # TLS/Encryption tab
│   ├── waf_view.py            # WAF/CDN Detection tab
│   ├── antibot_view.py        # Anti-Bot/CAPTCHA tab
│   ├── connection_view.py     # Keep-Alive Analysis tab
│   ├── flow_view.py           # Request Flow diagram
│   ├── search_filter.py       # Search & filtering bar
│   └── settings_dialog.py     # Redaction & privacy settings
└── tests/
    ├── test_http_parser.py
    ├── test_cookie_parser.py
    ├── test_waf_detection.py
    ├── test_antibot_detection.py
    ├── test_tls_parser.py
    └── test_redaction.py
```

## Running Tests

```bash
python -m pytest tests/
# or
python -m unittest discover tests/
```

## Redaction & Privacy

By default, this tool:

- **Redacts Authorization headers** — masked as `••••••••`
- **Redacts Cookie values** — masked by default
- **Withholds session tokens from storage** — cookies that look like session tokens (session, auth, jwt, etc.) are not persisted unless explicitly enabled in Settings

To change these defaults:
1. Open **Settings → Redaction & Privacy**
2. Uncheck boxes to expose sensitive values
3. (Only in authorized, controlled environments)

## Architecture Highlights

### Single Redaction Source of Truth

All sensitive-value decisions flow through `storage/redaction.py`. The UI, exporters, and storage layer all use this same `redact_headers()` and `redact_cookie_value()` logic so there's exactly one place that enforces "redact by default."

### Passive Detection, No Bypass

WAF/CDN and anti-bot detectors are pure functions that:
- Take already-captured headers/cookies as input
- Return structured `DetectionResult` objects with confidence scores and evidence
- Contain zero code for evading, bypassing, solving, or automating any system they detect

Trying to find a bypass technique in this codebase is futile by design — the functions don't exist.

### HTTPS Interception Model

- **Default (no CA install)**: TLS handshake metadata only (SNI, ALPN, cipher). Encrypted payload is never visible.
- **With CA install** (user explicitly places cert in their trust store): mitmproxy terminates TLS and decrypted headers/bodies are visible, same as any other local debugging proxy.

This model is enforced structurally: there is no code path that reaches decrypted content unless the user's own device trusts the proxy, which only happens by explicit action on their part.

### Event-Driven Architecture

- **mitmproxy thread** (background): Captures traffic, feeds events into a thread-safe queue
- **Qt thread** (main): Drains the queue on a 150ms timer, updates UI
- No blocking I/O on the main thread; proxy never waits for UI

## Example: Detecting Cloudflare + reCAPTCHA

1. User visits `example.com` through the proxy
2. Response headers include `server: cloudflare` and `cf-ray: ...`
3. WAF detector identifies Cloudflare at 87% confidence
4. Response body contains `<div class="g-recaptcha">`
5. Anti-bot detector identifies reCAPTCHA at 45% confidence
6. Both appear in the **WAF/CDN** and **Anti-Bot/CAPTCHA** tabs with evidence

User sees what systems are present. No attempt is made to bypass either.

## Limitations

- **Certificate pinning**: Pinned certificates will cause connection errors even with CA installed; tool shows the error, doesn't bypass it.
- **HSTS preload lists**: Enforced by the OS/browser, not this tool.
- **HTTP/3 / QUIC**: Limited support in mitmproxy; TLS metadata available but body interception may fail.
- **Streaming responses**: Large or streaming response bodies may not be fully captured depending on mitmproxy version.

## License

This tool is provided as-is for authorized testing in controlled environments only.

## Support

For issues, feature requests, or questions:
1. Review the **Help → About / Safety Boundary** dialog
2. Check test files for usage examples
3. Inspect module docstrings for implementation details
