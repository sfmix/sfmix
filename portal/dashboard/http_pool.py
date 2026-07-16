"""Shared, process-local pooled httpx clients for the dashboard's upstream REST
clients (Looking Glass, Alice-LG, Prometheus).

Each upstream previously opened a fresh ``httpx.Client`` — and thus a full
TCP+TLS handshake — on *every* request. A single dashboard render fans out to
several endpoints, so that meant a burst of handshakes from one source IP, which
under load surfaced as "_ssl.c:993: The handshake operation timed out". These
pooled clients keep connections alive, so the handshake is amortised across many
requests.

Scope of the pool
-----------------
An ``httpx.Client`` connection pool lives inside a single process and is never
shared across processes — a forked worker cannot share TLS/socket state. The
portal runs under gunicorn with 3 *sync* workers (each handles one request at a
time), so:

  * within a worker, sequential API calls reuse the same kept-alive connection;
  * each of the 3 workers keeps its own small pool, so aggregate idle
    connections to a backend are roughly ``3 x max_keepalive_connections``.

Clients here are created lazily on first use — i.e. *after* gunicorn has forked
its workers — so a pool is never inherited across a ``fork()`` (which would
corrupt the shared sockets). This is still a strict improvement over the old
per-request client even though it does not (and cannot) pool across workers.
"""

import threading

import httpx

# Sized for sync workers (concurrency 1 per process): a couple of kept-alive
# connections per backend per worker is plenty, and bounds the fleet-wide idle
# connection count.
_LIMITS = httpx.Limits(max_keepalive_connections=4, max_connections=8, keepalive_expiry=60.0)

# Transient transport failures worth one retry: a stale pooled connection or a
# momentarily-saturated front-end. Read timeouts are deliberately excluded — a
# genuinely slow backend must not be retried into double load — as are HTTP
# status errors (raised later by ``raise_for_status``).
RETRYABLE = (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout, httpx.RemoteProtocolError)

_clients: dict[str, httpx.Client] = {}
_lock = threading.Lock()


def pooled_client(name: str, timeout: httpx.Timeout) -> httpx.Client:
    """Return a process-local pooled ``httpx.Client``, created once per ``name``.

    ``name`` namespaces one client per upstream so their pools/timeouts stay
    independent. Thread-safe: httpx.Client may be shared across threads.
    """
    client = _clients.get(name)
    if client is None:
        with _lock:
            client = _clients.get(name)
            if client is None:
                client = httpx.Client(timeout=timeout, limits=_LIMITS)
                _clients[name] = client
    return client


def get_with_retry(client: httpx.Client, url: str, *, attempts: int = 2, **kwargs) -> httpx.Response:
    """GET ``url`` on ``client``, retrying only on transient transport errors.

    The caller still owns ``raise_for_status()`` / JSON parsing; only the
    transport-level ``RETRYABLE`` failures from the request itself are retried.
    """
    last_exc: Exception | None = None
    for _ in range(attempts):
        try:
            return client.get(url, **kwargs)
        except RETRYABLE as exc:
            last_exc = exc
    raise last_exc  # type: ignore[misc]
