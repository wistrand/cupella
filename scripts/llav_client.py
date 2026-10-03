"""Client for a local llav model server, for scripts that run in the analysis container.

./cupella puts the container on an internal Docker network (no route beyond the host)
and sets LLAV_URL to http://host.docker.internal:<port>. The llav server on the host
must listen on that network's gateway address or 0.0.0.0, not only 127.0.0.1.

    import llav_client
    model = llav_client.model_id()
    scores = llav_client.ask(text, {"q1": {"type": "noul", "instructions": "..."}})

Without LLAV_URL (outside the container) the default is http://127.0.0.1:8080.
LLAV_API_KEY, when set, is sent as a bearer token (llav --api-key, or a remote server).
Standard library only.
"""
import http.client
import json
import os
import urllib.parse


class LlavError(Exception):
  pass


def where():
  return os.environ.get("LLAV_URL", "http://127.0.0.1:8080")


def _request(method, path, body=None, timeout=300):
  try:
    u = urllib.parse.urlparse(where())
    if u.scheme == "https":
      conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=timeout)
    else:
      conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
    headers = {"Connection": "close"}
    if body is not None:
      headers["Content-Type"] = "application/json"
    if os.environ.get("LLAV_API_KEY"):
      headers["Authorization"] = "Bearer " + os.environ["LLAV_API_KEY"]
    conn.request(method, u.path.rstrip("/") + path, body=body, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
  except (OSError, http.client.HTTPException) as ex:
    raise LlavError("cannot reach llav at %s: %s" % (where(), ex))
  if resp.status != 200:
    raise LlavError("llav answered HTTP %d: %s" % (resp.status, data[:200].decode("utf-8", "replace")))
  try:
    return json.loads(data)
  except ValueError as ex:
    raise LlavError("llav sent a reply that is not JSON: %s" % ex)


def model_id():
  d = _request("GET", "/v1/models", timeout=15)
  try:
    return d["data"][0]["id"]
  except (KeyError, IndexError, TypeError):
    raise LlavError("unexpected /v1/models reply")


def ask(state, questions, model="llav-latest"):
  """questions: {id: {"type": "noul"|"choice"|"score", "instructions": ..., "criteria": ...}}.
  Returns the server's answers object: {id: {"noul": p} | {"choice": ..., "probabilities": ...} | ...}."""
  body = json.dumps({"state": state, "model": model, "questions": questions}).encode()
  d = _request("POST", "/v1/systemone", body=body)
  try:
    return d["answers"]
  except (KeyError, TypeError):
    raise LlavError("unexpected /v1/systemone reply")
