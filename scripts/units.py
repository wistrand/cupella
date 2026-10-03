"""Functions ("units") of decompiled output and the calls between them.

Shared by model-leads.py, structure-leads.py, and lead-eval.py. A library module, not
a command.

  java_units(work, scopes)   methods in jadx/sources/<scope>. Calls come from the
                             dex bytecode (dex.py) when work/<name>/raw/ has dex
                             files: exact, including methods jadx failed on, with
                             lambdas and anonymous classes folded into the method
                             that creates them. Otherwise calls are guessed from
                             the text (by class, or by a name in at most two classes).
  dart_units(work, name)     functions of the app's own Dart package (blutter output),
                             calls resolved exactly from blutter's call annotations
  native_units(work)         functions in Ghidra output work/<name>/native/**/*.c,
                             calls and function-pointer references by name

Each Unit has: kind, id, where (path under work/ plus position, as printed in lead
files), file, start and end line (Java, Dart), name, cls, lines (body text), calls
(ids of called units), ext (names of called functions outside the units), refs (ids
of units whose address it takes; native only), addr (native, Dart), meta (Java:
the signature line; Dart: the dart-index Func), and for Java inner (the binary
name of the declaring class, e.g. "pkg.Outer$Inner") and bname (the method's name in
bytecode). Both come from jadx's "renamed from" comments where jadx renamed.
"""
import importlib.util
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))

JAVA_SIG = re.compile(r"^\s+(?:(?:public|private|protected|static|final|synchronized|abstract|native|default)\s+)*"
                      r"[\w<>\[\], .?]+\s+[\w$]+\([^;{]*\)\s*(?:throws [\w., ]+)?\s*\{\s*$")
JAVA_CTOR = re.compile(r"^\s+(?:public|private|protected)?\s*[\w$]+\([^;{]*\)\s*(?:throws [\w., ]+)?\s*\{\s*$")
JAVA_SKIP_FILE = re.compile(r"(^|/)(R|BuildConfig|.*_Factory|.*_MembersInjector|Hilt_.*|Dagger.*|"
                            r"ComposableSingletons.*|.*_Impl|.*_HiltModules.*|.*_GeneratedInjector|"
                            r".*\$\$ExternalSyntheticLambda\d+)\.java$")
JAVA_KEYWORDS = ("if", "for", "while", "switch", "catch", "synchronized", "try", "else", "do", "return", "new")
JAVA_NOT_CALLS = {"if", "for", "while", "switch", "catch", "synchronized", "return", "super", "this", "new"}
# methods a class gets run through when an instance is handed to a scheduler or thread
JAVA_CLASS = re.compile(r"^\s*(?:(?:public|private|protected|static|final|abstract|sealed|non-sealed|strictfp)\s+)*"
                        r"(?:class|interface|enum|@interface|record)\s+([\w$]+)")
JAVA_RENAMED = re.compile(r"/\* JADX INFO: renamed from: ([^,\s]+), reason")
JAVA_RUN = ("run", "call", "invoke", "handleMessage", "doWork", "onReceive", "accept", "apply", "invokeSuspend")


class Unit:
  __slots__ = ("kind", "id", "where", "file", "start", "end", "name", "cls", "lines", "calls", "ext", "refs", "addr", "meta", "inner", "bname")

  def __init__(self, kind, uid, where, file, start, end, name, cls, lines):
    self.kind, self.id, self.where, self.file = kind, uid, where, file
    self.start, self.end, self.name, self.cls, self.lines = start, end, name, cls, lines
    self.calls, self.ext, self.refs, self.addr, self.meta, self.inner, self.bname = set(), set(), set(), None, None, "", ""

  @property
  def text(self):
    return "\n".join(self.lines)


def load_script(filename):
  spec = importlib.util.spec_from_file_location(filename.replace("-", "_")[:-3], os.path.join(HERE, filename))
  mod = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(mod)
  return mod


def _java_file_units(path, rel):
  with open(path, errors="replace") as fh:
    lines = fh.read().split("\n")
  out = []
  cur, depth, start, name, sig = None, 0, 0, "?", ""
  cls = os.path.basename(rel)[:-5]
  pkg = os.path.dirname(rel).replace("/", ".")
  pkg = "" if pkg == "defpackage" else pkg + "." if pkg else ""
  # brace depth of the file; nested classes [(name, depth at open, binary name)];
  # a pending "renamed from" comment applies to the next declaration
  fdepth, stack, pending, bname = 0, [], None, ""
  for i, line in enumerate(lines):
    if "@Metadata" in line or line.lstrip().startswith("import "):
      continue
    before = fdepth
    fdepth += line.count("{") - line.count("}")
    if cur is None:
      rm = JAVA_RENAMED.search(line)
      if rm:
        pending = rm.group(1)
        continue
      cm = JAVA_CLASS.match(line)
      if cm and "{" in line:
        binary = pending or ("%s$%s" % (stack[-1][2], cm.group(1)) if stack else pkg + cm.group(1))
        stack.append((cm.group(1), before, binary))
        pending = None
      while stack and fdepth <= stack[-1][1]:
        stack.pop()
    if cur is None:
      s = line.strip()
      if (JAVA_SIG.match(line) or JAVA_CTOR.match(line)) and not s.startswith(JAVA_KEYWORDS):
        m = re.search(r"([\w$]+)\(", s)
        cur, depth, start, sig = [line], line.count("{") - line.count("}"), i, s
        name = m.group(1) if m else "?"
        bname, pending = pending or name, None
        if depth <= 0:
          cur = None
      elif s.endswith(";"):
        pending = None
      continue
    cur.append(line)
    depth += line.count("{") - line.count("}")
    if depth <= 0:
      u = Unit("java", "java:%s::%s@%d" % (rel[:-5], name, start + 1),
               "jadx/sources/%s:%d %s()" % (rel, start + 1, name), "jadx/sources/" + rel,
               start + 1, i + 1, name, cls, [x[:200] for x in cur])
      u.meta = sig  # the signature line, for filters
      u.inner = stack[-1][2] if stack else pkg + cls
      u.bname = bname
      out.append(u)
      cur = None
  return out


def java_units(work, scopes):
  base = os.path.join(work, "jadx", "sources")
  units, seen = [], set()
  for scope in scopes:
    for dp, dn, fn in os.walk(os.path.join(base, scope)):
      dn.sort()
      for f in sorted(fn):
        path = os.path.join(dp, f)
        rel = os.path.relpath(path, base)
        if not f.endswith(".java") or JAVA_SKIP_FILE.search(rel) or rel in seen:
          continue
        seen.add(rel)
        units.extend(_java_file_units(path, rel))
  if _java_calls_from_dex(work, scopes, units):
    return units
  by_cls_name, by_name, by_cls = {}, {}, {}
  for u in units:
    by_cls_name.setdefault((u.cls, u.name), []).append(u)
    by_name.setdefault(u.name, set()).add(u.cls)
    by_cls.setdefault(u.cls, []).append(u)
  for u in units:
    body = u.text
    for m in re.finditer(r"(?:\b([A-Za-z_$][\w$]*)\s*\.\s*)?\b([A-Za-z_$][\w$]*)\s*\(", body):
      qual, name = m.group(1), m.group(2)
      if name in JAVA_NOT_CALLS:
        continue
      prefix = body[max(0, m.start() - 4):m.start()]
      if prefix.endswith("new "):
        # new X(...): the constructor, and the methods X runs as a task or callback
        for t in by_cls.get(name, ()):
          if t.name in (name,) + JAVA_RUN:
            u.calls.add(t.id)
        continue
      targets = []
      if qual and qual in by_cls:
        targets = by_cls_name.get((qual, name), [])
      elif not qual or qual == "this":
        targets = by_cls_name.get((u.cls, name), [])
      if not targets and name in by_name and len(by_name[name]) <= 2 and len(name) > 2:
        targets = [t for c in by_name[name] for t in by_cls_name[(c, name)]]
      if targets:
        u.calls.update(t.id for t in targets if t is not u)
      else:
        u.ext.add("%s.%s" % (qual, name) if qual else name)
  return units


def _param_count(sig):
  m = re.search(r"\((.*)\)", sig)
  if not m or not m.group(1).strip():
    return 0
  depth, n = 0, 1
  for ch in m.group(1):
    if ch == "<":
      depth += 1
    elif ch == ">":
      depth -= 1
    elif ch == "," and depth == 0:
      n += 1
  return n


def _java_name(desc):
  return desc[1:-1].replace("/", ".") if desc.startswith("L") else desc


DEX_INDEX = {}  # work dir -> (dex methods, hierarchy, units_for, dispatch), set by java_units


def _java_calls_from_dex(work, scopes, units):
  """Fill calls and ext of Java units from bytecode. False when there is no dex."""
  raw = os.path.join(work, "raw")
  paths = sorted(os.path.join(raw, f) for f in os.listdir(raw)
                 if re.match(r"classes\d*\.dex$", f) and os.path.isfile(os.path.join(raw, f))) if os.path.isdir(raw) else []
  if not paths:
    return False
  import dex
  prefixes = tuple("L" + ("" if sc in (".", "defpackage") else sc.strip("/") + "/") for sc in scopes)
  default_pkg = "defpackage" in scopes or "." in scopes

  def in_scope(desc):
    if desc.startswith(prefixes) and (desc.count("/") > 0 or default_pkg):
      return True
    return default_pkg and "/" not in desc

  methods, hier = dex.load(paths, in_scope)
  sig_of = lambda key: key.split("->", 1)[1]
  by_sig = {}
  for key, m in methods.items():
    by_sig.setdefault(sig_of(key), []).append(key)

  def ancestors(cls):
    seen, todo = set(), [cls]
    while todo:
      c = todo.pop()
      sup, ifs = hier.get(c, (None, []))
      for x in ([sup] if sup else []) + ifs:
        if x not in seen:
          seen.add(x)
          todo.append(x)
    return seen

  anc = {c: ancestors(c) for c in hier}

  def dispatch(key):
    """the method keys a call to key can run: the definition up the superclass chain,
    and for abstract or interface methods declared in scope their implementations"""
    cls, sig = key.split("->", 1)
    c, defined = cls, None
    while c and c in hier:
      k = "%s->%s" % (c, sig)
      if k in methods:
        defined = k
        break
      c = hier[c][0]
    out = [defined] if defined and methods[defined].code else []
    if not out and cls in hier:
      # an abstract method the app declares: its implementations, unless there are so
      # many that the call says nothing about which one runs
      impl = [k for k in by_sig.get(sig, ()) if methods[k].code and cls in anc.get(methods[k].cls, ())]
      out = impl if len(impl) <= 8 else []
    return out or [key]

  by_place, ctor_name = {}, {}
  for u in units:
    by_place.setdefault((u.inner, u.bname), []).append(u)
    if u.bname == u.name and u.meta and re.match(r"^(?:(?:public|private|protected)\s+)?%s\(" % re.escape(u.name), u.meta):
      ctor_name[u.inner] = u.name

  def units_for(key):
    m = methods.get(key)
    if m is None:
      return []
    binary = m.cls[1:-1].replace("/", ".")
    name = m.name
    if name == "<init>":
      name = ctor_name.get(binary, binary.split(".")[-1].split("$")[-1])
    cands = by_place.get((binary, name), [])
    if len(cands) > 1:
      same = [u for u in cands if _param_count(u.meta) == len(m.params)]
      cands = same or cands
    return cands

  # classes jadx shows inline (lambdas, anonymous classes) have no units: their
  # calls count for the method that creates or calls them
  by_cls = {}
  for key, m in methods.items():
    by_cls.setdefault(m.cls, []).append(key)

  def expand(key, seen, depth):
    """units and external APIs reached from method key, folding in methods without units"""
    found, ext = set(), set()
    m = methods.get(key)
    if m is None or depth > 4:
      return found, ext
    todo = [k for t in m.invokes for k in dispatch(t)]
    for t in m.news:
      if t in by_cls and not any(units_for(k) for k in by_cls[t]):
        # an inline class: its methods run on behalf of this one. An R8-merged lambda
        # class takes the lambda's number as a constructor argument (first or last) and
        # switches on it: follow only that case when a constant argument is a case label
        switched = [k for k in by_cls[t] if methods[k].cases]
        labels = {v for k in switched for v in methods[k].cases}
        picked = {v for c, vals in m.new_consts if c == t for v in vals if v in labels}
        if picked and switched:
          for k in by_cls[t]:
            if methods[k].cases:
              todo.extend(d for v in picked for c in methods[k].cases.get(v, ()) for d in dispatch(c))
            elif methods[k].name != "<init>":
              todo.append(k)
        else:
          todo.extend(by_cls[t])
      else:
        todo.extend(k for k in by_cls.get(t, ()) if methods[k].name in JAVA_RUN)
    for t in todo:
      if t in seen:
        continue
      seen.add(t)
      us = units_for(t)
      if us:
        found.update(x.id for x in us)
      elif t in methods:
        f2, e2 = expand(t, seen, depth + 1)
        found |= f2
        ext |= e2
      else:
        cls, rest = t.split("->", 1)
        ext.add("%s.%s" % (_java_name(cls), rest.split("(")[0]))
    return found, ext

  DEX_INDEX[work] = (methods, hier, units_for, dispatch)
  by_unit = {}
  for key in methods:
    for u in units_for(key):
      by_unit.setdefault(u.id, []).append(key)
  for u in units:
    for key in by_unit.get(u.id, ()):
      found, ext = expand(key, {key}, 0)
      u.calls |= found - {u.id}
      u.ext |= ext
  return True


def dart_units(work, name):
  if not os.path.isdir(os.path.join(work, "dart", "asm")):
    return []
  di = load_script("dart-index.py")
  pkgs = sorted(os.listdir(os.path.join(work, "dart", "asm")))
  app = di.app_package(name, pkgs)
  if app is None:
    return []
  funcs, _, _ = di.load(name, [app], keep_body=True)
  units, by_qual = [], {}
  for f in funcs:
    u = Unit("dart", "dart:%s" % f.qual, "dart/asm/%s:%d (0x%x) %s" % (f.file, f.line, f.addr, f.qual),
             "dart/asm/" + f.file, f.line, f.line, f.qual.split("::")[-1], f.qual.split("::")[0],
             [t for _a, t in f.body])
    u.addr, u.meta = f.addr, f  # meta: the dart-index Func
    units.append(u)
    by_qual.setdefault(f.qual, []).append(u)
  for u in units:
    for t in u.lines:
      m = di.CALL_TARGET.search(t)
      if not m:
        continue
      lib, qual = m.group(1), m.group(2).strip()
      if qual in by_qual and lib.startswith("package:%s/" % app):
        u.calls.update(x.id for x in by_qual[qual] if x is not u)
      else:
        u.ext.add("[%s] %s" % (lib, qual))
  return units


C_DECL = re.compile(r"^\s+(undefined\d*|int|uint|char|byte|bool|long|ushort|short|code|void|size_t|FILE|"
                    r"__pid_t|float|double|longlong|ulonglong) \*?\*?\w+( \[\d+\])?;$")
C_NOT_CALLS = {"if", "while", "for", "switch", "return", "sizeof", "do"}


def native_units(work):
  units = []
  nat = os.path.join(work, "native")
  for dp, dn, fn in os.walk(nat):
    dn.sort()
    for f in sorted(fn):
      if not f.endswith(".c"):
        continue
      rel = os.path.relpath(os.path.join(dp, f), work)
      with open(os.path.join(dp, f), errors="replace") as fh:
        text = fh.read()
      parts = re.split(r"(?m)^// ---- (\S+) @ (0x[0-9a-f]+).*$", text)
      here = {}
      line = parts[0].count("\n") + 1
      for i in range(1, len(parts), 3):
        name, addr, body = parts[i], parts[i + 1], parts[i + 2]
        lines = [x[:180] for x in body.split("\n") if x.strip() and not C_DECL.match(x)]
        # the body starts with the header's newline and runs to the next header; the id
        # keeps the ABI directory so one library built for several ABIs does not collide
        u = Unit("native", "native:%s:%s" % (os.path.relpath(os.path.join(dp, f), nat), name),
                 "%s (%s @ %s)" % (rel, name, addr), rel,
                 line, line + body.rstrip("\n").count("\n"), name, f, lines)
        u.addr = int(addr, 16)
        line += body.count("\n")
        here[name] = u
        units.append(u)
      for u in here.values():
        body = u.text
        for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", body):
          c = m.group(1)
          if c in here and here[c] is not u:
            u.calls.add(here[c].id)
          elif c not in here and c not in C_NOT_CALLS and not re.match(r"^(FUN|LAB|DAT|PTR|SUB|code|undefined\d*|"
                                                                        r"u?int|char|byte|bool|long|short|ushort|uint)", c):
            u.ext.add(c)
        for m in re.finditer(r"&(\w+)|\b(FUN_[0-9a-f]+|jni_\w+|init_\d+)\b(?!\s*\()", body):
          c = m.group(1) or m.group(2)
          if c in here and here[c] is not u:
            u.refs.add(here[c].id)
  return units


def callers_of(units):
  by_id = {u.id: u for u in units}
  callers = {u.id: set() for u in units}
  for u in units:
    for c in u.calls | u.refs:
      if c in callers:
        callers[c].add(u.id)
  return by_id, callers
