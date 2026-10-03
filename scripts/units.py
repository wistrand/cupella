"""Functions ("units") of decompiled output and the calls between them.

Shared by model-leads.py, structure-leads.py, and lead-eval.py. A library module, not
a command.

  java_units(work, scopes)   methods in jadx/sources/<scope>. Calls come from the
                             dex bytecode (dex.py) when work/<name>/raw/ has dex
                             files (see "Java call graph" below). Otherwise calls
                             are guessed from the text (by class, or by a name in
                             at most two classes).
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

Java call graph (checked against androguard by callgraph-check.py):
  mapping   each function has one dex method: same class, bytecode name, and parameters
            (types compared by name; a constructor may hide leading arguments). Bridge
            and synthetic methods, and methods of classes jadx shows inside a function
            body, have no function: their code counts for the function that runs them.
  calls     what the function's own code calls: the method and, to IN_DEPTH levels, the
            methods without a function that it calls or whose class it creates, with a
            virtual call resolved to the definition, or to at most 8 implementations
            of an abstract method. For a created class that has functions, only its
            run, call, invoke, handleMessage, ... methods.
  far       {id: hops} functions reached only through methods of classes that have a
            source file outside the scanned scope (a library, or app code R8 moved),
            to OUT_DEPTH hops. Weaker than calls: use callees(u), which adds those
            within FAR_HOPS.
  async_    Runnables and Handlers held in a field and handed to a thread or looper.
  ext       APIs outside the dex index that the function's own code calls.
All traversals are breadth first: the result does not depend on the order of calls.
"""
import importlib.util
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))

JAVA_SIG = re.compile(r"^\s+(?:(?:public|private|protected|static|final|synchronized|abstract|native|default)\s+)*"
                      r"[\w$<>\[\], .?]+\s+[\w$]+\([^;{]*\)\s*(?:throws [\w$., ]+)?\s*\{\s*$")
JAVA_CTOR = re.compile(r"^\s+(?:public|private|protected)?\s*[\w$]+\([^;{]*\)\s*(?:throws [\w$., ]+)?\s*\{\s*$")
JAVA_SKIP_FILE = re.compile(r"(^|/)(R|BuildConfig|.*_Factory|.*_MembersInjector|Hilt_.*|Dagger.*|"
                            r"ComposableSingletons.*|.*_Impl|.*_HiltModules.*|.*_GeneratedInjector|"
                            r".*\$\$ExternalSyntheticLambda\d+)\.java$")
# a line that starts with one of these words is a statement, not a declaration (whole
# words: "double g() {" and a class named if0 are declarations; "synchronized" before a
# type is a modifier)
JAVA_STATEMENT = re.compile(r"^(?:if|for|while|switch|catch|try|else|do|return|new|throw)\b(?![$\w])")
JAVA_NOT_CALLS = {"if", "for", "while", "switch", "catch", "synchronized", "return", "super", "this", "new"}
# methods a class gets run through when an instance is handed to a scheduler or thread
JAVA_CLASS = re.compile(r"^\s*(?:(?:public|private|protected|static|final|abstract|sealed|non-sealed|strictfp)\s+)*"
                        r"(?:class|interface|enum|@interface|record)\s+([\w$]+)")
JAVA_RENAMED = re.compile(r"/\* JADX INFO: renamed from: ([^,\s*]+)")
JAVA_RUN = ("run", "call", "invoke", "handleMessage", "doWork", "onReceive", "accept", "apply", "invokeSuspend")
# calls that hand a Runnable, Callable, or Message to another thread or a looper
SCHEDULE = re.compile(r"->(post|postDelayed|postAtTime|postAtFrontOfQueue|postOnAnimation|sendMessage|"
                      r"sendMessageDelayed|sendMessageAtTime|sendMessageAtFrontOfQueue|sendEmptyMessage|"
                      r"sendEmptyMessageDelayed|sendEmptyMessageAtTime|execute|submit|schedule|"
                      r"scheduleAtFixedRate|scheduleWithFixedDelay|runOnUiThread)\(")
ASYNC_BASES = {"Ljava/lang/Runnable;", "Ljava/lang/Thread;", "Landroid/os/Handler;", "Landroid/os/Handler$Callback;",
               "Ljava/util/concurrent/Callable;", "Ljava/util/TimerTask;"}


class Unit:
  __slots__ = ("kind", "id", "where", "file", "start", "end", "name", "cls", "lines", "calls", "ext", "refs", "addr", "meta", "inner", "bname",
               "async_", "far")

  def __init__(self, kind, uid, where, file, start, end, name, cls, lines):
    self.kind, self.id, self.where, self.file = kind, uid, where, file
    self.start, self.end, self.name, self.cls, self.lines = start, end, name, cls, lines
    self.calls, self.ext, self.refs, self.addr, self.meta, self.inner, self.bname = set(), set(), set(), None, None, "", ""
    # Runnables and Handlers this function hands to another thread or a looper (Java):
    # kept apart from calls, so structure-leads.py's chains and budgets do not change
    self.async_ = set()
    # Java: functions reached only through code outside the scanned scope, id -> number
    # of method hops through that code (1 .. OUT_DEPTH)
    self.far = {}

  @property
  def text(self):
    return "\n".join(self.lines)


def load_script(filename):
  spec = importlib.util.spec_from_file_location(filename.replace("-", "_")[:-3], os.path.join(HERE, filename))
  mod = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(mod)
  return mod


JAVA_ANON = re.compile(r"\bnew [\w.$<>, ?\[\]]+\([^()]*\)\s*\{\s*// from class: ([\w.$]+)\s*$")
JAVA_LITERAL = re.compile(r'''"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|/\*.*?\*/|//.*$''')


def _java_code(line, in_comment):
  """(the line with string and char literals emptied and comments removed, whether a
  block comment is still open): what counts for braces and declarations"""
  if in_comment:
    end = line.find("*/")
    if end < 0:
      return "", True
    line = line[end + 2:]
  if '"' in line or "'" in line or "/" in line:
    line = JAVA_LITERAL.sub(lambda m: '""' if m.group(0)[0] == '"' else " ", line)
    start = line.find("/*")
    if start >= 0:
      return line[:start], True
  return line, False


def _java_file_units(path, rel):
  """The functions jadx shows in one source file, each with the class that declares it
  in bytecode. Not functions: synthetic and bridge methods (jadx marks them; their code
  counts for their callers) and methods of classes shown inside a function body (they
  are part of that function)."""
  with open(path, errors="replace", newline="") as fh:  # lines on \n only
    lines = fh.read().split("\n")
  out = []
  cur, depth, start, name, sig = None, 0, 0, "?", ""
  cls = os.path.basename(rel)[:-5]
  pkg = os.path.dirname(rel).replace("/", ".")
  pkg = "" if pkg == "defpackage" else pkg + "." if pkg else ""
  top = pkg + cls
  # brace depth of the file, counted outside literals and comments; nested classes
  # [(name, depth at open, binary name)]; a pending "renamed from" comment applies to the
  # next declaration; skip: brace depth inside a method that gets no function
  fdepth, stack, pending, bname, comment, skip = 0, [], None, "", False, 0
  for i, raw in enumerate(lines):
    if "@Metadata" in raw or raw.lstrip().startswith("import "):
      continue
    line, comment = _java_code(raw, comment)
    delta = line.count("{") - line.count("}")
    # low: the lowest depth within the line ("}, new X() {" closes one class and opens another)
    low = fdepth
    if "}" in line:
      d = fdepth
      for ch in line:
        if ch == "{":
          d += 1
        elif ch == "}":
          d -= 1
          low = min(low, d)
    fdepth += delta
    if cur is not None:
      cur.append(raw)
      depth += delta
      if depth <= 0:
        u = Unit("java", "java:%s::%s@%d" % (rel[:-5], name, start + 1),
                 "jadx/sources/%s:%d %s()" % (rel, start + 1, name), "jadx/sources/" + rel,
                 start + 1, i + 1, name, cls, [x[:200] for x in cur])
        u.meta = sig  # the signature line, for filters
        u.inner = stack[-1][2] if stack else top
        u.bname = bname
        out.append(u)
        cur = None
      continue
    if skip:
      skip = max(0, skip + delta)
      continue
    rm = JAVA_RENAMED.search(raw)
    if rm:
      pending = rm.group(1)
      continue
    while stack and low <= stack[-1][1]:
      stack.pop()
    # a class body opens at the line's last brace: it is closed when the depth is back at
    # the level before that brace
    cm = JAVA_CLASS.match(line)
    if cm and "{" in line:
      binary = pending or ("%s$%s" % (stack[-1][2], cm.group(1)) if stack else pkg + cm.group(1))
      stack.append((cm.group(1), fdepth - 1, binary))
      pending = None
    else:
      # an anonymous class in a field initializer, which jadx names in a comment
      # ("= new g() { // from class: a.b.pk0", nested ones with dots: a.b.Outer.1): its
      # methods belong to that class
      am = JAVA_ANON.search(raw)
      if am:
        binary = am.group(1)
        if binary.startswith(top + "."):
          binary = top + binary[len(top):].replace(".", "$")
        stack.append(("", fdepth - 1, binary))
    s = line.strip()
    if (JAVA_SIG.match(line) or JAVA_CTOR.match(line)) and not JAVA_STATEMENT.match(s):
      if "/* synthetic */" in raw or "/* bridge */" in raw:
        skip, pending = max(0, delta), None
        continue
      m = re.search(r"([\w$]+)\(", s)
      cur, depth, start, sig = [raw], delta, i, s
      name = m.group(1) if m else "?"
      bname, pending = pending or name, None
      if depth <= 0:
        cur = None
    elif s.endswith(";"):
      pending = None
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


PRIMITIVE = {"I": "int", "Z": "boolean", "B": "byte", "S": "short", "C": "char", "J": "long", "F": "float",
             "D": "double", "V": "void"}


JADX_CLASS = re.compile(r"^(?:Abstract|Interface|Enum)?C\d{4,}(?=[A-Za-z_$])")


def _java_type(desc):
  """a dex type descriptor as Java prints it in full: int, java.lang.String, pkg.Outer.Inner, byte[]"""
  dims = len(desc) - len(desc.lstrip("["))
  d = desc[dims:]
  return (PRIMITIVE.get(d) or d[1:-1].replace("/", ".").replace("$", ".")) + "[]" * dims


def _type_fit(shown, desc):
  """how well a type in a jadx signature names a dex type: 2 when jadx wrote it with a
  package or outer class and it matches (jadx does that where simple names collide), 1
  for a matching simple name, 0 otherwise (also a type variable or a class jadx renamed)"""
  full = _java_type(desc)
  # jadx renames classes with short or invalid names: a -> C0628a, AbstractC0626a, ...
  shown = ".".join(JADX_CLASS.sub("", part) or part for part in shown.replace("$", ".").split("."))
  if "." in shown:
    return 2 if full == shown or full.endswith("." + shown) else 0
  return 1 if full.rsplit(".", 1)[-1] == shown else 0


def _sig_params(sig):
  """parameter types in a jadx signature line as written (generics and annotations
  dropped), or None when the line has no parameter list"""
  i = sig.find("(")
  if i < 0:
    return None
  depth, angle, cur, parts = 0, 0, [], []
  for ch in sig[i + 1:]:
    if ch == ")" and depth == 0:
      break
    if ch in "([":
      depth += 1
    elif ch in ")]":
      depth -= 1
    elif ch == "<":
      angle += 1
    elif ch == ">":
      angle -= 1
    if ch == "," and depth == 0 and angle == 0:
      parts.append("".join(cur))
      cur = []
    elif angle == 0 and ch != ">":
      cur.append(ch)
  else:
    return None
  if "".join(cur).strip():
    parts.append("".join(cur))
  out = []
  for part in parts:
    part = re.sub(r"@[\w.]+(?:\([^)]*\))?", " ", part)
    toks = [t for t in part.split() if t != "final"]
    if len(toks) < 2:
      out.append("?")
      continue
    out.append("".join(toks[:-1]).replace("...", "[]"))
  return out


def _java_name(desc):
  return desc[1:-1].replace("/", ".") if desc.startswith("L") else desc


DEX_INDEX = {}  # work dir -> (dex methods, hierarchy, units_for, dispatch), set by java_units
GRAPH = {}      # work dir -> the graph's building blocks, for callgraph-check.py
IN_DEPTH = 4    # own code: methods without a function of their own, nested this deep
OUT_DEPTH = 1   # method hops through code outside the scope, recorded in Unit.far (callgraph-check.py
                # raises it to count what lies further)
FAR_HOPS = 1    # of those, the hops that count as calls for leads, chains, and maps


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

  by_cls = {}
  for key, m in methods.items():
    by_cls.setdefault(m.cls, []).append(key)

  # The class of a function as the dex names it. jadx names a nested class in its comments
  # with dots (a.b.Outer.1), and shows a local class (Outer$method$Name, Outer$1Name) as a
  # nested one (Outer$Name).
  def desc(binary):
    return "L%s;" % binary.replace(".", "/")

  local, fixed = {}, {}
  for c in by_cls:
    b = c[1:-1].replace("/", ".")
    if b.count("$") >= 2 or re.search(r"\$\d+[A-Za-z_]", b):
      top, name = b.split("$", 1)[0], re.sub(r"^\d+", "", b.rsplit("$", 1)[1])
      local.setdefault((top, name), []).append(b)
  for u in units:
    if desc(u.inner) in by_cls:
      continue
    if u.inner not in fixed:
      inner, found = u.inner, None
      while "." in inner and not found:
        head, _, tail = inner.rpartition(".")
        inner = head + "$" + tail
        found = inner if desc(inner) in by_cls else None
      if not found and "$" in u.inner:
        cands = local.get((u.inner.split("$", 1)[0], u.inner.rsplit("$", 1)[1]), ())
        found = cands[0] if len(cands) == 1 else None
      fixed[u.inner] = found or u.inner
    u.inner = fixed[u.inner]

  by_place, ctor_name, ctors = {}, {}, set()
  for u in units:
    by_place.setdefault((u.inner, u.bname), []).append(u)
    if u.bname == u.name and u.meta and re.match(r"^(?:(?:public|private|protected)\s+)?%s\(" % re.escape(u.name), u.meta):
      ctor_name[u.inner] = u.name
      ctors.add(u.id)
  sig_params = {}

  def params_of(u):
    """(parameter types, return type) as written in a function's signature line"""
    if u.id not in sig_params:
      sig = u.meta or ""
      head = re.sub(r"<[^()]*>", "", sig[:sig.find("(")]).split() if "(" in sig else []
      sig_params[u.id] = (_sig_params(sig), head[-2] if len(head) >= 2 else "")
    return sig_params[u.id]

  def candidates(key):
    """[(function, fit)] for dex method key: functions of the same class and bytecode name
    with as many parameters, and how well their parameter and return types fit. None for
    bridge and synthetic methods: jadx marks those, and they get no function. A
    constructor may have leading arguments jadx does not show; a class's only shown
    constructor fits its only constructor whatever the count."""
    m = methods[key]
    if m.flags & 0x1040:
      return []
    binary = m.cls[1:-1].replace("/", ".")
    if m.name == "<init>":
      cands = [u for u in by_place.get((binary, ctor_name.get(binary, "")), ()) if u.id in ctors]
    else:
      # a method named like its class (Lq$b;->b()) is not the constructor b()
      cands = [u for u in by_place.get((binary, m.name), ()) if u.id not in ctors]
    variants = [m.params]
    if m.name == "<init>":
      # leading arguments jadx may leave out, constructor by constructor: the outer
      # instance of an inner class, the name and ordinal of an enum constant
      if "$" in m.cls and m.params[:1] == [m.cls.rsplit("$", 1)[0] + ";"]:
        variants.append(m.params[1:])
      if m.params[:2] == ["Ljava/lang/String;", "I"]:
        variants.append(m.params[2:])
    out = []
    for u in cands:
      have, uret = params_of(u)
      fits = [1 + sum(_type_fit(a, b) for a, b in zip(have, params)) + _type_fit(uret, m.ret)
              for params in variants if have is not None and len(have) == len(params)]
      if fits:
        out.append((u, max(fits)))
    if not out and m.name == "<init>" and len(cands) == 1:
      out = [(cands[0], 0)]
    return out

  # one dex method per function and one function per dex method, best fit first; what is
  # left without a function (bridge and synthetic methods, overloads jadx does not show)
  # counts for its callers. Only equal fits stay shared.
  pairs = []
  for key, m in methods.items():
    if (m.cls[1:-1].replace("/", "."), m.name) in by_place or m.name == "<init>":
      pairs.extend((-fit, key, u.id, u) for u, fit in candidates(key))
  pairs.sort(key=lambda p: p[:3])
  unit_memo, key_fit, unit_fit = {}, {}, {}
  for nfit, key, uid, u in pairs:
    if key_fit.get(key, nfit) == nfit and unit_fit.get(uid, nfit) == nfit:
      key_fit[key] = unit_fit[uid] = nfit
      unit_memo.setdefault(key, []).append(u)

  def units_for(key):
    """the jadx functions of dex method key: empty for a method jadx shows no function for
    (abstract, bridge, synthetic, inlined into its user) or outside the dex index"""
    return unit_memo.get(key, ())

  has_units = {c: any(units_for(k) for k in ks) for c, ks in by_cls.items()}

  # A class without functions is either shown by jadx inside the function that uses it
  # (a lambda, an anonymous class, a synthetic class jadx wrote no file for), or it has
  # a source file of its own outside the scanned scope. Only the first kind is part of
  # a scanned function's own code.
  src = os.path.join(work, "jadx", "sources")
  scope_dirs = tuple("" if sc in (".", "") else sc.strip("/") + "/" for sc in scopes)
  outside_memo = {}

  def outside(cls):
    if cls not in outside_memo:
      res = False
      if not has_units.get(cls):
        parts = cls[1:-1].split("$")
        for n in range(len(parts), 0, -1):  # Outer$Inner$1: Outer$Inner$1.java, Outer$Inner.java, Outer.java
          name = "$".join(parts[:n])
          rel = (name if "/" in name else "defpackage/" + name) + ".java"
          if os.path.isfile(os.path.join(src, rel)):
            res = not rel.startswith(scope_dirs)
            break
      outside_memo[cls] = res
    return outside_memo[cls]

  def schedules(k):
    """a call that hands work to another thread or a looper (Thread.start only on a Thread)"""
    cls, rest = k.split("->", 1)
    if rest.startswith("start()"):
      return cls == "Ljava/lang/Thread;" or "Ljava/lang/Thread;" in anc.get(cls, ())
    return bool(SCHEDULE.search(k))

  succ_memo = {}

  def successors(key):
    """[(method key, class or None)]: what running dex method key runs. Its calls,
    resolved (class None), and for each class it creates or takes from a static field
    the methods that then run on its behalf (with that class):
    - a class without functions: all its methods. An R8-merged lambda class takes the
      lambda's number as a constructor argument (first or last) and switches on it: only
      the calls of that case, when a constant argument is a case label
    - a class with functions: its run, call, invoke, handleMessage, ... methods"""
    if key in succ_memo:
      return succ_memo[key]
    m = methods[key]
    out = [(k, None) for t in m.invokes for k in dispatch(t)]
    for t in m.news:
      if t not in by_cls:
        continue
      if not has_units[t]:
        switched = [k for k in by_cls[t] if methods[k].cases]
        labels = {v for k in switched for v in methods[k].cases}
        picked = {v for c, vals in m.new_consts if c == t for v in vals if v in labels}
        if picked and switched:
          for k in by_cls[t]:
            if methods[k].cases:
              out.extend((d, t) for v in sorted(picked) for c in methods[k].cases.get(v, ()) for d in dispatch(c))
            elif methods[k].name != "<init>":
              out.append((k, t))
        else:
          out.extend((k, t) for k in by_cls[t])
      else:
        out.extend((k, t) for k in by_cls[t] if methods[k].name in JAVA_RUN)
    succ_memo[key] = out
    return out

  def api(t):
    cls, rest = t.split("->", 1)
    return "%s.%s" % (_java_name(cls), rest.split("(")[0])

  def expand(key):
    """(direct, far, ext) for the function of dex method key.
    direct  functions its own code calls: the method and, to IN_DEPTH levels, the methods
            without a function of their own that it runs (code jadx shows inline)
    far     {function: hops} reached only through code outside the scope, to OUT_DEPTH
            method hops from the first outside method
    ext     APIs outside the dex index that its own code calls
    Breadth first in both parts, so the result does not depend on the order of calls."""
    direct, far, ext = set(), {}, set()
    seen, frontier, out = {key}, [key], []
    for _ in range(IN_DEPTH + 1):
      nxt = []
      for k in frontier:
        for t, via in successors(k):
          through = via is not None and outside(via)
          us = unit_memo.get(t, ())
          if us:
            if through:
              for x in us:
                far.setdefault(x.id, 1)
            else:
              direct.update(x.id for x in us)
          elif t in seen:
            continue
          elif t in methods:
            seen.add(t)
            (out if through or outside(methods[t].cls) else nxt).append(t)
          elif not through:
            ext.add(api(t))
      frontier = nxt
    for hop in range(1, OUT_DEPTH + 1):
      nxt = []
      for k in out:
        for t, _via in successors(k):
          us = unit_memo.get(t, ())
          if us:
            for x in us:
              far.setdefault(x.id, hop)
          elif t not in seen and t in methods:
            seen.add(t)
            nxt.append(t)
      out = nxt
    for uid in direct:
      far.pop(uid, None)
    return direct, far, ext

  DEX_INDEX[work] = (methods, hier, units_for, dispatch)
  GRAPH[work] = {"successors": successors, "outside": outside, "has_units": has_units, "by_cls": by_cls,
                 "ctors": ctors}
  by_unit = {}
  for key in methods:
    for u in units_for(key):
      by_unit.setdefault(u.id, []).append(key)
  for u in units:
    for key in by_unit.get(u.id, ()):
      direct, far, ext = expand(key)
      u.calls |= direct - {u.id}
      u.ext |= ext
      for uid, hop in far.items():
        if uid != u.id and hop < u.far.get(uid, OUT_DEPTH + 1):
          u.far[uid] = hop
      m = methods[key]
      if any(schedules(k) for k in m.invokes):
        # a Runnable or Handler held in a field (or this object) handed to another thread
        # or a looper: its run or handleMessage runs later on its behalf. Only classes
        # whose ancestors include a Runnable, Thread, Handler, Callable, or TimerTask.
        for t in dict.fromkeys(m.fields + [m.cls]):
          if t in by_cls and anc.get(t, set()) & ASYNC_BASES:
            for k in by_cls[t]:
              if methods[k].name in JAVA_RUN:
                us = units_for(k)
                u.async_ |= ({x.id for x in us} if us else expand(k)[0]) - {u.id}
    for uid in u.calls:
      u.far.pop(uid, None)
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
      with open(os.path.join(dp, f), errors="replace", newline="") as fh:  # lines on \n only
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
        # a literal-pool annotation (postprocess.py) whose word is used as an offset
        # (base + DAT_x) is a chance match, not a reference: Ghidra output written before
        # postprocess.py skipped those still has them
        offsets = set(re.findall(r"[-+]\s*\(?\w*\)?\s*(DAT_[0-9a-f]{8})\b", body)) | \
            set(re.findall(r"\b(DAT_[0-9a-f]{8})\s*(?:/\*[^*]*\*/\s*)?[-+]", body))
        body = re.sub(r"\b(DAT_[0-9a-f]{8}) /\* -> &\w+ \*/",
                      lambda mo: mo.group(1) if mo.group(1) in offsets else mo.group(0), body)
        for m in re.finditer(r"&(\w+)|\b(FUN_[0-9a-f]+|jni_\w+|init_\d+)\b(?!\s*\()", body):
          c = m.group(1) or m.group(2)
          if c in here and here[c] is not u:
            u.refs.add(here[c].id)
  return units


def callees(u, hops=None):
  """ids of the units u calls: its direct calls and, for Java, what it reaches through at
  most hops (default FAR_HOPS) methods outside the scanned scope"""
  if not u.far:
    return u.calls
  hops = FAR_HOPS if hops is None else hops
  return u.calls | {v for v, h in u.far.items() if h <= hops}


def callers_of(units, with_async=False):
  """callers per unit id; with_async also counts Runnables and Handlers handed over (async_)"""
  by_id = {u.id: u for u in units}
  callers = {u.id: set() for u in units}
  for u in units:
    for c in callees(u) | u.refs | (u.async_ if with_async else set()):
      if c in callers:
        callers[c].add(u.id)
  return by_id, callers
