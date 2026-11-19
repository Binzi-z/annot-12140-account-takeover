#!/usr/bin/env python3
"""incscan —— 增量污点扫描器。

设计：
- 包级缓存：.scancache/index.json，按包记录文件哈希、函数摘要、findings、接口与实现。
- 影响面按导入图 + 调用图计算：源文件变更重扫自己；被调函数摘要变化重扫所有调用方；
  跨包接口方法集变化重扫所有实现类型所在文件。
- 缓存只是性能提示：每个条目携带输入哈希，不匹配即弃用，绝不盲信缓存内容。
- 全量 = 空缓存的增量，同一条代码路径，保证"增量结论与全量逐条一致"是构造性成立的。

用法：
  scan.py full --repo R --sarif out.sarif
  scan.py inc  --repo R --sarif out.sarif [--debug]
  scan.py ci   --repo R --baseline base.sarif --sarif out.sarif   # 有新增违规则 exit 1
"""
import argparse
import hashlib
import json
import os
import re
import socket
import sys
import time

CATS = ("sql_injection", "command_injection", "path_traversal", "ssrf")
ALL = frozenset(CATS)
CACHE_DIRNAME = ".scancache"
CACHE_VERSION = 3
LOCK_STALE_SEC = 120

# ---------------------------------------------------------------- 规则注册表
# 终端 sink：全限定名优先，其次裸名（仓库内的封装函数）
SINK_EXACT = {
    "db.Query": "sql_injection",
    "exec.Command": "command_injection",
    "os.Open": "path_traversal",
    "http.Get": "ssrf",
}
SINK_BASE = {
    "queryStr": "sql_injection",
    "runCmd": "command_injection",
    "readFile": "path_traversal",
    "fetch": "ssrf",
}
# 仓库内由注册表直接给摘要、跳过函数体分析的函数
REGISTRY_FUNCS = {"queryStr", "runCmd", "readFile", "fetch", "allowlistHost"}

SOURCE_RE = re.compile(
    r"URL\.Query\(\)|FormValue\(|PostFormValue\(|\.Header\.Get\(|\.Cookie\("
)
FUNC_RE = re.compile(
    r"^func\s+(?:\(\s*(\w+)\s+\*?(\w+)\s*\)\s*)?(\w+)\s*\(([^)]*)\)"
)
IFACE_RE = re.compile(r"^type\s+(\w+)\s+interface\s*\{")
CALL_RE = re.compile(r"([A-Za-z_][\w.]*)\s*\(")
ASSIGN_RE = re.compile(r"^\s*([A-Za-z0-9_,\s]+?)\s*(?::=|(?<![<>=!:])=(?![=]))\s*(.+?)\s*$")
SKIP_PREFIX = ("if ", "if{", "for ", "for{", "switch", "case ", "else", "defer ",
               "go ", "func", "}", "return", "import", "package", "var ", "const ", "type ")


def sink_cat(name):
    if name in SINK_EXACT:
        return SINK_EXACT[name]
    return SINK_BASE.get(name.split(".")[-1])


def sanitizer_clears(name, args_str):
    """返回该调用清除的污点类别集合；不是净化器则返回空集。"""
    base = name.split(".")[-1]
    if base == "allowlistHost":
        return {"ssrf"}
    if name == "filepath.Clean":
        return {"path_traversal"}
    if base == "ReplaceAll" and '"\'"' in args_str:
        return {"sql_injection"}
    return set()


def sha1(s):
    return hashlib.sha1(s.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- 词法小工具
def strip_strings(line):
    line = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
    line = re.sub(r"'(?:\\.|[^'\\])'", "''", line)
    return line


def split_top(s, sep):
    """按顶层分隔符切分，跳过括号与字符串字面量内部。"""
    parts, cur, depth = [], [], 0
    in_str = None
    i = 0
    while i < len(s):
        ch = s[i]
        if in_str:
            cur.append(ch)
            if ch == "\\" and i + 1 < len(s):
                cur.append(s[i + 1])
                i += 2
                continue
            if ch == in_str:
                in_str = None
        elif ch in "\"'`":
            in_str = ch
            cur.append(ch)
        elif ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            depth -= 1
            cur.append(ch)
        elif ch == sep and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return parts


def match_paren(s, open_idx):
    """返回与 s[open_idx]=='(' 配对的 ')' 下标；失败返回 -1。跳过字符串。"""
    depth, in_str, i = 0, None, open_idx
    while i < len(s):
        ch = s[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
        elif ch in "\"'`":
            in_str = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def parse_call(expr):
    """expr 整体是一个调用时返回 (名字, 参数串)，否则 None。"""
    expr = expr.strip()
    m = re.match(r"^([A-Za-z_][\w.]*)\s*\(", expr)
    if not m:
        return None
    close = match_paren(expr, m.end() - 1)
    if close < 0 or expr[close + 1:].strip():
        return None  # 链式调用如 f(x).Output()，按未知处理
    return m.group(1), expr[m.end():close]


def parse_params(s):
    """从形参列表提取参数名（不支持 `a, b string` 的省略写法，语料未用到）。"""
    names = []
    for m in re.finditer(r"(\w+)\s+[\w.*\[\]]+", s):
        names.append(m.group(1))
    return names


# ---------------------------------------------------------------- Go 源码解析
class FuncInfo:
    __slots__ = ("key", "pkg", "file", "name", "recv", "params", "start_line",
                 "body_lines", "body_hash")

    def __init__(self, pkg, rel, name, recv, params, start_line, body_lines):
        self.pkg = pkg
        self.file = rel
        self.name = name
        self.recv = recv
        self.params = params
        self.start_line = start_line
        self.body_lines = body_lines
        self.body_hash = sha1("\n".join(body_lines))
        self.key = "%s/%s" % (pkg, name)


class FileInfo:
    __slots__ = ("rel", "pkg", "hash", "imports", "functions", "interfaces",
                 "type_methods")

    def __init__(self, rel, pkg, text):
        self.rel = rel
        self.pkg = pkg
        self.hash = sha1(text)
        self.imports = {}       # alias -> import path
        self.functions = []     # FuncInfo
        self.interfaces = {}    # name -> [method]
        self.type_methods = {}  # type -> [method]


def extract_block(lines, start_idx):
    """从 start_idx 行（含首个 '{'）做花括号配对，返回块内所有行（含首尾）。"""
    body, depth, started = [], 0, False
    for i in range(start_idx, len(lines)):
        line = lines[i]
        body.append(line)
        stripped = strip_strings(line)
        depth += stripped.count("{") - stripped.count("}")
        if "{" in stripped:
            started = True
        if started and depth <= 0:
            break
    return body


def parse_file(rel, pkg, text):
    fi = FileInfo(rel, pkg, text)
    lines = text.splitlines()
    # imports
    for m in re.finditer(r'import\s*\((.*?)\)', text, re.S):
        for im in re.finditer(r'(?:(\w+)\s+)?"([^"]+)"', m.group(1)):
            alias, path = im.group(1), im.group(2)
            fi.imports[alias or path.rsplit("/", 1)[-1]] = path
    for im in re.finditer(r'import\s+(?:(\w+)\s+)?"([^"]+)"', text):
        alias, path = im.group(1), im.group(2)
        fi.imports[alias or path.rsplit("/", 1)[-1]] = path
    # 函数 / 方法 / 接口
    i = 0
    while i < len(lines):
        line = lines[i]
        fm = FUNC_RE.match(line)
        if fm:
            recv_type, name, params_s = fm.group(2), fm.group(3), fm.group(4)
            body = extract_block(lines, i)
            fn = FuncInfo(pkg, rel, name, recv_type, parse_params(params_s),
                          i + 1, body)
            fi.functions.append(fn)
            if recv_type:
                fi.type_methods.setdefault(recv_type, []).append(name)
            i += len(body)
            continue
        im = IFACE_RE.match(line)
        if im:
            body = extract_block(lines, i)
            methods = []
            for bl in body[1:-1]:
                mm = re.match(r"\s*(\w+)\s*\(", bl)
                if mm:
                    methods.append(mm.group(1))
            fi.interfaces[im.group(1)] = sorted(methods)
            i += len(body)
            continue
        i += 1
    return fi


def parse_repo(repo):
    """返回 {relpath: FileInfo}，relpath 用正斜杠。"""
    module = ""
    gomod = os.path.join(repo, "go.mod")
    if os.path.isfile(gomod):
        with open(gomod, encoding="utf-8") as fh:
            m = re.search(r"^module\s+(\S+)", fh.read(), re.M)
            module = m.group(1) if m else ""
    files = {}
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = [d for d in dirnames
                       if not d.startswith(".") and d not in ("vendor", "node_modules")]
        for n in filenames:
            if not n.endswith(".go"):
                continue
            ap = os.path.join(dirpath, n)
            rel = os.path.relpath(ap, repo).replace(os.sep, "/")
            with open(ap, encoding="utf-8") as fh:
                text = fh.read()
            d = os.path.dirname(rel)
            pkg = module + ("/" + d if d else "")
            files[rel] = parse_file(rel, pkg, text)
    return module, files


# ---------------------------------------------------------------- 污点分析
class Ctx:
    """一次分析回合的共享视图。"""

    def __init__(self, files, fns, summaries, key_file):
        self.files = files          # rel -> FileInfo（当前解析）
        self.fns = fns              # key -> FuncInfo（当前）
        self.summaries = summaries  # key -> summary（缓存 + 本回合重算，原地更新）
        self.key_file = key_file    # key -> rel
        self.findings = []          # 当前函数分析产出的 findings
        self.cur_file = None
        self.cur_imports = None

    def resolve(self, name):
        """把调用名解析成函数 key；解析不了返回 None。"""
        if "." in name:
            alias, base = name.split(".", 1)
            path = self.cur_imports.get(alias)
            if path:
                return path + "/" + base
            return None
        key = self.cur_pkg + "/" + name
        return key if key in self.key_file else None

    def emit_callee_sink(self, callee_key, ps):
        rel = self.key_file.get(callee_key)
        if rel:
            self.findings.append({"file": rel, "line": ps["line"], "cat": ps["cat"]})


def eval_expr(expr, env, ctx):
    """返回 (类别集合, 来源集合)；来源是形参名或 'source'。"""
    expr = expr.strip()
    if not expr:
        return (frozenset(), frozenset())
    if SOURCE_RE.search(expr):
        return (ALL, frozenset({"source"}))
    parts = split_top(expr, "+")
    if len(parts) > 1:
        cats, orgs = set(), set()
        for p in parts:
            c, o = eval_expr(p, env, ctx)
            cats |= c
            orgs |= o
        return (frozenset(cats), frozenset(orgs))
    call = parse_call(expr)
    if call:
        name, args_str = call
        args = split_top(args_str, ",") if args_str.strip() else []
        arg_taints = [eval_expr(a, env, ctx) for a in args]
        clears = sanitizer_clears(name, args_str)
        if clears:
            cats, orgs = set(), set()
            for c, o in arg_taints:
                cats |= c
                orgs |= o
            return (frozenset(cats - clears), frozenset(orgs))
        key = ctx.resolve(name)
        if key and key in ctx.summaries:
            summ = ctx.summaries[key]
            # 调用方触发"形参→sink"摘要：污染实参传到被调函数的 sink（事故现场模式）
            for ps in summ.get("param_sinks", []):
                if ps["param"] in summ["params"]:
                    idx = summ["params"].index(ps["param"])
                    if idx < len(arg_taints):
                        c, o = arg_taints[idx]
                        if ps["cat"] in c and "source" in o:
                            ctx.emit_callee_sink(key, ps)
            cats, orgs = set(), set()
            for ret in summ.get("return", []):
                rcats = set(ret["cats"])
                for org in ret["origins"]:
                    if org == "source":
                        cats |= rcats
                        orgs.add("source")
                    elif org in summ["params"]:
                        idx = summ["params"].index(org)
                        if idx < len(arg_taints):
                            ac, ao = arg_taints[idx]
                            cats |= rcats & set(ac)
                            orgs |= ao
            return (frozenset(cats), frozenset(orgs))
        # 未知调用：保守传播实参与接收者的污点
        cats, orgs = set(), set()
        if "." in name:
            recv = name.rsplit(".", 1)[0]
            if recv in env:
                c, o = env[recv]
                cats |= c
                orgs |= o
        for c, o in arg_taints:
            cats |= c
            orgs |= o
        return (frozenset(cats), frozenset(orgs))
    if re.match(r"^[A-Za-z_]\w*$", expr) and expr in env:
        return env[expr]
    return (frozenset(), frozenset())


def scan_sinks_in_line(line, env, ctx, param_sinks):
    """在单行里找终端 sink 调用；命中则记 finding 或（形参来源时）记 param_sink。"""
    for m in CALL_RE.finditer(line):
        name = m.group(1)
        cat = sink_cat(name)
        if not cat:
            continue
        close = match_paren(line, m.end() - 1)
        if close < 0:
            continue
        args_str = line[m.end():close]
        cats, orgs = eval_expr(args_str, env, ctx)
        if cat not in cats:
            continue
        if "source" in orgs:
            ctx.findings.append({"file": ctx.cur_file, "line": ctx.cur_line,
                                 "cat": cat})
        for o in orgs:
            if o != "source":
                param_sinks.append({"param": o, "cat": cat, "line": ctx.cur_line})


def registry_summary(fn):
    base = fn.name
    if base in ("queryStr", "runCmd", "readFile", "fetch"):
        return {"params": fn.params, "return": [], "param_sinks": []}
    if base == "allowlistHost":
        return {"params": fn.params,
                "return": [{"cats": sorted(ALL - {"ssrf"}),
                            "origins": fn.params[:1]}],
                "param_sinks": []}
    return None


def analyze_function(fn, ctx):
    """返回 (summary, findings, calls)。注册表函数直接给摘要，跳过函数体。"""
    reg = registry_summary(fn)
    if reg is not None:
        return reg, [], []
    ctx.cur_file = fn.file
    ctx.cur_pkg = fn.pkg
    ctx.cur_imports = ctx.files[fn.file].imports
    ctx.findings = []
    env = {p: (ALL, frozenset({p})) for p in fn.params}
    ret, param_sinks, calls = [], [], set()
    for i, raw_line in enumerate(fn.body_lines):
        ctx.cur_line = fn.start_line + i
        line = raw_line
        for cm in CALL_RE.finditer(line):
            key = ctx.resolve(cm.group(1))
            if key:
                calls.add(key)
        scan_sinks_in_line(line, env, ctx, param_sinks)
        s = line.strip()
        if any(s.startswith(p) for p in SKIP_PREFIX):
            if s.startswith("return"):
                expr = s[len("return"):].strip()
                if expr:
                    first = split_top(expr, ",")[0]
                    c, o = eval_expr(first, env, ctx)
                    if c:
                        ret.append({"cats": sorted(c), "origins": sorted(o)})
            continue
        m = ASSIGN_RE.match(line)
        if m:
            lhs, rhs = m.group(1), m.group(2)
            val = eval_expr(rhs, env, ctx)
            for var in lhs.split(","):
                var = var.strip()
                if var and var != "_" and re.match(r"^\w+$", var):
                    env[var] = val
    # 去重并保持确定性
    ret = [dict(t) for t in {json.dumps(r, sort_keys=True) for r in ret}
           for t in [json.loads(t)]]
    ps = [dict(t) for t in {json.dumps(p, sort_keys=True) for p in param_sinks}
          for t in [json.loads(t)]]
    summary = {"params": fn.params, "return": sorted(ret, key=str),
               "param_sinks": sorted(ps, key=str)}
    findings = [dict(t) for t in {json.dumps(f, sort_keys=True) for f in ctx.findings}
                for t in [json.loads(t)]]
    return summary, findings, sorted(calls)


# ---------------------------------------------------------------- 缓存与锁
class CacheLock:
    """跨进程互斥锁：O_EXCL 创建锁文件，带 stale 检测（PID+时间戳）。"""

    def __init__(self, path, timeout):
        self.path = path
        self.timeout = timeout
        self.fd = None

    def __enter__(self):
        deadline = time.time() + self.timeout
        while True:
            try:
                self.fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(self.fd, json.dumps({
                    "pid": os.getpid(), "host": socket.gethostname(),
                    "time": time.time()}).encode())
                return self
            except FileExistsError:
                try:
                    if time.time() - os.path.getmtime(self.path) > LOCK_STALE_SEC:
                        os.remove(self.path)  # 持有者已死，破锁
                        continue
                except FileNotFoundError:
                    continue
                if time.time() > deadline:
                    raise TimeoutError("cache lock held by another process: " + self.path)
                time.sleep(0.05)

    def __exit__(self, *exc):
        if self.fd is not None:
            os.close(self.fd)
        try:
            os.remove(self.path)
        except FileNotFoundError:
            pass
        return False


def cache_paths(repo):
    d = os.path.join(repo, CACHE_DIRNAME)
    return d, os.path.join(d, "index.json"), os.path.join(d, "lock")


def load_cache(repo):
    _, index, _ = cache_paths(repo)
    try:
        with open(index, encoding="utf-8") as fh:
            c = json.load(fh)
        if c.get("version") == CACHE_VERSION:
            return c
    except (OSError, ValueError):
        pass
    return {"version": CACHE_VERSION, "files": {}, "functions": {},
            "interfaces": {}, "type_methods": {}}


def save_cache(repo, cache):
    """读改写合并 + 原子落盘，全程持锁；锁外只做无状态分析。"""
    d, index, lock = cache_paths(repo)
    os.makedirs(d, exist_ok=True)
    timeout = float(os.environ.get("INCSCAN_LOCK_TIMEOUT", "30"))
    with CacheLock(lock, timeout):
        sleep_s = float(os.environ.get("INCSCAN_SLEEP_AFTER_LOCK", "0"))
        if sleep_s:
            time.sleep(sleep_s)  # 测试钩子：人为拉宽竞争窗口
        # 合并：缓存条目按内容哈希寻址，同一输入必然算出同一条目，
        # 因此并集是安全的——丢条目只损失性能，绝不产生错误结论。
        on_disk = load_cache(repo)
        for rel, e in cache["files"].items():
            old = on_disk["files"].get(rel)
            if not old or old["hash"] != e["hash"]:
                on_disk["files"][rel] = e
        for key, e in cache["functions"].items():
            old = on_disk["functions"].get(key)
            if not old or old["body_hash"] != e["body_hash"]:
                on_disk["functions"][key] = e
        on_disk["interfaces"].update(cache["interfaces"])
        on_disk["type_methods"].update(cache["type_methods"])
        on_disk["version"] = CACHE_VERSION
        tmp = "%s.tmp.%d" % (index, os.getpid())
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(on_disk, fh, indent=1, sort_keys=True)
        # 同目录原子替换：读者只见完整旧版或完整新版。
        # Windows 上读者打开文件的瞬间会阻塞 replace（PermissionError），
        # 读者窗口极短，退避重试即可；这是平台文件锁语义，不是逻辑竞争。
        for attempt in range(100):
            try:
                os.replace(tmp, index)
                break
            except PermissionError:
                if attempt == 99:
                    raise
                time.sleep(0.05)


# ---------------------------------------------------------------- 扫描驱动
def run_scan(repo, use_cache):
    """增量与全量共用同一条路径：全量 = 空缓存的增量。"""
    module, files = parse_repo(repo)
    cache = load_cache(repo) if use_cache else \
        {"version": CACHE_VERSION, "files": {}, "functions": {},
         "interfaces": {}, "type_methods": {}}

    fns, key_file = {}, {}
    for rel, fi in files.items():
        for fn in fi.functions:
            fns[fn.key] = fn
            key_file[fn.key] = rel

    cached_fns = cache["functions"]
    summaries = {k: v["summary"] for k, v in cached_fns.items()}
    callsmap = {k: list(v.get("calls", [])) for k, v in cached_fns.items()}
    cached_findings = {rel: e.get("findings", []) for rel, e in cache["files"].items()}

    # 1) 源文件变更 → 重扫自己
    dirty = {rel for rel, fi in files.items()
             if rel not in cache["files"] or cache["files"][rel]["hash"] != fi.hash}
    deleted_keys = set(cached_fns) - set(fns)

    ctx = Ctx(files, fns, summaries, key_file)
    fresh_findings = {}  # rel -> [finding]（本回合重算）
    changed_keys = set()

    # 2) 失效传播不动点：被调摘要变化 → 重扫调用方；接口变化 → 重扫实现类
    while True:
        todo = [fn for rel in sorted(dirty) for fn in files[rel].functions]
        for _ in range(50):  # 包内摘要不动点
            stable = True
            for fn in todo:
                summ, finds, calls = analyze_function(fn, ctx)
                fresh_findings.setdefault(fn.file, {})
                fresh_findings[fn.file][fn.key] = finds
                callsmap[fn.key] = calls
                if summaries.get(fn.key) != summ:
                    summaries[fn.key] = summ
                    stable = False
            if stable:
                break
        for fn in todo:
            old = cached_fns.get(fn.key)
            if not old or old["summary"] != summaries[fn.key]:
                changed_keys.add(fn.key)

        propagate = set()
        # 2a) 被调函数变更（含删除）→ 所有调用方所在文件
        for ck in changed_keys | deleted_keys:
            for caller, clist in callsmap.items():
                if ck in clist and caller in fns:
                    propagate.add(fns[caller].file)
        # 2b) 跨包接口方法集变更 → 所有实现类型所在文件（新旧实现取并集）
        cur_ifaces = {fi.pkg: fi.interfaces for fi in files.values()}
        cur_types = {}
        for fi in files.values():
            for t, ms in fi.type_methods.items():
                cur_types[t] = {"methods": ms, "file": fi.rel}
        old_types = {}
        for pkg, tm in cache["type_methods"].items():
            for t, e in tm.items():
                old_types[t] = e
        for pkg, ifaces in cur_ifaces.items():
            old_ifaces = cache["interfaces"].get(pkg, {})
            for iname, methods in ifaces.items():
                if old_ifaces.get(iname) == methods:
                    continue
                need = set(methods)
                old_need = set(old_ifaces.get(iname, []))
                for t, e in cur_types.items():
                    if need <= set(e["methods"]):
                        propagate.add(e["file"])
                for t, e in old_types.items():
                    if old_need and old_need <= set(e["methods"]):
                        propagate.add(e["file"])
        for pkg, ifaces in cache["interfaces"].items():
            for iname in ifaces:
                if iname not in cur_ifaces.get(pkg, {}):  # 接口被删
                    need = set(ifaces[iname])
                    for t, e in cur_types.items():
                        if need <= set(e["methods"]):
                            propagate.add(e["file"])

        deleted_keys = set()
        changed_keys = set()
        propagate -= dirty
        if not propagate:
            break
        dirty |= propagate

    # 3) 汇总 findings：脏文件用新算的，干净文件用缓存的
    out = []
    for rel in sorted(files):
        if rel in dirty:
            for key_finds in fresh_findings.get(rel, {}).values():
                out.extend(key_finds)
        else:
            out.extend(cached_findings.get(rel, []))
    seen, findings = set(), []
    for f in sorted(out, key=lambda x: (x["file"], x["line"], x["cat"])):
        t = (f["file"], f["line"], f["cat"])
        if t not in seen:
            seen.add(t)
            findings.append(f)

    # 4) 写回缓存（全量模式也写，供下一次增量使用）
    new_cache = {"version": CACHE_VERSION, "files": {}, "functions": {},
                 "interfaces": {}, "type_methods": {}}
    per_file_findings = {}
    for rel in files:
        if rel in dirty:
            fl = []
            for key_finds in fresh_findings.get(rel, {}).values():
                fl.extend(key_finds)
            per_file_findings[rel] = sorted(
                {json.dumps(x, sort_keys=True) for x in fl})
            per_file_findings[rel] = [json.loads(x) for x in per_file_findings[rel]]
        else:
            per_file_findings[rel] = cached_findings.get(rel, [])
    for rel, fi in files.items():
        new_cache["files"][rel] = {"hash": fi.hash, "pkg": fi.pkg,
                                   "findings": per_file_findings[rel]}
        if fi.interfaces:
            new_cache["interfaces"][fi.pkg] = fi.interfaces
        if fi.type_methods:
            new_cache["type_methods"][fi.pkg] = {
                t: {"methods": ms, "file": rel} for t, ms in fi.type_methods.items()}
    for key, fn in fns.items():
        new_cache["functions"][key] = {
            "file": fn.file, "body_hash": fn.body_hash,
            "summary": summaries.get(key, {"params": fn.params, "return": [],
                                           "param_sinks": []}),
            "calls": callsmap.get(key, [])}
    save_cache(repo, new_cache)

    if os.environ.get("INCSCAN_DEBUG"):
        sys.stderr.write(json.dumps({"dirty_files": sorted(dirty)},
                                    ensure_ascii=False) + "\n")
    return findings


# ---------------------------------------------------------------- 输出
def to_sarif(findings):
    rules = [{"id": c, "name": c,
              "shortDescription": {"text": "tainted data reaches %s sink" % c},
              "defaultConfiguration": {"level": "error"}} for c in CATS]
    results = [{
        "ruleId": f["cat"], "level": "error",
        "message": {"text": "tainted data reaches %s sink" % f["cat"]},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f["file"]},
            "region": {"startLine": f["line"]}}}],
    } for f in findings]
    return {"version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "incscan", "version": "1.0.0",
                                          "rules": rules}},
                      "results": results}]}


def load_findings_any(path):
    """兼容 SARIF 与裸 findings.json，返回 {(file, line, cat)}。"""
    with open(path, encoding="utf-8-sig") as fh:
        doc = json.load(fh)
    out = set()
    if "findings" in doc:
        for f in doc["findings"]:
            out.add((f.get("file"), int(f.get("line", 0)), f.get("cat")))
    else:
        for run in doc.get("runs", []):
            for res in run.get("results", []):
                loc = res["locations"][0]["physicalLocation"]
                out.add((loc["artifactLocation"]["uri"],
                         int(loc["region"]["startLine"]), res.get("ruleId")))
    return out


def main():
    ap = argparse.ArgumentParser(prog="incscan")
    ap.add_argument("mode", choices=["full", "inc", "ci"])
    ap.add_argument("--repo", default=".")
    ap.add_argument("--sarif")
    ap.add_argument("--baseline", help="ci 模式：基线 SARIF，只拦截新增违规")
    args = ap.parse_args()
    repo = os.path.abspath(args.repo)

    try:
        findings = run_scan(repo, use_cache=(args.mode != "full"))
    except TimeoutError as e:
        sys.stderr.write("incscan: %s\n" % e)
        sys.exit(3)

    sarif = to_sarif(findings)
    out = args.sarif or os.path.join(repo, "findings.sarif")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=1)
    print("findings=%d -> %s" % (len(findings), out))

    if args.mode == "ci":
        if not args.baseline:
            sys.stderr.write("incscan ci: --baseline required\n")
            sys.exit(2)
        base = load_findings_any(args.baseline)
        cur = {(f["file"], f["line"], f["cat"]) for f in findings}
        new = sorted(cur - base)
        for f, l, c in new:
            print("NEW VIOLATION: %s:%d %s" % (f, l, c))
        if new:
            print("ci: %d new violation(s), gate FAILED" % len(new))
            sys.exit(1)
        print("ci: no new violations, gate PASSED")


if __name__ == "__main__":
    main()
