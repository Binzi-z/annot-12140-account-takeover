#!/usr/bin/env python3
"""backtest —— 50 条标注样本回测增量扫描器。

每个样本： pristine 工作区冷启动扫描 -> 施加一次变更 -> 热缓存增量扫描。
对每个样本断言三件事：
  1. 冷启动增量 == 全量（空缓存路径正确）
  2. 热缓存增量 == 变更后的全量（逐条一致，硬要求）
  3. 热缓存增量 == 该样本的标注真值（计入召回/误报）
门槛：召回 >= 85%，误报率 <= 15%，且 2 不允许任何失败。
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SCAN = os.path.join(HERE, "scan.py")
H = "pkg/handlers/handlers.go"

BASE = None  # 从 labels.json 读


def load_base():
    with open(os.path.join(REPO, "labels.json"), encoding="utf-8") as fh:
        return {(v["file"], v["line"]) for v in json.load(fh)["vulns"]}


# ---------------------------------------------------------------- 工作区工具
def make_ws(root):
    ws = tempfile.mkdtemp(prefix="incbt_", dir=root)
    for name in ("main.go", "go.mod", "labels.json"):
        shutil.copy(os.path.join(REPO, name), os.path.join(ws, name))
    shutil.copytree(os.path.join(REPO, "pkg"), os.path.join(ws, "pkg"))
    return ws


def read(ws, rel):
    with open(os.path.join(ws, rel), encoding="utf-8") as fh:
        return fh.read()


def write(ws, rel, text):
    p = os.path.join(ws, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(text)


def edit_line(ws, rel, lineno, old, new):
    """整行替换（保行号），并断言旧内容在场，防止样本写错行。"""
    lines = read(ws, rel).splitlines()
    assert old in lines[lineno - 1], "%s:%d 期望包含 %r，实际 %r" % (
        rel, lineno, old, lines[lineno - 1])
    lines[lineno - 1] = new
    write(ws, rel, "\n".join(lines) + "\n")


def run_scan(ws, mode):
    out = os.path.join(ws, "out_%s.sarif" % mode)
    env = dict(os.environ)
    subprocess.run([sys.executable, SCAN, mode, "--repo", ws, "--sarif", out],
                   capture_output=True, text=True, check=True, env=env)
    with open(out, encoding="utf-8") as fh:
        doc = json.load(fh)
    got = set()
    for r in doc["runs"][0]["results"]:
        loc = r["locations"][0]["physicalLocation"]
        got.add((loc["artifactLocation"]["uri"], loc["region"]["startLine"]))
    return got


# ---------------------------------------------------------------- 夹具文件
STORE_GO = '''package store

import "database/sql"

var db *sql.DB

func Lookup(id string) string {
	rows, _ := db.Query("SELECT * FROM refunds WHERE id = '" + id + "'")
	if rows == nil {
		return ""
	}
	defer rows.Close()
	return "ok"
}
'''
STORE_GO_SAFE = STORE_GO.replace(
    'db.Query("SELECT * FROM refunds WHERE id = \'" + id + "\'")',
    'db.Query("SELECT * FROM refunds")')
assert STORE_GO_SAFE != STORE_GO

EXTRA_VULN_GO = '''package handlers

import "net/http"

func ExtraVuln(w http.ResponseWriter, r *http.Request) {
	_ = w
	raw := r.URL.Query().Get("input")
	_ = queryStr("SELECT * FROM t WHERE x = '" + raw + "'")
}
'''
EXTRA_SAFE_GO = '''package handlers

import "net/http"

func ExtraSafe(w http.ResponseWriter, r *http.Request) {
	_ = w
	raw := r.URL.Query().Get("input")
	_ = queryStr("SELECT * FROM t WHERE x = '" + onlyDigits(raw) + "'")
}
'''
EXTRA_XPKG_GO = '''package handlers

import (
	"net/http"
	"annot/pkg/store"
)

func ExtraXpkg(w http.ResponseWriter, r *http.Request) {
	_ = w
	raw := r.URL.Query().Get("input")
	_ = store.Lookup(raw)
}
'''
EXTRA_XPKG_SAFE_GO = EXTRA_XPKG_GO.replace(
    "store.Lookup(raw)", "store.Lookup(onlyDigits(raw))")
EXTRA_INC_GO = '''package handlers

import (
	"net/http"
	"annot/pkg/store"
)

func ExtraInc(w http.ResponseWriter, r *http.Request) {
	_ = w
	raw := r.URL.Query().Get("input")
	_ = store.Lookup(onlyDigits(raw))
}
'''
IFACE_GO = '''package iface

// Cleaner 是跨包净化接口。
type Cleaner interface {
	Clean(string) string
}
'''
IMPL_GO = '''package impl

import "strings"

type Passthrough struct{}

func (Passthrough) Clean(v string) string {
	return strings.ReplaceAll(v, "'", "")
}

func Clean(v string) string {
	return strings.ReplaceAll(v, "'", "")
}
'''
EXTRA_IFACE_GO = '''package handlers

import (
	"net/http"
	"annot/pkg/impl"
)

func ExtraIface(w http.ResponseWriter, r *http.Request) {
	_ = w
	raw := r.URL.Query().Get("input")
	clean := impl.Clean(raw)
	_ = queryStr("SELECT * FROM t WHERE x = '" + clean + "'")
}
'''

VULN_LINES = [74, 86, 98, 110, 122, 134, 146, 158]
FWD_RET_LINES = [66, 78, 90, 102, 114, 126, 138, 150]   # forward00..07 的 return v
CALLER_V_LINES = [72, 84, 96, 108, 120, 132, 144, 156]  # v := forwardNN(raw)
SAFE_CLEAN_LINES = [168, 181, 194, 207, 220, 233]       # 6 个 decoy 的净化行
SAFE_SINK_LINES = [171, 184, 197, 210, 223, 236]


# ---------------------------------------------------------------- 场景定义
class Sc:
    def __init__(self, name, setup=None, mutate=None, expect=None):
        self.name = name
        self.setup = setup or (lambda ws: None)
        self.mutate = mutate or (lambda ws: None)
        self.expect = expect  # None -> BASE


def scenarios():
    S = []

    def add(name, **kw):
        S.append(Sc(name, **kw))

    # A. 无实质变更（注释/gomod），真值不变 --------------------------------
    add("a1-comment-var", mutate=lambda ws: edit_line(
        ws, H, 13, 'var baseDir = "/srv/data"', 'var baseDir = "/srv/data" // a1'))
    add("a2-comment-db", mutate=lambda ws: edit_line(
        ws, H, 12, "var db *sql.DB", "var db *sql.DB // a2"))
    add("a3-comment-main", mutate=lambda ws: edit_line(
        ws, "main.go", 8, "func main() {", "func main() { // a3"))
    add("a4-comment-sanitizer-func", mutate=lambda ws: edit_line(
        ws, H, 47, "func onlyDigits(v string) string {",
        "func onlyDigits(v string) string { // a4"))
    add("a5-gomod-comment", mutate=lambda ws: write(
        ws, "go.mod", read(ws, "go.mod") + "// a5\n"))

    # B. 调用方删掉净化 → decoy 变真漏洞 ----------------------------------
    for i, (cl, sl) in enumerate(zip(SAFE_CLEAN_LINES, SAFE_SINK_LINES)):
        add("b%d-strip-sanitizer-L%d" % (i + 1, cl),
            mutate=lambda ws, cl=cl: edit_line(ws, H, cl, "clean :=", "\tclean := raw"),
            expect=lambda b, sl=sl: b | {(H, sl)})

    # C. 调用方加净化（onlyDigits 包一层）→ 真漏洞消失 ---------------------
    for i, (vl, sl) in enumerate(zip(CALLER_V_LINES, VULN_LINES)):
        n = i
        add("c%d-sanitize-caller-L%d" % (i + 1, vl),
            mutate=lambda ws, vl=vl, n=n: edit_line(
                ws, H, vl, "v := forward%02d(raw)" % n,
                "\tv := forward%02d(onlyDigits(raw))" % n),
            expect=lambda b, sl=sl: b - {(H, sl)})

    # D. 被调函数 forwardNN 改为净化 → 调用方必须重扫 ----------------------
    for i, (rl, sl) in enumerate(zip(FWD_RET_LINES, VULN_LINES)):
        add("d%d-callee-sanitizes-L%d" % (i + 1, rl),
            mutate=lambda ws, rl=rl: edit_line(
                ws, H, rl, "return v", "\treturn onlyDigits(v)"),
            expect=lambda b, sl=sl: b - {(H, sl)})

    # E. 净化器本体被破坏 -------------------------------------------------
    add("e1-onlydigits-returns-input", mutate=lambda ws: edit_line(
        ws, H, 54, "return b.String()", "\treturn v"),
        expect=lambda b: b | {(H, 184), (H, 236)})
    add("e2-allowlist-host-narrowed", mutate=lambda ws: edit_line(
        ws, H, 58, 'if strings.HasPrefix(u, "https://api.internal/") {',
        '\tif strings.HasPrefix(u, "https://api.internal/v2/") {'))

    # F. 新增文件 ----------------------------------------------------------
    add("f1-add-vuln-handler", mutate=lambda ws: write(
        ws, "pkg/handlers/extra_vuln.go", EXTRA_VULN_GO),
        expect=lambda b: b | {("pkg/handlers/extra_vuln.go", 8)})
    add("f2-add-safe-handler", mutate=lambda ws: write(
        ws, "pkg/handlers/extra_safe.go", EXTRA_SAFE_GO))
    add("f3-add-xpkg-tainted", mutate=lambda ws: (
        write(ws, "pkg/store/store.go", STORE_GO),
        write(ws, "pkg/handlers/extra_xpkg.go", EXTRA_XPKG_GO)),
        expect=lambda b: b | {("pkg/store/store.go", 8)})
    add("f4-add-xpkg-safe", mutate=lambda ws: (
        write(ws, "pkg/store/store.go", STORE_GO),
        write(ws, "pkg/handlers/extra_xpkg.go", EXTRA_XPKG_SAFE_GO)))

    # G. 跨包接口与实现 ----------------------------------------------------
    def g_setup(ws):
        write(ws, "pkg/iface/iface.go", IFACE_GO)
        write(ws, "pkg/impl/impl.go", IMPL_GO)
        write(ws, "pkg/handlers/extra_iface.go", EXTRA_IFACE_GO)
    add("g1-iface-fixture-comment", setup=g_setup, mutate=lambda ws: edit_line(
        ws, "pkg/impl/impl.go", 5, "type Passthrough struct{}",
        "type Passthrough struct{} // g1"))
    add("g2-iface-adds-method", setup=g_setup, mutate=lambda ws: edit_line(
        ws, "pkg/iface/iface.go", 5, "Clean(string) string",
        "\tClean(string) string\n\tName() string"))
    add("g3-impl-stops-sanitizing", setup=g_setup, mutate=lambda ws: edit_line(
        ws, "pkg/impl/impl.go", 12, 'return strings.ReplaceAll(v, "\'", "")',
        "\treturn v"),
        expect=lambda b: b | {("pkg/handlers/extra_iface.go", 12)})

    # H. 入口文件变更 ------------------------------------------------------
    add("h1-main-port", mutate=lambda ws: edit_line(
        ws, "main.go", 23, '":8080"', '":8081"'))
    add("h2-main-comment", mutate=lambda ws: edit_line(
        ws, "main.go", 8, "func main() {", "func main() { // h2"))

    # I. 事故现场复盘：sink 在被调函数里 ----------------------------------
    add("i1-caller-drops-sanitizer",  # 改动在调用方，sink 在被调函数（上月事故）
        setup=lambda ws: (write(ws, "pkg/store/store.go", STORE_GO),
                          write(ws, "pkg/handlers/extra_inc.go", EXTRA_INC_GO)),
        mutate=lambda ws: edit_line(
            ws, "pkg/handlers/extra_inc.go", 11,
            "store.Lookup(onlyDigits(raw))", "\t_ = store.Lookup(raw)"),
        expect=lambda b: b | {("pkg/store/store.go", 8)})
    add("i2-callee-gains-sink",  # 反向：被调函数新增 sink，调用方一行没动
        setup=lambda ws: (write(ws, "pkg/store/store.go", STORE_GO_SAFE),
                          write(ws, "pkg/handlers/extra_inc.go",
                                EXTRA_INC_GO.replace("onlyDigits(raw)", "raw"))),
        mutate=lambda ws: edit_line(
            ws, "pkg/store/store.go", 8, 'db.Query("SELECT * FROM refunds")',
            '\trows, _ := db.Query("SELECT * FROM refunds WHERE id = \'" + id + "\'")'),
        expect=lambda b: b | {("pkg/store/store.go", 8)})

    # J. 组合变更 ----------------------------------------------------------
    add("j1-two-decoys-open", mutate=lambda ws: (
        edit_line(ws, H, 168, "clean :=", "\tclean := raw"),
        edit_line(ws, H, 181, "clean :=", "\tclean := raw")),
        expect=lambda b: b | {(H, 171), (H, 184)})
    add("j2-caller-plus-callee-fix", mutate=lambda ws: (
        edit_line(ws, H, 72, "v := forward00(raw)",
                  "\tv := forward00(onlyDigits(raw))"),
        edit_line(ws, H, 78, "return v", "\treturn onlyDigits(v)")),
        expect=lambda b: b - {(H, 74), (H, 86)})
    add("j3-sanitizer-broken-plus-decoy", mutate=lambda ws: (
        edit_line(ws, H, 54, "return b.String()", "\treturn v"),
        edit_line(ws, H, 207, "clean :=", "\tclean := raw")),
        expect=lambda b: b | {(H, 184), (H, 236), (H, 210)})
    add("j4-comment-plus-decoy", mutate=lambda ws: (
        edit_line(ws, H, 13, 'var baseDir = "/srv/data"',
                  'var baseDir = "/srv/data" // j4'),
        edit_line(ws, H, 220, "clean :=", "\tclean := raw")),
        expect=lambda b: b | {(H, 223)})

    # K. sink 封装函数本体变更（摘要稳定，结论必须不变） --------------------
    add("k1-querystr-body", mutate=lambda ws: edit_line(
        ws, H, 21, "rows, _ := db.Query(q)", '\trows, _ := db.Query("SELECT 1")'))
    add("k2-runcmd-body", mutate=lambda ws: edit_line(
        ws, H, 16, 'exec.Command("sh", "-c", c)',
        '\tout, _ := exec.Command("sh", "-c", "echo ok").Output()'))
    add("k3-readfile-body", mutate=lambda ws: edit_line(
        ws, H, 30, "os.Open(p)", '\tf, err := os.Open("/etc/hostname")'))
    add("k4-fetch-body", mutate=lambda ws: edit_line(
        ws, H, 39, "http.Get(u)", '\tr, err := http.Get("https://api.internal/health")'))

    # L. 被调函数只改注释（摘要不稳 → 不重扫调用方，结论不变） --------------
    add("l1-forward00-comment", mutate=lambda ws: edit_line(
        ws, H, 65, "func forward00(v string) string {",
        "func forward00(v string) string { // l1"))
    add("l2-forward07-comment", mutate=lambda ws: edit_line(
        ws, H, 149, "func forward07(v string) string {",
        "func forward07(v string) string { // l2"))

    return S


# ---------------------------------------------------------------- 执行
def main():
    global BASE
    BASE = load_base()
    scs = scenarios()
    assert len(scs) == 50, "样本数=%d，应为 50" % len(scs)

    root = tempfile.mkdtemp(prefix="incbt_root_")
    tp = fp = fn_ = 0
    mismatches, label_fails = [], []
    for sc in scs:
        ws = make_ws(root)
        try:
            sc.setup(ws)
            cold_inc = run_scan(ws, "inc")          # 冷缓存
            cold_full = run_scan(ws, "full")
            sc.mutate(ws)
            warm_inc = run_scan(ws, "inc")          # 热缓存（复用上一轮的缓存）
            warm_full = run_scan(ws, "full")
        finally:
            shutil.rmtree(ws, ignore_errors=True)

        ok = True
        if cold_inc != cold_full:
            mismatches.append((sc.name, "cold", cold_inc ^ cold_full))
            ok = False
        if warm_inc != warm_full:
            mismatches.append((sc.name, "warm", warm_inc ^ warm_full))
            ok = False
        expect = sc.expect(set(BASE)) if sc.expect else set(BASE)
        got = warm_inc
        tp += len(expect & got)
        fp += len(got - expect)
        fn_ += len(expect - got)
        if got != expect:
            label_fails.append((sc.name, sorted(expect - got), sorted(got - expect)))
            ok = False
        print("%s %-32s findings=%d" % ("PASS" if ok else "FAIL", sc.name, len(got)))

    recall = tp / (tp + fn_) if (tp + fn_) else 1.0
    fpr = fp / (tp + fp) if (tp + fp) else 0.0
    print("\n== 50 样本回测 ==")
    print("TP=%d FP=%d FN=%d  recall=%.1f%%  false_positive_rate=%.1f%%"
          % (tp, fp, fn_, recall * 100, fpr * 100))
    print("增量==全量 不一致样本: %d  标注不一致样本: %d"
          % (len(mismatches), len(label_fails)))
    for name, phase, diff in mismatches:
        print("  MISMATCH %s [%s] %s" % (name, phase, sorted(diff)))
    for name, missed, extra in label_fails:
        print("  LABEL %s missed=%s extra=%s" % (name, missed, extra))

    shutil.rmtree(root, ignore_errors=True)
    ok = (not mismatches) and recall >= 0.85 and fpr <= 0.15
    print("VERDICT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
