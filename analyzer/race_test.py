#!/usr/bin/env python3
"""race_test —— 验证两个/多个进程同时扫同一仓库时缓存的一致性。

一致性论证（被测对象的设计依据）：
1. 缓存条目按内容哈希寻址：同一输入必然算出同一条目，因此并发写不会"写坏"，
   最坏情况是重复计算或丢条目（只损失性能，不产生错误结论）。
2. 写盘是 临时文件 + os.replace 原子替换：读者只能看到完整旧版或完整新版，
   永远读不到半拉文件。
3. 读-改-写合并全程持互斥锁（O_EXCL 锁文件 + stale 检测），防止丢更新。
4. 任何条目被采用前都重新校验输入哈希，缓存只是提示，不是事实来源。

测试方式：真进程并发（不是线程），外加 INCSCAN_SLEEP_AFTER_LOCK 钩子
人为拉宽临界区窗口，把低概率竞争变成必然交错。
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SCAN = os.path.join(HERE, "scan.py")


def make_ws(root):
    ws = tempfile.mkdtemp(prefix="incrace_", dir=root)
    for name in ("main.go", "go.mod"):
        shutil.copy(os.path.join(REPO, name), os.path.join(ws, name))
    shutil.copytree(os.path.join(REPO, "pkg"), os.path.join(ws, "pkg"))
    return ws


def run_scan(ws, mode="inc", env_extra=None, timeout=120):
    out = os.path.join(ws, "out_%s_%d.sarif" % (mode, os.getpid()))
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, SCAN, mode, "--repo", ws, "--sarif", out],
        capture_output=True, text=True, timeout=timeout, env=env), out


def findings_of(sarif_path):
    with open(sarif_path, encoding="utf-8") as fh:
        doc = json.load(fh)
    return sorted(
        (r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
         r["locations"][0]["physicalLocation"]["region"]["startLine"])
        for r in doc["runs"][0]["results"])


def edit_line(ws, rel, lineno, old, new):
    p = os.path.join(ws, rel)
    with open(p, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    assert old in lines[lineno - 1]
    lines[lineno - 1] = new
    with open(p, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def cache_ok(ws):
    d = os.path.join(ws, ".scancache")
    leftover_tmp = [f for f in os.listdir(d) if ".tmp." in f]
    with open(os.path.join(d, "index.json"), encoding="utf-8") as fh:
        json.load(fh)  # 必须是完整合法的 JSON
    return not leftover_tmp and not os.path.exists(os.path.join(d, "lock"))


def parallel_scans(ws, n, env_extra=None):
    procs, outs = [], []
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    for i in range(n):
        out = os.path.join(ws, "par_%d.sarif" % i)
        procs.append(subprocess.Popen(
            [sys.executable, SCAN, "inc", "--repo", ws, "--sarif", out],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env))
        outs.append(out)
    rcs, errs = [], []
    for p in procs:
        _, err = p.communicate(timeout=180)
        rcs.append(p.returncode)
        errs.append(err.strip())
    bad = [e for e in errs if e]
    return rcs, outs, "; ".join(bad)[:400]


def main():
    root = tempfile.mkdtemp(prefix="incrace_root_")
    failures = []

    def check(name, cond, detail=""):
        print("%s %s %s" % ("PASS" if cond else "FAIL", name, detail))
        if not cond:
            failures.append(name)

    # T1: 8 进程并发扫同一仓库（含冷缓存竞争建缓存），结论必须全部等于全量
    ws = make_ws(root)
    rcs, outs, errs = parallel_scans(ws, 8,
                                     env_extra={"INCSCAN_SLEEP_AFTER_LOCK": "0.2"})
    _, full_out = run_scan(ws, "full")
    full = findings_of(full_out)
    check("t1-concurrent-cold-cache",
          all(rc == 0 for rc in rcs) and
          all(findings_of(o) == full for o in outs) and cache_ok(ws),
          "rcs=%s %s" % (rcs, errs))
    shutil.rmtree(ws, ignore_errors=True)

    # T2: 交替变更 + 4 进程并发热扫描，每轮结论都必须等于当轮全量
    ws = make_ws(root)
    run_scan(ws)  # 建缓存
    ok = True
    for rnd in range(4):
        # 每轮翻转 b1：去掉/恢复 SafeHandle08 的净化
        if rnd % 2 == 0:
            edit_line(ws, "pkg/handlers/handlers.go", 168,
                      "clean :=", "\tclean := raw")
        else:
            edit_line(ws, "pkg/handlers/handlers.go", 168,
                      "clean := raw",
                      "\tclean := strings.ReplaceAll(raw, \"'\", \"\")")
        rcs, outs, errs = parallel_scans(ws, 4)
        _, full_out = run_scan(ws, "full")
        full = findings_of(full_out)
        rnd_ok = all(rc == 0 for rc in rcs) and \
            all(findings_of(o) == full for o in outs) and cache_ok(ws)
        if not rnd_ok:
            print("  t2 round %d: rcs=%s %s" % (rnd, rcs, errs))
        ok = ok and rnd_ok
    check("t2-mutate-and-race-x4", ok)
    shutil.rmtree(ws, ignore_errors=True)

    # T3: 锁互斥 —— 锁被占时短超时进程必须报错退出，解锁后必须成功
    ws = make_ws(root)
    lock = os.path.join(ws, ".scancache", "lock")
    os.makedirs(os.path.dirname(lock), exist_ok=True)
    fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    os.write(fd, b'{"pid": 999999}')
    proc, _ = run_scan(ws, env_extra={"INCSCAN_LOCK_TIMEOUT": "1"})
    blocked = proc.returncode == 3 and "lock" in proc.stderr.lower()
    os.close(fd)
    os.remove(lock)
    proc2, _ = run_scan(ws)
    check("t3-lock-exclusion", blocked and proc2.returncode == 0,
          "blocked_rc=%s after_rc=%s" % (proc.returncode, proc2.returncode))

    # T4: stale 锁（持有者已死，mtime 超过阈值）必须被破锁，扫描照常完成
    old = time.time() - 200
    fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    os.close(fd)
    os.utime(lock, (old, old))
    proc3, _ = run_scan(ws, env_extra={"INCSCAN_LOCK_TIMEOUT": "5"})
    check("t4-stale-lock-breaking", proc3.returncode == 0 and cache_ok(ws))
    shutil.rmtree(ws, ignore_errors=True)

    # T5: 拉宽临界区（持锁后 sleep），两进程必然交错，结论仍须一致且缓存完好
    ws = make_ws(root)
    run_scan(ws)
    edit_line(ws, "pkg/handlers/handlers.go", 168, "clean :=", "\tclean := raw")
    rcs, outs, errs = parallel_scans(ws, 2,
                                     env_extra={"INCSCAN_SLEEP_AFTER_LOCK": "0.5"})
    _, full_out = run_scan(ws, "full")
    full = findings_of(full_out)
    check("t5-widened-race-window",
          all(rc == 0 for rc in rcs) and
          all(findings_of(o) == full for o in outs) and cache_ok(ws),
          "rcs=%s %s" % (rcs, errs))
    shutil.rmtree(ws, ignore_errors=True)

    shutil.rmtree(root, ignore_errors=True)
    print("\nVERDICT:", "PASS" if not failures else "FAIL %s" % failures)
    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main()
