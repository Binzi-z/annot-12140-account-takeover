# 支付网关的增量静态扫描

## 现状

`baseline/scan.py` 只做正则匹配，凡是出现 exec.Command / db.Query / os.Open / http.Get 就报。
召回够，误报高，`eval.py` 能算出具体数字。

## 语料

- `pkg/handlers.go`：14 个 handler，8 个真漏洞、6 个 decoy（同形状但过了净化）
- `main.go`：路由入口，参数来自 HTTP 查询串
- `labels.json`：真漏洞的文件、行号、sink 类别
- `eval.py`：算召回/误报

## 跑法

```
go build ./...
python baseline/scan.py > findings.json
python eval.py findings.json
```

## 增量扫描器（analyzer/）

```
python analyzer/scan.py inc  --repo . --sarif findings.sarif   # 增量（首次=全量）
python analyzer/scan.py full --repo . --sarif findings.sarif   # 全量
python analyzer/scan.py ci   --repo . --baseline main.sarif --sarif pr.sarif
python analyzer/backtest.py     # 50 条标注样本回测（召回/误报/增量==全量）
python analyzer/race_test.py    # 多进程并发扫描的缓存一致性测试
```

设计与并发一致性论证见 `docs/incremental.md`。
