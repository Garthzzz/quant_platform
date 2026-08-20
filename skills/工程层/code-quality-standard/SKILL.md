---
name: code-quality-standard
description: Enforces code quality standards — single responsibility (one function one thing), minimum interface (only necessary params, explicit return), error handling (every external operation has try-except, no bare except, no silent pass), atomic file write (write tmp then os.replace), batch DB operations in single transaction, UTF-8 encoding for all file IO. Chinese strings use triple quotes, no print Chinese to terminal (use debug.log). Use when writing any Python module, when reviewing code, or when porting from another codebase.
metadata:
  category: engineering
  version: 1.0.0
  evidence_grade: user 实测 (CLAUDE3 工程规范)
---

# code-quality-standard — 代码质量 + 算法效率

## 视角

写出 user 在生产环境实际跑得通的代码。**准确性 > 优化**,但**优化也不可缺**。

## 代码架构标准

### 1. 单一职责

每个函数**只做一件事**。

- 扫描函数只扫描,不写库
- 写库函数只写库,不格式化
- 格式化函数只格式化,不验证

### 2. 最小接口

- 只传必要参数
- 返回值明确(成功 / 失败状态 + 错误信息)
- 不传"context 字典"等模糊参数

### 3. 错误处理

**每个外部操作必须有 try-except**,不允许:
- 裸 `except:`
- `except: pass`(silent 吞异常)

错误信息包含:
- 操作类型(`scan_pdf` / `write_db` 等)
- 输入参数
- 具体原因
- 写入 `debug.log`

```python
# 正确
try:
    result = some_external_op(arg1, arg2)
except SpecificError as e:
    logger.error(f"some_external_op failed: arg1={arg1}, arg2={arg2}, error={e}")
    raise OperationFailed(f"Cannot complete: {e}") from e

# 错误
try:
    result = some_external_op(arg1, arg2)
except:
    pass
```

### 4. 原子写入

所有文件写入: **先写 `.tmp` 再 `os.replace` 重命名**:

```python
# 原子写入协议
tmp_path = path + ".tmp"
with open(tmp_path, "w", encoding="utf-8") as f:
    f.write(content)
os.replace(tmp_path, path)  # 原子重命名
```

数据库写操作: **包在事务中**:

```python
with sqlite3.connect(db_path) as conn:
    cur = conn.cursor()
    cur.execute("BEGIN")
    try:
        for record in records:
            cur.execute("INSERT INTO papers VALUES (?, ?, ?)", record)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
```

## 算法效率标准

### 1. 复杂度

- 能 O(n) 不用 O(n²)
- 单次 SQL 取全量数据做集合运算,**不逐行查询**

```python
# 正确 — 单次 SQL + Python set 运算
existing_ids = set(row[0] for row in conn.execute("SELECT id FROM papers"))
new_papers = [p for p in scanned if p.id not in existing_ids]

# 错误 — 逐行查询
new_papers = []
for p in scanned:
    if not conn.execute("SELECT 1 FROM papers WHERE id=?", (p.id,)).fetchone():
        new_papers.append(p)
```

### 2. 批量处理

批量写库用**单事务**包裹所有 INSERT,不是每条一个事务。

### 3. 数据库

- 高频查询字段建表时**一并创建索引**
- 不在 Python 层过滤能在 SQL 层过滤的数据
- SQLite 连接后设置:

```python
conn.execute("PRAGMA journal_mode=WAL")
conn.execute("PRAGMA synchronous=NORMAL")
```

### 4. 并行调度

Engineer 管理全局任务队列,每个 Subagent 只接受单篇任务,**文件系统作为唯一 IPC 介质**(per `engineering/parallel-subagent-orchestration`)。

## 工程规范

- **Python 含中文字符串用三引号**,不用双引号硬编码
- **所有文件读写指定 `encoding='utf-8'`**
- **禁止 print 中文到终端**,调试信息写 debug.log
- **关键操作记录开始和结束时间**,批量操作完成后输出汇总
- **写库后验证查询,导出后验证列数**,不做自检的代码不算完成
- **执行多行 Python 脚本必须写入临时文件再执行**,执行完删除:

```bash
# 正确
echo "..." > pipeline/_tmp_xxx.py
python pipeline/_tmp_xxx.py
rm pipeline/_tmp_xxx.py

# 错误 — heredoc 在中文/路径/引号混合时会因引号冲突解析失败
python << 'PYEOF'
...
PYEOF
```

## Docstring 规范(中文,per `core/chinese-output` + `design/interface-contract`)

每个函数必须有**中文 docstring**,注明输入输出的 shape + 单位:

```python
def my_func(x: torch.Tensor) -> torch.Tensor:
    """函数简短说明.

    Args:
        x: 输入 tensor, shape (N, F), 已经 z-score 化 (per design/interface-contract)
            N 是截面股票数, F 是特征数

    Returns:
        预测值 tensor, shape (N,), dimensionless (cross-sectional rank-like)
    """
    ...
```

## 反模式

- ❌ 裸 except / except: pass
- ❌ 多个责任混在一个函数(扫描 + 写库 + 格式化)
- ❌ 文件直接 write 不用 `.tmp` + `os.replace`
- ❌ 数据库多个独立事务跑一批 INSERT
- ❌ 中文用双引号硬编码
- ❌ Print 中文到终端
- ❌ Heredoc 执行含中文 Python
- ❌ 写库后不验证查询就 claim done
- ❌ Docstring 英文(应中文,per chinese-output)

## 与其他 skill 的关系

- 与 `core/chinese-output`: 互文 — docstring 中文
- 与 `design/interface-contract`: 必读 — 单位 / shape 必明示
- 与 `engineering/outcome-based-verification`: 必读 — 写库后验证查询
- 与 `engineering/parallel-subagent-orchestration`: 互文 — 文件 IPC

## Provenance

来自 user CLAUDE3 完整实测的工程规范:
- 单一职责 / 最小接口 / 错误处理 / 原子写入
- O(n) 优先 / SQL 集合运算 / 批量单事务 / SQLite WAL
- 禁止 print 中文 / heredoc 执行 / 三引号中文 / utf-8 encoding

每条规则都来自实际生产 bug。
