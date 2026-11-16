# CI 定义副本（激活方式见下）

本文件与 `.github/workflows/tests.yml` 内容一致，放在 `ci/` 下是因为
**通过 API 向 `.github/workflows/` 写入需要 token 具备 `workflow` scope**，
而普通 `repo` scope 的 token 会被 GitHub 拒绝（返回 404）。

## 激活方式（任选其一）

1. **网页复制（最快）**：打开
   `https://github.com/wushulin111/ir-forensic-analysis/new/main/.github/workflows`
   文件名填 `tests.yml`，把本文件内容粘贴进去提交。
2. **有 workflow 权限的 token**：
   ```bash
   gh auth refresh -h github.com -s workflow
   git add .github/workflows/tests.yml && git commit -m "ci: enable" && git push
   ```

## 工作流做什么

- 矩阵：ubuntu-latest / windows-latest × Python 3.11 / 3.12
- 跑 `python -m unittest discover -s tests`
- 跑 `python scripts/parsers_registry.py --list`
- **故意不安装** evtx / regipy / dissect.util / dissect.esedb / olefile，
  用于验证"缺依赖时跳过而不崩"的降级路径
