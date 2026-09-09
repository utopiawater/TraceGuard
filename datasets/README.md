# Datasets

公开数据集只在此目录保存 manifest、校验哈希、许可说明和可复现小切片。每个 Dataset Adapter 必须输出 `RawEventEnvelope`，之后复用 `AnalysisPipeline`；禁止复制检测、图投影或攻击链逻辑。

## DARPA TC E3 CADets

完整 DARPA TC E3 CADets 数据集不是仓库自带内容，也不应直接提交到 GitHub。仓库内只保留代码、说明、运行报告和用于单元测试的最小 fixture。

如果需要运行真实 DARPA 数据集集成测试或重新生成评估报告，请将处理后的文件放到：

```text
datasets/darpa_tc_e3_cadets/processed_dataset/
  process_events.json
  network_events.json
  file_events.json
```

可选的评估元数据放到：

```text
datasets/darpa_tc_e3_cadets/source_metadata/
  selection_manifest.json
```

没有安装完整数据集时，普通 `pytest -q` 会运行单元测试和仓库内小样本测试；依赖真实 DARPA 文件的集成测试会显示 skipped，而不是 failed。

仓库内的小样本位于：

```text
backend/fixtures/datasets/darpa_tc_e3_cadets/
```

该目录仅是 `minimal test fixture`，用于覆盖 `DarpaTcE3CadetsAdapter` 的主要字段转换，不代表完整 DARPA 数据集，也不能用于 IOC 覆盖率、性能或课程实验结论。

