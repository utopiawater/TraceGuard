# Datasets

公开数据集只在此目录保存 manifest、校验哈希、许可说明和可复现小切片。每个 Dataset Adapter 必须输出 `RawEventEnvelope`，之后复用 `AnalysisPipeline`；禁止复制检测、图投影或攻击链逻辑。

