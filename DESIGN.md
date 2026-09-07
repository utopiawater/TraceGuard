# Design System

## Intent

面向明亮教室里使用笔记本并投影答辩的安全调查工作台：像一本结构清楚的取证案卷，关键异常用琥珀色标记，事实和证据保持冷静、可扫描。

## Theme

- 默认使用高可读的浅色主题；数据图谱画布可使用略深的独立工作区，但不把整个产品做成“黑客暗色”。
- 色彩策略为 restrained：中性表面承载大部分信息，主色只用于当前选择、主要操作和需要关注的候选状态。
- 页面优先适配 1440×900 与教室投影，同时在 1024px 宽度折叠侧栏，在手机宽度转为单列检查模式。

## Color Tokens

所有颜色以 OKLCH 定义。

```css
:root {
  --color-bg: oklch(1 0 0);
  --color-surface: oklch(0.972 0.006 250);
  --color-surface-raised: oklch(0.992 0.003 250);
  --color-ink: oklch(0.23 0.018 250);
  --color-muted: oklch(0.48 0.022 250);
  --color-border: oklch(0.89 0.012 250);
  --color-primary: oklch(0.62 0.17 53);
  --color-primary-soft: oklch(0.94 0.045 65);
  --color-accent: oklch(0.43 0.105 235);
  --color-accent-soft: oklch(0.94 0.025 235);
  --color-success: oklch(0.55 0.12 150);
  --color-warning: oklch(0.66 0.15 75);
  --color-danger: oklch(0.55 0.19 28);
  --color-info: oklch(0.57 0.13 245);
}
```

红色仅表示已确认的高危或失败；候选攻击链使用琥珀主色；未知与未接入状态使用带文字的中性色。图表和徽标始终配合图标、线型或文本标签。

## Typography

- UI 使用 `Inter, "Noto Sans SC", "Microsoft YaHei", system-ui, sans-serif` 单一字体族。
- 基准字号 14px，正文行高 1.55；密集表格可用 13px，但不降低关键证据可读性。
- 标题采用 16/20/26px 的固定层级，字距不小于 -0.02em；标签与按钮不使用展示字体。
- 标识符、哈希、IP、端口和时间使用 `"JetBrains Mono", "Cascadia Code", monospace`，允许安全换行。

## Layout

- 桌面应用壳：232px 侧栏、56px 顶栏、可滚动主内容；窄屏使用抽屉式导航。
- 页面水平留白 24px，主区最大宽度不强制收窄；调查说明文本限制在 72ch。
- 以分栏、表格、时间线和工作区组织数据。卡片只用于真正独立的状态单元，不嵌套卡片。
- 攻击链页采用主画布 + 右侧检查器；证据区采用可复制表格和详情抽屉。

## Components

- `AppShell`：侧栏、顶栏、运行模式、时间范围、源缺口。
- `PageHeader`：页面标题、上下文摘要和当前资源操作。
- `StatusBadge`：文本、图标和颜色三重表达 live/replay/snapshot/partial/failed。
- `DataTable`：稳定列宽、键盘焦点、空状态、错误状态与横向滚动。
- `FilterBar`：URL 同步的 case、时间、资产、Technique 和来源筛选。
- `EvidenceDrawer`：raw/normalized 切换、来源字段、完整性哈希、复制操作。
- `ChainCanvas`：Cytoscape.js 关系图，事实边实线、候选边虚线、节点上限提示。
- `MetricStrip`：少量相关指标的连续横条，不使用重复英雄数字卡。
- `EmptyState`：说明缺少什么、为什么缺少，以及接入数据源或清除筛选的下一步。

每个交互组件具有 default、hover、focus-visible、active、disabled、loading 和 error 状态。

## Data Visualization

- ECharts 用于时间趋势、来源分布、时间质量和 ATT&CK 热力矩阵。
- Cytoscape.js 用于攻击链与实体关系图，默认最多 100 个节点。
- 图表旁提供可访问文本摘要，tooltip 只补充信息而不是承载唯一含义。

## Motion

- 状态过渡 160–220ms，采用 ease-out；只表达侧栏展开、筛选应用、抽屉出现和数据更新。
- 不设计编排式页面入场动画，不让内容初始不可见。
- `prefers-reduced-motion: reduce` 下取消位移和非必要过渡。

## Content Rules

- 用“未接入数据源”“当前筛选范围暂无事件”“分析部分完成”等具体文案替代笼统的“暂无数据”。
- 事实写“已观测/已确认”，推断写“候选/可能”，信息不足写“无法判断”。
- 不把 ATT&CK 覆盖率解释为防护能力，不把 TTP 相似性表述为现实身份确认。
