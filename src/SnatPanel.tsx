import { useMemo, useState } from 'react'
import { evaluateSnat } from './audit/snat'
import type {
  SnatCategorySummary,
  SnatFormInput,
  SnatPacket,
  SnatResult,
  SnatTraceGroup,
} from './audit/snat'
import { evaluateSnatCollision } from './audit/snatcollision'
import type { SnatCollisionResult } from './audit/snatcollision'
import { TANDEM_CATEGORY_ORDER } from './audit/tandem'
import type { TandemCategory, TandemRuleRef } from './audit/tandem'
import { parseRulesJson, validateRules } from './audit/engine'
import type { ExactRegionGroup, RuleInput } from './audit/types'
import { formatPacket, formatPercent, formatPortRange, formatSize } from './format'

interface Props {
  rules: RuleInput[]
}

const CATEGORY_META: Record<
  TandemCategory,
  { label: string; badge: string; card: string }
> = {
  pass: { label: '最终通过', badge: 'reachable', card: 'ok' },
  'blocked-stage1': { label: '前级阻断', badge: 'fully-shadowed', card: 'danger' },
  'blocked-stage2': { label: '后级阻断', badge: 'partial-shadowed', card: 'warn' },
}

const EXAMPLE_STAGE2_JSON = `[
  { "name": "放行转换后办公网", "cidr": "192.168.10.0/24", "portStart": 0, "portEnd": 65535,
    "protocol": "ANY", "action": "allow" },
  { "name": "默认拒绝", "cidr": "0.0.0.0/0", "portStart": 0, "portEnd": 65535,
    "protocol": "ANY", "action": "deny" }
]`

const EXAMPLE_MAPPINGS = `10.0.0.0/24 -> 192.168.10.0/24
10.0.1.0/24 -> 192.168.11.0/24`

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      type="button"
      className="copy-mini"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text)
          setCopied(true)
          setTimeout(() => setCopied(false), 1200)
        } catch {
          setCopied(false)
        }
      }}
    >
      {copied ? '已复制' : '复制'}
    </button>
  )
}

/** 代表报文单行：原始报文 +（进入后级时）转换后地址 */
function snatPacketText(p: SnatPacket): string {
  const base = formatPacket(p)
  return p.translatedSrcIp === null
    ? base
    : `${base} → 转换后 src=${p.translatedSrcIp}:${p.srcPort}`
}

/** 精确区域：协议 → 连续端口段 × 规范 CIDR（行式，互斥且完备，原始地址空间） */
function RegionView({ regions }: { regions: ExactRegionGroup[] }) {
  if (regions.length === 0) {
    return <div className="muted-text" style={{ paddingLeft: 12 }}>（无区域）</div>
  }
  return (
    <div className="code-list">
      {regions.map((reg) => (
        <div key={reg.protocol} className="line">
          <strong>{reg.protocol}</strong>
          <span className="muted-text">（{formatSize(reg.size)} 条报文空间）</span>
          {reg.rows.map((row, i) => (
            <div key={i} className="muted-text" style={{ paddingLeft: 12 }}>
              端口 {formatPortRange(row.portStart, row.portEnd)} × {row.cidrs.join(', ')}
              <span className="muted-text">（{formatSize(row.size)}）</span>
            </div>
          ))}
        </div>
      ))}
    </div>
  )
}

/** 某一级的首命中规则引用 / 未命中 / 未进入该级 */
function StageRefView({
  stage,
  ref_,
  entered,
}: {
  stage: string
  ref_: TandemRuleRef | null
  entered: boolean
}) {
  if (!entered) {
    return <span className="action-pill conflict-pill">{stage}：未进入</span>
  }
  if (!ref_) {
    return <span className="action-pill conflict-pill">{stage}：未命中任何规则</span>
  }
  return (
    <span className="traffic-side">
      <span className="muted-text">{stage}</span>
      <span className="idx-cell">#{ref_.index + 1}</span>
      <span className="reorder-rule-name">{ref_.name}</span>
      <span className="action-pill">{ref_.action}</span>
    </span>
  )
}

/** 分组的判定理由（为什么阻断 / 通过） */
function groupReason(group: SnatTraceGroup): string {
  if (group.category === 'pass') return '两级首命中动作均在各自放行列表内 → 最终通过'
  if (group.category === 'blocked-stage1') {
    return group.stage1 === null
      ? '前级未命中任何规则 → 阻断（不发生转换，不进入后级）'
      : `前级首命中动作「${group.stage1.action}」不在放行列表内 → 阻断（不发生转换，不进入后级）`
  }
  return group.stage2 === null
    ? '转换后地址在后级未命中任何规则 → 阻断'
    : `后级首命中动作「${group.stage2.action}」不在放行列表内 → 阻断`
}

/** 一条分级命中轨迹分组卡片 */
function TraceGroupCard({ group }: { group: SnatTraceGroup }) {
  const meta = CATEGORY_META[group.category]
  return (
    <div className={`takeover-block ${group.category === 'pass' ? '' : 'conflict-block'}`}>
      <div className="takeover-head">
        <span className={`badge ${meta.badge}`}>{meta.label}</span>
        <StageRefView stage="前级" ref_={group.stage1} entered />
        <span className="reorder-arrow">→</span>
        <StageRefView stage="后级" ref_={group.stage2} entered={group.enteredStage2} />
        <span className="spacer" />
        <span className="muted-text">
          {formatSize(group.size)} 条报文空间（{group.cells} 个原子单元）
        </span>
      </div>
      <div className="packet-box">
        <span className="tag shadowed">代表报文</span>
        <span className="mono">{snatPacketText(group.packet)}</span>
        <span className="arrow-note">{groupReason(group)}</span>
        <CopyButton text={snatPacketText(group.packet)} />
      </div>
      <RegionView regions={group.regions} />
    </div>
  )
}

/** 一个类别的完整小节：汇总 + 带轨迹的代表报文 + 精确区域 + 轨迹分组 */
function CategorySection({ summary }: { summary: SnatCategorySummary }) {
  const meta = CATEGORY_META[summary.category]
  return (
    <div className="snapshot-category">
      <h3 className="reorder-section-title" style={{ marginTop: 14 }}>
        <span className={`badge ${meta.badge}`}>{meta.label}</span>{' '}
        <span className="muted-text" style={{ fontWeight: 400 }}>
          {formatSize(summary.size)} 条报文空间（{formatPercent(summary.ratio)}） ·{' '}
          {summary.cells} 个原子单元
        </span>
      </h3>

      <div className="goal-block-title">
        代表报文（每个具体协议一个，含转换后地址与分级命中轨迹，可复制复现）
      </div>
      {summary.examples.map((p, i) => (
        <div className="packet-box" key={i}>
          <span className="tag shadowed">代表报文</span>
          <span className="mono">{snatPacketText(p)}</span>
          <span className="arrow-note">
            前级：
            {p.stage1 ? `#${p.stage1.index + 1} ${p.stage1.name}（${p.stage1.action}）` : '未命中'}
            {' → '}
            {p.enteredStage2
              ? `后级：${p.stage2 ? `#${p.stage2.index + 1} ${p.stage2.name}（${p.stage2.action}）` : '未命中'}`
              : '未进入后级（不发生转换）'}
          </span>
          <CopyButton text={snatPacketText(p)} />
        </div>
      ))}

      <div className="goal-block-title">精确区域（原始地址空间：协议 → 连续端口段 × 规范 CIDR）</div>
      <RegionView regions={summary.regions} />

      <div className="goal-block-title">
        分级命中轨迹分组（同一组内每个报文的两级首命中轨迹相同，共 {summary.groups.length} 组）
      </div>
      {summary.groups.map((g, i) => (
        <TraceGroupCard key={i} group={g} />
      ))}
    </div>
  )
}

function SnatResultView({ result }: { result: SnatResult }) {
  const cats = result.categories
  const t = result.target
  const allPass = cats['blocked-stage1'].cells === 0 && cats['blocked-stage2'].cells === 0
  const stageSummary = (label: string, s: SnatResult['stage1'], allow: string[]) => (
    <>
      {label}：{s.active} 条合法且启用的规则参与重放
      {s.invalid > 0 ? `，${s.invalid} 条非法已排除` : ''}
      {s.disabled > 0 ? `，${s.disabled} 条停用已排除` : ''}
      ；放行动作 = {allow.map((a) => (
        <span key={a} className="action-pill" style={{ marginRight: 4 }}>
          {a}
        </span>
      ))}
    </>
  )

  return (
    <div className="snapshot-report">
      <div className="legend" style={{ marginTop: 0, marginBottom: 10 }}>
        目标 <span className="mono">{t.cidrText}</span> · 端口{' '}
        {formatPortRange(t.portStart, t.portEnd)} · 协议 {t.protocol} · 目标总空间{' '}
        {formatSize(result.totalSize)}。
        {stageSummary('前级（当前规则，按原始地址首命中）', result.stage1, result.allow1)}
        <br />
        {stageSummary('后级（粘贴规则，按转换后地址首命中）', result.stage2, result.allow2)}
        <br />
        源地址映射：
        {result.mappings.map((m) => (
          <span key={m.sourceText} className="mono" style={{ marginRight: 10 }}>
            {m.sourceText} → {m.translatedText}
          </span>
        ))}
        （主机位一一对应，端口与协议不改写）。后级 CIDR 边界已逆映射回原始空间，
        与目标、前级边界合并切分后逐单元重放；区域与代表报文均以原始地址展示，
        进入后级的报文附转换后地址。结果随当前规则编辑 / 调序确认自动刷新。
      </div>

      {allPass ? (
        <div className="notice ok">
          ✓ 目标空间全部最终通过：每个报文前级放行、转换后地址在后级也放行。
        </div>
      ) : (
        <div className="notice error">
          ✗ 目标未全部通过：前级阻断 {formatSize(cats['blocked-stage1'].size)}（
          {formatPercent(cats['blocked-stage1'].ratio)}），后级阻断{' '}
          {formatSize(cats['blocked-stage2'].size)}（
          {formatPercent(cats['blocked-stage2'].ratio)}）。明细见下方分类。
        </div>
      )}

      <div className="stats">
        {TANDEM_CATEGORY_ORDER.map((c) => (
          <div className={`stat-card ${CATEGORY_META[c].card}`} key={c}>
            <div className="label">{CATEGORY_META[c].label}</div>
            <div className="value" style={{ fontSize: 16 }}>
              {formatSize(cats[c].size)}
            </div>
            <div className="label">
              {formatPercent(cats[c].ratio)} · {cats[c].cells} 个原子单元
            </div>
          </div>
        ))}
      </div>

      {t.protocol === 'ANY' && (
        <div style={{ overflowX: 'auto', marginBottom: 12 }}>
          <table className="rule-table goal-proto-table">
            <thead>
              <tr>
                <th>协议（ANY 分别重放）</th>
                <th>最终通过</th>
                <th>前级阻断</th>
                <th>后级阻断</th>
              </tr>
            </thead>
            <tbody>
              {result.perProtocol.map((p) => (
                <tr key={p.protocol}>
                  <td>{p.protocol}</td>
                  <td className="goal-num">{formatSize(p.passSize)}</td>
                  <td className="goal-num">{formatSize(p.blockedStage1Size)}</td>
                  <td className="goal-num">{formatSize(p.blockedStage2Size)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {TANDEM_CATEGORY_ORDER.filter((c) => cats[c].cells > 0).map((c) => (
        <CategorySection key={c} summary={cats[c]} />
      ))}
    </div>
  )
}

/** 转换后源身份碰撞分析结果（只读；只依赖前级放行、源地址映射与目标，不使用后级规则） */
function SnatCollisionView({ result }: { result: SnatCollisionResult }) {
  const mappingText = (i: number) =>
    `#${i + 1} ${result.mappings[i].sourceText} → ${result.mappings[i].translatedText}`
  return (
    <div className="snapshot-report" style={{ marginTop: 22 }}>
      <h3 className="reorder-section-title" style={{ marginTop: 0 }}>
        转换后源身份碰撞（只读 · 独立于后级规则）
      </h3>
      <div className="legend" style={{ marginTop: 0, marginBottom: 10 }}>
        仅目标内<strong>经前级首命中放行</strong>的报文参与（{formatSize(result.releasedSize)}{' '}
        条报文空间，{result.releasedCells} 个原子单元；前级未命中、动作不在放行列表、
        非法与停用规则的处理与上方路径分析完全一致）。每条等长映射把放行的原始
        IPv4×端口×协议区域投影到转换后空间后逐对求交：同一条转换后报文被两条映射的
        放行报文同时占用即碰撞。转换后网段重叠但实际放行区域投影不交时不报碰撞；
        多对重叠时总量按转换后报文去重。本分析不读取后级规则与后级放行动作。
      </div>

      {result.pairs.length === 0 ? (
        <div className="notice ok">
          ✓ 无转换后源身份碰撞：没有任何转换后报文被两条映射的放行报文同时占用。
        </div>
      ) : (
        <>
          <div className="notice error">
            ✗ 发现 {result.pairs.length} 对映射发生转换后源身份碰撞：按转换后报文去重共{' '}
            {formatSize(result.totalSize)} 条报文空间（{result.totalCells} 个原子单元）。
          </div>

          <div className="stats">
            <div className="stat-card danger">
              <div className="label">碰撞映射对</div>
              <div className="value">{result.pairs.length}</div>
            </div>
            <div className="stat-card danger">
              <div className="label">碰撞总量（转换后报文去重）</div>
              <div className="value" style={{ fontSize: 16 }}>
                {formatSize(result.totalSize)}
              </div>
            </div>
            <div className="stat-card">
              <div className="label">参与计算的放行空间</div>
              <div className="value" style={{ fontSize: 16 }}>
                {formatSize(result.releasedSize)}
              </div>
            </div>
          </div>

          <div className="goal-block-title">
            整体碰撞区域（全部碰撞映射对合并，按转换后报文去重；转换后地址空间）
          </div>
          <RegionView regions={result.regions} />

          <div className="goal-block-title">
            逐对碰撞明细（共 {result.pairs.length} 对，按碰撞空间降序）
          </div>
          {result.pairs.map((pair) => (
            <div className="takeover-block conflict-block" key={`${pair.a}.${pair.b}`}>
              <div className="takeover-head">
                <span className="badge fully-shadowed">碰撞</span>
                <span className="mono">{mappingText(pair.a)}</span>
                <span className="reorder-arrow">×</span>
                <span className="mono">{mappingText(pair.b)}</span>
                <span className="spacer" />
                <span className="muted-text">
                  {formatSize(pair.size)} 条转换后报文空间（{pair.cells} 个原子单元）
                </span>
              </div>
              <div className="packet-box">
                <span className="tag shadowed">见证报文 A</span>
                <span className="mono">{snatPacketText(pair.witness.packetA)}</span>
                <span className="arrow-note">经映射 #{pair.a + 1} 转换</span>
                <CopyButton text={snatPacketText(pair.witness.packetA)} />
              </div>
              <div className="packet-box">
                <span className="tag shadowed">见证报文 B</span>
                <span className="mono">{snatPacketText(pair.witness.packetB)}</span>
                <span className="arrow-note">经映射 #{pair.b + 1} 转换</span>
                <CopyButton text={snatPacketText(pair.witness.packetB)} />
              </div>
              <div className="packet-box">
                <span className="tag shadowed">同一转换后报文</span>
                <span className="mono">{formatPacket(pair.witness.translated)}</span>
                <span className="arrow-note">两条不同原始报文转换后无法区分</span>
                <CopyButton text={formatPacket(pair.witness.translated)} />
              </div>
              <div className="goal-block-title">精确转换后碰撞区域</div>
              <RegionView regions={pair.regions} />
            </div>
          ))}
        </>
      )}

      {result.nonCollidingOverlaps.length > 0 && (
        <div className="notice info" style={{ marginTop: 10 }}>
          以下 {result.nonCollidingOverlaps.length} 对映射的转换后网段虽重叠，
          但实际放行区域的投影不相交（地址段 / 端口 / 协议不交），不报碰撞：
          {result.nonCollidingOverlaps.map(({ a, b }) => (
            <div key={`${a}.${b}`} className="mono" style={{ paddingLeft: 12 }}>
              {mappingText(a)}　×　{mappingText(b)}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export function SnatPanel({ rules }: Props) {
  const [stage2Json, setStage2Json] = useState('')
  const [allow1Text, setAllow1Text] = useState('allow')
  const [allow2Text, setAllow2Text] = useState('allow')
  const [mappingsText, setMappingsText] = useState('')
  const [targetForm, setTargetForm] = useState({
    cidr: '10.0.0.0/24',
    portStart: '0',
    portEnd: '65535',
    protocol: 'ANY',
  })
  const [submitted, setSubmitted] = useState<SnatFormInput | null>(null)

  const form: SnatFormInput = {
    stage2Json,
    allow1Text,
    allow2Text,
    mappingsText,
    target: targetForm,
  }

  // 只读分析：纯函数计算，不改动任何规则；当前规则编辑 / 调序确认后自动重算
  const outcome = useMemo(
    () => (submitted ? evaluateSnat(rules, submitted) : null),
    [rules, submitted],
  )

  // 转换后源身份碰撞：只复用前级放行动作、源地址映射与目标，独立于后级规则；
  // 因此即使后级 JSON / 后级放行动作有误，只要其所需输入合法仍可单独给出结果
  const collisionOutcome = useMemo(
    () => (submitted ? evaluateSnatCollision(rules, submitted) : null),
    [rules, submitted],
  )

  const dirty =
    submitted !== null &&
    (form.stage2Json !== submitted.stage2Json ||
      form.allow1Text !== submitted.allow1Text ||
      form.allow2Text !== submitted.allow2Text ||
      form.mappingsText !== submitted.mappingsText ||
      form.target.cidr !== submitted.target.cidr ||
      String(form.target.portStart) !== String(submitted.target.portStart) ||
      String(form.target.portEnd) !== String(submitted.target.portEnd) ||
      form.target.protocol !== submitted.target.protocol)

  // 动作建议：前级取当前规则动作；后级实时宽容解析粘贴的 JSON（仅用于输入建议）
  const stage1Actions = useMemo(
    () => [...new Set(rules.map((r) => r.action.trim()).filter(Boolean))],
    [rules],
  )
  const stage2Actions = useMemo(() => {
    if (!stage2Json.trim()) return []
    const { rules: parsed, errors } = parseRulesJson(stage2Json)
    if (errors.length > 0) return []
    return [...new Set(parsed.map((r) => r.action.trim()).filter(Boolean))]
  }, [stage2Json])

  // 前级规则构成提示（与分析同一套语义：合法且启用才参与）
  const stage1Stats = useMemo(() => {
    const { valid, invalid } = validateRules(rules)
    const disabled = valid.filter((r) => !r.enabled).length
    return { active: valid.length - disabled, invalid: invalid.length, disabled }
  }, [rules])

  const submit = () =>
    setSubmitted({
      stage2Json,
      allow1Text,
      allow2Text,
      mappingsText,
      target: { ...targetForm },
    })

  return (
    <div className="panel tandem-panel">
      <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap' }}>
        <h2 style={{ margin: 0 }}>源地址转换路径分析（只读）</h2>
        <span className="legend" style={{ marginLeft: 12 }}>
          当前规则为前级（按原始地址首命中），粘贴后级规则 JSON；仅前级放行的报文
          按源地址映射（主机位一一对应）转换后进入后级；目标必须完全落在映射源网段内；
          不修改任何规则。结果下方附「转换后源身份碰撞」分析（复用前级放行、映射与目标，
          独立于后级规则）：逐对检查两条映射的放行报文是否投影到同一条转换后报文。
        </span>
      </div>

      <div className="tandem-stage-grid">
        <div className="tandem-stage-block">
          <div className="goal-block-title" style={{ marginTop: 0 }}>
            前级：当前规则（{stage1Stats.active} 条合法启用参与重放
            {stage1Stats.invalid > 0 ? `，${stage1Stats.invalid} 条非法已排除` : ''}
            {stage1Stats.disabled > 0 ? `，${stage1Stats.disabled} 条停用已排除` : ''}）
          </div>
          <label>
            <span>前级放行动作列表（逗号 / 空格分隔，精确匹配）</span>
            <input
              list="snat-allow1-options"
              value={allow1Text}
              onChange={(e) => setAllow1Text(e.target.value)}
              placeholder="allow, permit"
              spellCheck={false}
            />
          </label>
          <datalist id="snat-allow1-options">
            {stage1Actions.map((a) => (
              <option key={a} value={a} />
            ))}
          </datalist>
        </div>

        <div className="tandem-stage-block">
          <div className="goal-block-title" style={{ marginTop: 0 }}>
            后级：粘贴同格式 JSON 规则（匹配转换后地址；非法 / 停用规则按现有语义排除）
          </div>
          <textarea
            value={stage2Json}
            onChange={(e) => setStage2Json(e.target.value)}
            placeholder={EXAMPLE_STAGE2_JSON}
            spellCheck={false}
          />
          <label>
            <span>后级放行动作列表（逗号 / 空格分隔，精确匹配）</span>
            <input
              list="snat-allow2-options"
              value={allow2Text}
              onChange={(e) => setAllow2Text(e.target.value)}
              placeholder="allow, permit"
              spellCheck={false}
            />
          </label>
          <datalist id="snat-allow2-options">
            {stage2Actions.map((a) => (
              <option key={a} value={a} />
            ))}
          </datalist>
        </div>
      </div>

      <div className="tandem-stage-block" style={{ marginTop: 12 }}>
        <div className="goal-block-title" style={{ marginTop: 0 }}>
          源地址映射（每行一条：源CIDR -&gt; 转换后CIDR；二者前缀等长，源网段两两不重叠）
        </div>
        <textarea
          className="snat-mappings-input"
          value={mappingsText}
          onChange={(e) => setMappingsText(e.target.value)}
          placeholder={EXAMPLE_MAPPINGS}
          spellCheck={false}
        />
      </div>

      <div className="goal-form tandem-target-form">
        <label>
          <span>目标 IPv4 CIDR（须完全落在映射源网段内）</span>
          <input
            value={targetForm.cidr}
            onChange={(e) => setTargetForm((f) => ({ ...f, cidr: e.target.value }))}
            placeholder="10.0.0.0/24"
            spellCheck={false}
          />
        </label>
        <label>
          <span>目标端口区间</span>
          <div className="port-cell">
            <input
              value={targetForm.portStart}
              onChange={(e) => setTargetForm((f) => ({ ...f, portStart: e.target.value }))}
              placeholder="0"
            />
            <span className="muted-text">–</span>
            <input
              value={targetForm.portEnd}
              onChange={(e) => setTargetForm((f) => ({ ...f, portEnd: e.target.value }))}
              placeholder="65535"
            />
          </div>
        </label>
        <label>
          <span>协议</span>
          <select
            value={targetForm.protocol}
            onChange={(e) => setTargetForm((f) => ({ ...f, protocol: e.target.value }))}
          >
            {['ANY', 'TCP', 'UDP'].map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
        </label>
        <button className="primary" onClick={submit}>
          执行分析
        </button>
      </div>

      {outcome && !outcome.ok && (
        <div className="notice error">
          <div style={{ fontWeight: 600, marginBottom: 4 }}>输入有误，已阻止分析：</div>
          {outcome.errors.map((e, i) => (
            <div key={i}>• {e}</div>
          ))}
        </div>
      )}

      {dirty && outcome?.ok && (
        <div className="notice info">
          输入已修改，以下结果仍对应上次分析；点击「执行分析」以新输入重新分析。
        </div>
      )}

      {!submitted && (
        <div className="notice info" style={{ marginBottom: 0 }}>
          粘贴后级规则 JSON、填写两级放行动作列表、源地址映射与目标空间后点击「执行分析」。
          后级 CIDR 边界将逆映射回原始空间，与目标和前级边界合并切分后逐单元重放；
          协议 ANY 将分别检查 TCP 与 UDP。下方同时给出「转换后源身份碰撞」分析：
          只使用前级放行动作、源地址映射与目标（与后级规则无关），
          逐对检查两条映射的放行报文是否会投影到同一条转换后报文。
        </div>
      )}

      {outcome?.ok && <SnatResultView result={outcome.result} />}
      {collisionOutcome?.ok && <SnatCollisionView result={collisionOutcome.result} />}
    </div>
  )
}
