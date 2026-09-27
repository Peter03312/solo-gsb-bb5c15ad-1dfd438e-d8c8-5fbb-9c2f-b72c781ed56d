/**
 * 转换后源身份碰撞分析引擎自检：
 * 仅目标内经前级首命中放行的报文参与（未命中 / 动作不放行 / 非法 / 停用
 * 沿用现有处理）、按每条等长映射把放行区域投影到转换后空间后逐对求交、
 * 网段重叠但端口 / 协议 / 地址投影不交不报碰撞、逐对碰撞空间与精确转换后
 * 区域、多对重叠总量按转换后报文去重、见证报文可暴力复现、输入错误阻止、
 * 分析独立于后级规则、确定性。
 */
import assert from 'node:assert'
import {
  analyzeSnatCollision,
  evaluateSnatCollision,
} from './audit/snatcollision'
import { parseSnatMappings } from './audit/snat'
import type { NormalizedSnatMapping } from './audit/snat'
import { validateTandemTarget } from './audit/tandem'
import { validateRules } from './audit/engine'
import { intToIpv4, ipv4ToInt, parseCidrStrict } from './audit/iputil'
import type { RuleInput } from './audit/types'

let passed = 0
function test(name: string, fn: () => void) {
  fn()
  passed++
  console.log(`  ✓ ${name}`)
}

let seq = 0
function rule(partial: Partial<RuleInput> & { id?: string }): RuleInput {
  return {
    id: partial.id ?? `t${seq++}`,
    name: partial.name ?? `R${seq}`,
    cidr: partial.cidr ?? '0.0.0.0/0',
    portStart: partial.portStart ?? '0',
    portEnd: partial.portEnd ?? '65535',
    protocol: partial.protocol ?? 'ANY',
    action: partial.action ?? 'allow',
    enabled: partial.enabled ?? true,
  }
}

interface CollForm {
  allow1Text: string
  mappingsText: string
  target: { cidr: string; portStart: string; portEnd: string; protocol: string }
}

// 两条映射转换后网段部分重叠（192.168.0.64..127），第三条仅用于铺满目标 /24
const TWO_MAPS =
  '10.0.0.0/25 -> 192.168.0.0/25\n' +
  '10.0.0.128/26 -> 192.168.0.64/26\n' +
  '10.0.0.192/26 -> 192.168.9.0/26'
const SAME_DST_MAPS =
  '10.0.0.0/25 -> 192.168.0.0/25\n10.0.0.128/25 -> 192.168.0.0/25'

function form(partial: Partial<CollForm> = {}): CollForm {
  return {
    allow1Text: partial.allow1Text ?? 'allow',
    mappingsText: partial.mappingsText ?? TWO_MAPS,
    target:
      partial.target ??
      { cidr: '10.0.0.0/24', portStart: '0', portEnd: '65535', protocol: 'TCP' },
  }
}

function mappingOf(text: string): NormalizedSnatMapping[] {
  const { mappings, errors } = parseSnatMappings(text)
  assert.deepEqual(errors, [])
  return mappings
}

function targetOf(input: {
  cidr: string
  portStart: string
  portEnd: string
  protocol: string
}) {
  const { target, errors } = validateTandemTarget(input)
  assert.deepEqual(errors, [])
  return target!
}

/** 暴力首命中：在合法启用规则上判定一个具体报文的首命中规则 */
function bruteHit(
  rules: RuleInput[],
  ipNum: number,
  port: number,
  protocol: 'TCP' | 'UDP',
) {
  const { valid } = validateRules(rules)
  return valid
    .filter((r) => r.enabled)
    .find(
      (r) =>
        ipNum >= r.ipStart &&
        ipNum <= r.ipEnd &&
        port >= r.portStart &&
        port <= r.portEnd &&
        (r.protocol === 'ANY' || r.protocol === protocol),
    )
}

/** 报文是否落在一组精确区域（协议 → 端口段 × CIDR 行）内 */
function packetInRegions(
  regions: ReturnType<typeof analyzeSnatCollision>['regions'],
  ip: number,
  port: number,
  proto: 'TCP' | 'UDP',
): boolean {
  const group = regions.find((g) => g.protocol === proto)
  return Boolean(
    group?.rows.some(
      (row) =>
        port >= row.portStart &&
        port <= row.portEnd &&
        row.cidrs.some((c) => {
          const b = parseCidrStrict(c)
          return ip >= b.start && ip <= b.end
        }),
    ),
  )
}

// ---------------------------------------------------------------------------
// 基本碰撞语义
// ---------------------------------------------------------------------------

test('基本碰撞：逐对大小 / 精确转换后区域 / 去重总量 / 单元数', () => {
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' })]
  const out = evaluateSnatCollision(stage1, form())
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const r = out.result

  // 两条映射的转换后网段在 192.168.0.64..127（/26）重叠，放行区域全覆盖
  assert.equal(r.releasedSize, 256 * 65536)
  assert.equal(r.releasedCells, 3)
  assert.equal(r.pairs.length, 1)
  const p = r.pairs[0]
  assert.deepEqual([p.a, p.b], [0, 1])
  assert.equal(p.size, 64 * 65536)
  assert.equal(p.cells, 1)
  assert.equal(r.totalSize, 64 * 65536)
  assert.equal(r.totalCells, 1)
  assert.deepEqual(p.regions[0].rows, [
    { portStart: 0, portEnd: 65535, cidrs: ['192.168.0.64/26'], size: 64 * 65536 },
  ])
  assert.deepEqual(r.regions[0].rows, [
    { portStart: 0, portEnd: 65535, cidrs: ['192.168.0.64/26'], size: 64 * 65536 },
  ])
  // 区域以转换后地址空间展示，不出现原始地址
  assert.ok(!JSON.stringify(p.regions).includes('10.0.0'))
  assert.deepEqual(r.nonCollidingOverlaps, [])
})

test('见证：两条原始报文经各自映射转换后成为同一转换后报文（确定性选点）', () => {
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' })]
  const out = evaluateSnatCollision(stage1, form())
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const w = out.result.pairs[0].witness

  assert.deepEqual(w.packetA, {
    srcIp: '10.0.0.65',
    srcPort: 0,
    protocol: 'TCP',
    translatedSrcIp: '192.168.0.65',
  })
  assert.deepEqual(w.packetB, {
    srcIp: '10.0.0.129',
    srcPort: 0,
    protocol: 'TCP',
    translatedSrcIp: '192.168.0.65',
  })
  assert.deepEqual(w.translated, { srcIp: '192.168.0.65', srcPort: 0, protocol: 'TCP' })
  assert.notEqual(w.packetA.srcIp, w.packetB.srcIp)
})

test('见证暴力复现：两条原始报文都经前级首命中放行，且落在该对转换后碰撞区域内', () => {
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' })]
  const mappings = mappingOf(TWO_MAPS)
  const target = targetOf(form().target)
  const r = analyzeSnatCollision(stage1, ['allow'], mappings, target)
  const p = r.pairs[0]

  for (const [mi, pkt] of [
    [p.a, p.witness.packetA],
    [p.b, p.witness.packetB],
  ] as const) {
    const ip = ipv4ToInt(pkt.srcIp)
    const m = mappings[mi]
    // 原始地址确属该映射源网段
    assert.ok(ip >= m.srcStart && ip <= m.srcEnd)
    // 前级首命中放行
    const hit = bruteHit(stage1, ip, pkt.srcPort, pkt.protocol)
    assert.equal(hit?.action, 'allow')
    // 主机位平移后恰为共同转换后地址
    assert.equal(
      intToIpv4((m.dstStart + (ip - m.srcStart)) >>> 0),
      p.witness.translated.srcIp,
    )
  }
  // 共同转换后报文位于该对精确碰撞区域内
  assert.ok(
    packetInRegions(
      p.regions,
      ipv4ToInt(p.witness.translated.srcIp),
      p.witness.translated.srcPort,
      p.witness.translated.protocol,
    ),
  )
})

test('转换后网段完全相同但放行端口不交：不报碰撞，仅列为网段重叠', () => {
  const stage1 = [
    rule({ name: 'A', cidr: '10.0.0.0/25', portStart: '0', portEnd: '99', protocol: 'TCP', action: 'allow' }),
    rule({ name: 'B', cidr: '10.0.0.128/25', portStart: '100', portEnd: '199', protocol: 'TCP', action: 'allow' }),
  ]
  const out = evaluateSnatCollision(stage1, form({ mappingsText: SAME_DST_MAPS }))
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const r = out.result
  assert.equal(r.pairs.length, 0)
  assert.equal(r.totalSize, 0)
  assert.equal(r.totalCells, 0)
  assert.deepEqual(r.regions, [])
  // 参与计算的放行总量仍精确（128 IP × 100 端口 × 2 条映射）
  assert.equal(r.releasedSize, 128 * 100 * 2)
  assert.deepEqual(r.nonCollidingOverlaps, [{ a: 0, b: 1 }])
})

test('转换后网段相同但放行协议不交（TCP / UDP）：不报碰撞', () => {
  const stage1 = [
    rule({ name: 'A', cidr: '10.0.0.0/25', protocol: 'TCP', action: 'allow' }),
    rule({ name: 'B', cidr: '10.0.0.128/25', protocol: 'UDP', action: 'allow' }),
  ]
  const out = evaluateSnatCollision(
    stage1,
    form({
      mappingsText: SAME_DST_MAPS,
      target: { cidr: '10.0.0.0/24', portStart: '0', portEnd: '65535', protocol: 'ANY' },
    }),
  )
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const r = out.result
  assert.equal(r.pairs.length, 0)
  assert.equal(r.totalSize, 0)
  assert.equal(r.releasedSize, 128 * 65536 * 2) // 一映射 TCP、一映射 UDP
  assert.deepEqual(r.nonCollidingOverlaps, [{ a: 0, b: 1 }])
})

test('前级动作不放行 / 未命中的报文不参与：仅一侧放行时无碰撞', () => {
  const stage1 = [
    rule({ name: 'A', cidr: '10.0.0.0/25', protocol: 'ANY', action: 'allow' }),
    rule({ name: 'D', cidr: '10.0.0.128/25', protocol: 'ANY', action: 'deny' }),
  ]
  const out = evaluateSnatCollision(
    stage1,
    form({
      mappingsText: SAME_DST_MAPS,
      target: { cidr: '10.0.0.0/24', portStart: '0', portEnd: '65535', protocol: 'ANY' },
    }),
  )
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const r = out.result
  assert.equal(r.pairs.length, 0)
  assert.equal(r.totalSize, 0)
  assert.equal(r.releasedSize, 128 * 65536 * 2) // 只有映射 0 的 TCP+UDP 放行

  // 无任何合法规则：全部未命中，放行总量为 0
  const empty = analyzeSnatCollision(
    [],
    ['allow'],
    mappingOf(SAME_DST_MAPS),
    targetOf(form({ mappingsText: SAME_DST_MAPS }).target),
  )
  assert.equal(empty.releasedSize, 0)
  assert.equal(empty.pairs.length, 0)
})

test('多对映射碰撞同一转换后区域：逐对列出，总量按转换后报文去重', () => {
  // 源网段 4 个相邻 /26 铺满 /24；前三条映射到同一转换后网段，第四条不重叠
  const maps =
    '10.0.0.0/26 -> 192.168.0.0/26\n' +
    '10.0.0.64/26 -> 192.168.0.0/26\n' +
    '10.0.0.128/26 -> 192.168.0.0/26\n' +
    '10.0.0.192/26 -> 192.168.9.0/26'
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' })]
  const out = evaluateSnatCollision(stage1, form({ mappingsText: maps }))
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const r = out.result

  // 三对碰撞，每对各 64 IP × 65536 端口；同一批转换后报文，去重后只计一份
  assert.deepEqual(
    r.pairs.map((p) => [p.a, p.b]),
    [
      [0, 1],
      [0, 2],
      [1, 2],
    ],
  )
  for (const p of r.pairs) assert.equal(p.size, 64 * 65536)
  assert.equal(r.totalSize, 64 * 65536)
  assert.equal(r.totalCells, 1)
  assert.equal(r.releasedSize, 256 * 65536)
  assert.equal(r.releasedCells, 4)
  assert.deepEqual(r.nonCollidingOverlaps, [])

  // 各对见证的转换后报文相同，原始侧分别取自对应映射源网段
  const w01 = r.pairs[0].witness
  const w12 = r.pairs[2].witness
  assert.equal(w01.translated.srcIp, '192.168.0.1')
  assert.equal(w01.packetA.srcIp, '10.0.0.1')
  assert.equal(w01.packetB.srcIp, '10.0.0.65')
  assert.equal(w12.packetA.srcIp, '10.0.0.65')
  assert.equal(w12.packetB.srcIp, '10.0.0.129')
})

test('目标端口区间限制参与范围：碰撞区域端口随目标收窄', () => {
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' })]
  const out = evaluateSnatCollision(
    stage1,
    form({
      mappingsText: SAME_DST_MAPS,
      target: { cidr: '10.0.0.0/24', portStart: '80', portEnd: '443', protocol: 'TCP' },
    }),
  )
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const p = out.result.pairs[0]
  assert.equal(p.size, 128 * 364)
  assert.deepEqual(p.regions[0].rows, [
    { portStart: 80, portEnd: 443, cidrs: ['192.168.0.0/25'], size: 128 * 364 },
  ])
})

test('区域行合计与逐对 / 去重总量精确一致', () => {
  const maps =
    '10.0.0.0/26 -> 192.168.0.0/26\n' +
    '10.0.0.64/26 -> 192.168.0.0/26\n' +
    '10.0.0.128/26 -> 192.168.0.0/26\n' +
    '10.0.0.192/26 -> 192.168.9.0/26'
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' })]
  const target = targetOf({
    cidr: '10.0.0.0/24',
    portStart: '80',
    portEnd: '443',
    protocol: 'TCP',
  })
  const r = analyzeSnatCollision(stage1, ['allow'], mappingOf(maps), target)
  for (const p of r.pairs) {
    assert.equal(p.regions.reduce((s, g) => s + g.size, 0), p.size)
  }
  assert.equal(r.regions.reduce((s, g) => s + g.size, 0), r.totalSize)
})

test('非法与停用前级规则按既有语义排除并计数', () => {
  const stage1 = [
    rule({ id: 'ok', name: 'OK', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' }),
    rule({ id: 'off', name: 'OFF', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'deny', enabled: false }),
    rule({ id: 'bad', name: 'BAD', cidr: '10.0.0.5/24', protocol: 'TCP', action: 'deny' }),
  ]
  const out = evaluateSnatCollision(stage1, form({ mappingsText: SAME_DST_MAPS }))
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const r = out.result
  assert.deepEqual(r.stage1, { total: 3, active: 1, invalid: 1, disabled: 1 })
  // 仅合法启用的 allow 规则放行：TCP 全量，两映射转换后网段相同 → 全量碰撞
  assert.equal(r.pairs[0].size, 128 * 65536)
})

test('单条映射：不存在映射对，不可能碰撞', () => {
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' })]
  const out = evaluateSnatCollision(
    stage1,
    form({ mappingsText: '10.0.0.0/24 -> 192.168.0.0/24' }),
  )
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  assert.equal(out.result.pairs.length, 0)
  assert.equal(out.result.totalSize, 0)
  assert.equal(out.result.releasedSize, 256 * 65536)
})

test('输入错误阻止分析：放行列表空 / 映射空 / 目标未覆盖 / 目标非法', () => {
  const stage1 = [rule({ cidr: '10.0.0.0/24' })]

  let out = evaluateSnatCollision(stage1, form({ allow1Text: ' ' }))
  assert.equal(out.ok, false)
  assert.ok(!out.ok && out.errors.some((e) => e.includes('前级放行动作列表不能为空')))

  out = evaluateSnatCollision(stage1, form({ mappingsText: '  \n ' }))
  assert.ok(!out.ok && out.errors.some((e) => e.includes('源地址映射不能为空')))

  out = evaluateSnatCollision(
    stage1,
    form({
      mappingsText: '10.0.0.0/25 -> 192.168.0.0/25',
      target: { cidr: '10.0.0.0/24', portStart: '0', portEnd: '65535', protocol: 'TCP' },
    }),
  )
  assert.ok(!out.ok && out.errors.some((e) => e.includes('未完全落在映射源网段内')))

  out = evaluateSnatCollision(
    stage1,
    form({ target: { cidr: '10.0.0.5/24', portStart: '0', portEnd: '65535', protocol: 'TCP' } }),
  )
  assert.ok(!out.ok && out.errors.some((e) => e.includes('主机位非零')))
})

test('独立于后级规则：表单携带任意后级字段（含非法 JSON）不影响碰撞分析', () => {
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' })]
  // 面板直接把完整 SnatFormInput（含 stage2Json / allow2Text）传入；此处只多不少
  const mixed = { ...form(), stage2Json: 'not a json', allow2Text: 'whatever' }
  const out = evaluateSnatCollision(stage1, mixed)
  assert.equal(out.ok, true)
  if (out.ok) assert.equal(out.result.pairs.length, 1)
})

test('同一输入重复分析结果完全确定（含逐对区域与见证）', () => {
  const stage1 = [
    rule({ name: 'A', cidr: '10.0.0.0/25', portStart: '80', portEnd: '443', action: 'allow' }),
    rule({ name: 'B', cidr: '10.0.0.128/25', portStart: '80', portEnd: '443', action: 'allow' }),
    rule({ name: 'D', cidr: '10.0.0.0/24', action: 'deny' }),
  ]
  const target = targetOf({
    cidr: '10.0.0.0/24',
    portStart: '0',
    portEnd: '65535',
    protocol: 'ANY',
  })
  const mappings = mappingOf(TWO_MAPS)
  const fixed = new Date('2026-05-01T00:00:00Z')
  const r1 = analyzeSnatCollision(stage1, ['allow'], mappings, target, fixed)
  const r2 = analyzeSnatCollision(stage1, ['allow'], mappings, target, fixed)
  assert.equal(r1.pairs.length, 1)
  assert.deepStrictEqual(JSON.parse(JSON.stringify(r1)), JSON.parse(JSON.stringify(r2)))
})

console.log(`\n转换后源身份碰撞分析 ${passed} 项测试通过 ✔`)
