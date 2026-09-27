/**
 * 转换后源身份碰撞分析引擎自检：
 * 仅目标内经前级首命中放行的报文参与（未命中 / 非法 / 停用沿用现有语义）、
 * 按等长映射投影到转换后空间逐对求交、转换后网段重叠但放行区域不交时不报碰撞、
 * 每对碰撞的大小 / 精确转换后区域 / 可复制见证、多对重叠总量按转换后报文去重、
 * 输入错误阻止分析、后级规则不参与本分析、暴力对照、确定性。
 */
import assert from 'node:assert'
import {
  analyzeSnatCollision,
  evaluateSnatCollision,
} from './audit/snatCollision'
import type { SnatCollisionResult } from './audit/snatCollision'
import { parseSnatMappings } from './audit/snat'
import type { NormalizedSnatMapping, SnatFormInput } from './audit/snat'
import { validateTandemTarget } from './audit/tandem'
import { validateRules } from './audit/engine'
import { intToIpv4, ipv4ToInt } from './audit/iputil'
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

const TARGET = {
  cidr: '10.0.0.0/24',
  portStart: '0',
  portEnd: '65535',
  protocol: 'TCP',
}

function form(partial: Partial<SnatFormInput> = {}): SnatFormInput {
  return {
    stage2Json: partial.stage2Json ?? '[]',
    allow1Text: partial.allow1Text ?? 'allow',
    allow2Text: partial.allow2Text ?? 'allow',
    mappingsText:
      partial.mappingsText ??
      '10.0.0.0/25 -> 192.168.0.0/25\n10.0.0.128/25 -> 192.168.0.0/25',
    target: partial.target ?? TARGET,
  }
}

function mappingOf(text: string): NormalizedSnatMapping[] {
  const { mappings, errors } = parseSnatMappings(text)
  assert.deepEqual(errors, [])
  return mappings
}

function targetOf(input: { cidr: string; portStart: string; portEnd: string; protocol: string }) {
  const { target, errors } = validateTandemTarget(input)
  assert.deepEqual(errors, [])
  return target!
}

function analyze(
  stage1: RuleInput[],
  mappingsText: string,
  targetInput = TARGET,
  allow1: string[] = ['allow'],
): SnatCollisionResult {
  return analyzeSnatCollision(
    stage1,
    allow1,
    mappingOf(mappingsText),
    targetOf(targetInput),
    new Date('2026-09-27T00:00:00Z'),
  )
}

/** 暴力首命中：在给定规则数组上判定一个具体报文的首命中规则 */
function bruteHit(rules: RuleInput[], ipNum: number, port: number, protocol: 'TCP' | 'UDP') {
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

// ---------------------------------------------------------------------------
// 输入校验（仅校验自身依赖的输入，独立于后级规则）
// ---------------------------------------------------------------------------

test('输入错误阻止分析：目标 / 前级放行列表 / 映射 / 目标未落在映射源网段', () => {
  let out = evaluateSnatCollision([rule({})], form({ target: { ...TARGET, cidr: '10.0.0.5/24' } }))
  assert.ok(!out.ok && out.errors.some((e) => e.includes('主机位非零')))

  out = evaluateSnatCollision([rule({})], form({ allow1Text: ' ' }))
  assert.ok(!out.ok && out.errors.some((e) => e.includes('前级放行动作列表不能为空')))

  out = evaluateSnatCollision([rule({})], form({ mappingsText: ' ' }))
  assert.ok(!out.ok && out.errors.some((e) => e.includes('源地址映射不能为空')))

  out = evaluateSnatCollision(
    [rule({})],
    form({ mappingsText: '10.0.0.0/24 -> 192.168.0.0/24\n10.0.0.0/24 -> 192.168.1.0/24' }),
  )
  assert.ok(!out.ok && out.errors.some((e) => e.includes('重叠')))

  out = evaluateSnatCollision(
    [rule({})],
    form({ mappingsText: '10.0.0.0/25 -> 192.168.0.0/25' }),
  )
  assert.ok(!out.ok && out.errors.some((e) => e.includes('未完全落在映射源网段内')))
})

test('独立于后级规则：后级 JSON 缺失或非法不影响碰撞分析', () => {
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' })]
  for (const stage2Json of ['', 'not json', '[{"cidr":"10/8"}]']) {
    const out = evaluateSnatCollision(stage1, form({ stage2Json }))
    assert.equal(out.ok, true)
    if (out.ok) assert.equal(out.result.pairs.length, 1)
  }
})

// ---------------------------------------------------------------------------
// 碰撞语义
// ---------------------------------------------------------------------------

test('转换后网段完全重叠且两段均放行：整个转换后网段碰撞，见证可复现', () => {
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' })]
  const r = analyze(stage1, '10.0.0.0/25 -> 192.168.0.0/25\n10.0.0.128/25 -> 192.168.0.0/25')
  assert.equal(r.allowedSize, 256 * 65536)
  assert.equal(r.pairs.length, 1)
  const p = r.pairs[0]
  assert.equal(p.first, 0)
  assert.equal(p.second, 1)
  assert.equal(p.size, 128 * 65536)
  assert.equal(r.totalSize, 128 * 65536)
  // 精确转换后区域
  assert.deepEqual(p.regions, [
    {
      protocol: 'TCP',
      rows: [{ portStart: 0, portEnd: 65535, cidrs: ['192.168.0.0/25'], size: 128 * 65536 }],
      size: 128 * 65536,
    },
  ])
  assert.deepEqual(r.totalRegions, p.regions)
  // 见证：两条原始报文分别落在两条映射源网段内，转换后相同
  const w = p.witness
  assert.equal(w.firstOriginal.srcIp, '10.0.0.1')
  assert.equal(w.secondOriginal.srcIp, '10.0.0.129')
  assert.deepEqual(w.translated, { srcIp: '192.168.0.1', srcPort: 0, protocol: 'TCP' })
  assert.notEqual(w.firstOriginal.srcIp, w.secondOriginal.srcIp)
})

test('转换后网段重叠但放行区域不交：不报碰撞', () => {
  // 前级只放行前半（映射 #1 的源网段），后半 deny
  const stage1 = [
    rule({ name: 'A', cidr: '10.0.0.0/25', protocol: 'TCP', action: 'allow' }),
    rule({ name: 'D', cidr: '10.0.0.128/25', protocol: 'TCP', action: 'deny' }),
  ]
  const r = analyze(stage1, '10.0.0.0/25 -> 192.168.0.0/25\n10.0.0.128/25 -> 192.168.0.0/25')
  assert.equal(r.allowedSize, 128 * 65536)
  assert.equal(r.pairs.length, 0)
  assert.equal(r.totalSize, 0)
  assert.equal(r.totalCells, 0)
  assert.deepEqual(r.totalRegions, [])
})

test('前级未命中的报文不参与：映射 #2 源网段无任何规则覆盖 → 无碰撞', () => {
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/25', protocol: 'TCP', action: 'allow' })]
  const r = analyze(stage1, '10.0.0.0/25 -> 192.168.0.0/25\n10.0.0.128/25 -> 192.168.0.0/25')
  assert.equal(r.allowedSize, 128 * 65536)
  assert.equal(r.pairs.length, 0)
  assert.equal(r.totalSize, 0)
})

test('转换后网段不重叠：无碰撞', () => {
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' })]
  const r = analyze(stage1, '10.0.0.0/25 -> 192.168.0.0/25\n10.0.0.128/25 -> 192.168.1.0/25')
  assert.equal(r.allowedSize, 256 * 65536)
  assert.equal(r.pairs.length, 0)
  assert.equal(r.totalSize, 0)
})

test('转换后网段部分重叠（不同前缀映射）：碰撞区域精确等于交集', () => {
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' })]
  const r = analyze(
    stage1,
    '10.0.0.0/25 -> 192.168.0.0/25\n' +
      '10.0.0.128/26 -> 192.168.0.64/26\n' +
      '10.0.0.192/26 -> 192.168.1.0/26',
  )
  // 仅映射 #1（/25）与映射 #2（/26，落在前者转换后网段内）碰撞
  assert.equal(r.pairs.length, 1)
  const p = r.pairs[0]
  assert.equal(p.first, 0)
  assert.equal(p.second, 1)
  assert.equal(p.size, 64 * 65536)
  assert.equal(r.totalSize, 64 * 65536)
  assert.deepEqual(p.regions[0].rows, [
    { portStart: 0, portEnd: 65535, cidrs: ['192.168.0.64/26'], size: 64 * 65536 },
  ])
  // 见证的转换后地址落在交集内
  const tip = ipv4ToInt(p.witness.translated.srcIp)
  assert.ok(tip >= ipv4ToInt('192.168.0.64') && tip <= ipv4ToInt('192.168.0.127'))
})

test('端口维：仅放行端口区间参与碰撞', () => {
  const stage1 = [
    rule({ name: 'A', cidr: '10.0.0.0/24', portStart: '80', portEnd: '443', protocol: 'TCP', action: 'allow' }),
  ]
  const r = analyze(stage1, '10.0.0.0/25 -> 192.168.0.0/25\n10.0.0.128/25 -> 192.168.0.0/25')
  assert.equal(r.allowedSize, 256 * 364)
  assert.equal(r.pairs.length, 1)
  assert.equal(r.pairs[0].size, 128 * 364)
  assert.deepEqual(r.pairs[0].regions[0].rows, [
    { portStart: 80, portEnd: 443, cidrs: ['192.168.0.0/25'], size: 128 * 364 },
  ])
  assert.equal(r.pairs[0].witness.translated.srcPort, 80)
})

test('协议维：ANY 目标下 UDP 未命中前级，碰撞只含 TCP', () => {
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' })]
  const r = analyze(
    stage1,
    '10.0.0.0/25 -> 192.168.0.0/25\n10.0.0.128/25 -> 192.168.0.0/25',
    { ...TARGET, protocol: 'ANY' },
  )
  assert.equal(r.allowedSize, 256 * 65536) // 仅 TCP
  assert.equal(r.pairs.length, 1)
  assert.equal(r.pairs[0].size, 128 * 65536)
  assert.deepEqual(r.pairs[0].regions.map((g) => g.protocol), ['TCP'])
})

test('非法与停用规则按现有语义排除并计数', () => {
  const stage1 = [
    rule({ id: 'ok', name: 'OK', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' }),
    rule({ id: 'off', name: 'OFF', cidr: '10.0.0.128/25', protocol: 'TCP', action: 'deny', enabled: false }),
    rule({ id: 'bad', name: 'BAD', cidr: '10.0.0.5/24', protocol: 'TCP', action: 'deny' }),
  ]
  const r = analyze(stage1, '10.0.0.0/25 -> 192.168.0.0/25\n10.0.0.128/25 -> 192.168.0.0/25')
  assert.deepEqual(r.stage1, { total: 3, active: 1, invalid: 1, disabled: 1 })
  // 停用与非法规则不参与：全目标由 OK 放行 → 全碰撞
  assert.equal(r.pairs.length, 1)
  assert.equal(r.totalSize, 128 * 65536)
})

test('三条映射重叠同一转换后网段：3 对碰撞，总量按转换后报文去重', () => {
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' })]
  const r = analyze(
    stage1,
    '10.0.0.0/25 -> 192.168.0.0/25\n' +
      '10.0.0.128/26 -> 192.168.0.0/26\n' +
      '10.0.0.192/26 -> 192.168.0.0/26',
  )
  assert.equal(r.pairs.length, 3)
  assert.deepEqual(
    r.pairs.map((p) => [p.first, p.second]),
    [
      [0, 1],
      [0, 2],
      [1, 2],
    ],
  )
  for (const p of r.pairs) assert.equal(p.size, 64 * 65536)
  // 总量去重：同一转换后报文被 3 对共享，只计一次
  assert.equal(r.totalSize, 64 * 65536)
  assert.equal(r.totalRegions[0].rows[0].cidrs.join(','), '192.168.0.0/26')
})

test('单条映射：不可能碰撞', () => {
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' })]
  const r = analyze(stage1, '10.0.0.0/24 -> 192.168.0.0/24')
  assert.equal(r.allowedSize, 256 * 65536)
  assert.equal(r.pairs.length, 0)
  assert.equal(r.totalSize, 0)
})

// ---------------------------------------------------------------------------
// 暴力对照与见证复现
// ---------------------------------------------------------------------------

test('暴力对照：小空间逐报文重放，总量 / 逐对大小 / 放行空间完全一致', () => {
  const stage1 = [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/25', portStart: '0', portEnd: '3', protocol: 'TCP', action: 'allow' }),
    rule({ id: 'b', name: 'B', cidr: '10.0.0.64/26', portStart: '2', portEnd: '5', protocol: 'TCP', action: 'allow' }),
    rule({ id: 'c', name: 'C', cidr: '10.0.0.128/25', portStart: '1', portEnd: '4', protocol: 'TCP', action: 'allow' }),
    rule({ id: 'd', name: 'D', cidr: '10.0.0.192/26', portStart: '0', portEnd: '5', protocol: 'TCP', action: 'deny' }),
  ]
  const mappingsText =
    '10.0.0.0/25 -> 192.168.0.0/25\n' +
    '10.0.0.128/26 -> 192.168.0.0/26\n' +
    '10.0.0.192/26 -> 192.168.0.64/26'
  const mappings = mappingOf(mappingsText)
  const targetInput = { cidr: '10.0.0.0/24', portStart: '0', portEnd: '5', protocol: 'TCP' }
  const r = analyze(stage1, mappingsText, targetInput)

  // 暴力：逐报文首命中放行 → 按映射平移 → 统计转换后报文的来源映射集合
  const translatedSources = new Map<string, Set<number>>() // 转换后报文 -> 来源映射集合
  let allowed = 0
  for (let ip = ipv4ToInt('10.0.0.0'); ip <= ipv4ToInt('10.0.0.255'); ip++) {
    const m = mappings.findIndex((x) => ip >= x.srcStart && ip <= x.srcEnd)
    assert.ok(m >= 0)
    for (let port = 0; port <= 5; port++) {
      const hit = bruteHit(stage1, ip, port, 'TCP')
      if (!hit || hit.action !== 'allow') continue
      allowed++
      const tip = (mappings[m].dstStart + (ip - mappings[m].srcStart)) >>> 0
      const key = `${tip}.${port}`
      let set = translatedSources.get(key)
      if (!set) {
        set = new Set()
        translatedSources.set(key, set)
      }
      set.add(m)
    }
  }
  assert.equal(r.allowedSize, allowed)

  let bruteTotal = 0
  const brutePair = new Map<string, number>()
  for (const sources of translatedSources.values()) {
    if (sources.size < 2) continue
    bruteTotal++
    const list = [...sources].sort((a, b) => a - b)
    for (let a = 0; a < list.length; a++) {
      for (let b = a + 1; b < list.length; b++) {
        const pk = `${list[a]}|${list[b]}`
        brutePair.set(pk, (brutePair.get(pk) ?? 0) + 1)
      }
    }
  }
  assert.equal(r.totalSize, bruteTotal)
  assert.equal(r.pairs.length, brutePair.size)
  for (const p of r.pairs) {
    assert.equal(p.size, brutePair.get(`${p.first}|${p.second}`)!)
  }
  // 区域行合计与逐单元统计一致
  assert.equal(r.totalRegions.reduce((s, g) => s + g.size, 0), r.totalSize)
  for (const p of r.pairs) {
    assert.equal(p.regions.reduce((s, g) => s + g.size, 0), p.size)
  }
})

test('每对见证暴力复现：两条原始报文均放行且映射到同一转换后报文', () => {
  const stage1 = [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/24', portStart: '80', portEnd: '443', action: 'allow' }),
    rule({ id: 'd', name: 'D', cidr: '10.0.0.96/27', portStart: '80', portEnd: '443', action: 'deny' }),
  ]
  const mappingsText =
    '10.0.0.0/25 -> 192.168.1.0/25\n' +
    '10.0.0.128/26 -> 192.168.1.0/26\n' +
    '10.0.0.192/26 -> 192.168.1.64/26'
  const mappings = mappingOf(mappingsText)
  const targetInput = { cidr: '10.0.0.0/24', portStart: '0', portEnd: '65535', protocol: 'ANY' }
  const r = analyze(stage1, mappingsText, targetInput)
  assert.ok(r.pairs.length > 0)

  for (const p of r.pairs) {
    const w = p.witness
    const originals = [
      { packet: w.firstOriginal, mi: p.first },
      { packet: w.secondOriginal, mi: p.second },
    ]
    for (const { packet, mi } of originals) {
      const ipNum = ipv4ToInt(packet.srcIp)
      const m = mappings[mi]
      // 原始报文落在该映射源网段与目标内
      assert.ok(ipNum >= m.srcStart && ipNum <= m.srcEnd)
      assert.ok(ipNum >= ipv4ToInt('10.0.0.0') && ipNum <= ipv4ToInt('10.0.0.255'))
      // 前级首命中且动作放行
      const hit = bruteHit(stage1, ipNum, packet.srcPort, packet.protocol)
      assert.ok(hit && hit.action === 'allow')
      // 按该映射转换后 == 共同转换后报文（端口与协议不改写）
      const tip = (m.dstStart + (ipNum - m.srcStart)) >>> 0
      assert.equal(intToIpv4(tip), w.translated.srcIp)
      assert.equal(packet.srcPort, w.translated.srcPort)
      assert.equal(packet.protocol, w.translated.protocol)
    }
    // 两条原始报文不同（源网段两两不重叠，源地址必不同）
    assert.notEqual(w.firstOriginal.srcIp, w.secondOriginal.srcIp)
    // 转换后地址同时落在两条映射的转换后网段内
    const tip = ipv4ToInt(w.translated.srcIp)
    for (const mi of [p.first, p.second]) {
      assert.ok(tip >= mappings[mi].dstStart && tip <= mappings[mi].dstEnd)
    }
  }
})

test('同一输入重复分析结果完全确定（含逐对明细、区域与见证）', () => {
  const stage1 = [
    rule({ name: 'A', cidr: '10.0.0.0/24', action: 'allow' }),
    rule({ name: 'D', cidr: '10.0.0.0/26', action: 'deny' }),
  ]
  const mappingsText =
    '10.0.0.0/25 -> 192.168.0.0/25\n10.0.0.128/25 -> 192.168.0.0/25'
  const targetInput = { cidr: '10.0.0.0/24', portStart: '0', portEnd: '65535', protocol: 'ANY' }
  const fixed = new Date('2026-09-27T00:00:00Z')
  const r1 = analyzeSnatCollision(
    stage1,
    ['allow'],
    mappingOf(mappingsText),
    targetOf(targetInput),
    fixed,
  )
  const r2 = analyzeSnatCollision(
    stage1,
    ['allow'],
    mappingOf(mappingsText),
    targetOf(targetInput),
    fixed,
  )
  assert.deepStrictEqual(JSON.parse(JSON.stringify(r1)), JSON.parse(JSON.stringify(r2)))
})

console.log(`\n转换后源身份碰撞分析 ${passed} 项测试通过 ✔`)
