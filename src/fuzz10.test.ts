/**
 * 转换后源身份碰撞分析模糊对照：在缩小且完全可枚举的报文空间
 * （10.1.2.0/24 × 端口 0..31 × {TCP, UDP}）上随机生成前级规则集、
 * 放行动作列表与一组源网段互不重叠、转换后网段刻意高频重叠的等长映射，
 * 逐报文暴力执行「前级首命中放行 → 按所在映射主机位平移投影 →
 * 同一转换后 IPv4×端口×协议被 ≥2 条映射的放行报文占用即碰撞」，
 * 与 analyzeSnatCollision 的放行总量、逐对碰撞大小、去重总量、
 * 精确区域逐报文覆盖、网段重叠但不碰撞清单与见证报文逐一对账。
 * 规则 CIDR 全部在 /24 内对齐、端口均在 0..31 内，因此每个枚举报文代表
 * 1 条真实报文空间，引擎大小与枚举计数精确相等。
 */
import assert from 'node:assert'
import { analyzeSnatCollision } from './audit/snatcollision'
import type { NormalizedSnatMapping } from './audit/snat'
import { validateTandemTarget } from './audit/tandem'
import { validateRules } from './audit/engine'
import { intToIpv4, parseCidrStrict } from './audit/iputil'
import type { RuleInput } from './audit/types'

function rand(n: number) {
  return Math.floor(Math.random() * n)
}

const BASE = parseCidrStrict('10.1.2.0/24').start
const DST_BASE = parseCidrStrict('172.16.5.0/24').start
const MAX_PORT = 31
const PROTOS = ['TCP', 'UDP', 'ANY'] as const
const ACTIONS = ['allow', 'deny', 'drop'] as const

/**
 * 随机等长映射：源网段为 10.1.2.0/24 内一组相邻对齐块（互不重叠、
 * 联合成一块连续区域，便于目标跨多条映射）；转换后网段等长——
 * 多数轮次全部落在同一 c 对齐槽位（刻意制造高碰撞率），
 * 其余在 172.16.5.0/24 前 2c 窗口内随机（c = 块大小），覆盖网段重叠
 * 但放行区域不交与网段不重叠的情形。
 */
function makeMappings(): NormalizedSnatMapping[] {
  const options: Array<{ c: number; n: number }> = []
  for (const c of [16, 32, 64]) {
    for (let n = 1; n <= Math.min(4, 256 / c); n++) options.push({ c, n })
  }
  const { c, n } = options[rand(options.length)]
  const S = c * n
  const start = (BASE + rand(256 / S) * S) >>> 0
  const sameSlot = rand(5) < 3 // 60%：全部映射共用同一转换后网段
  const mappings: NormalizedSnatMapping[] = []
  for (let i = 0; i < n; i++) {
    const srcStart = (start + i * c) >>> 0
    const srcEnd = (srcStart + c - 1) >>> 0
    const dStart = (DST_BASE + (sameSlot ? 0 : rand(2)) * c) >>> 0
    const dEnd = (dStart + c - 1) >>> 0
    mappings.push({
      srcStart,
      srcEnd,
      dstStart: dStart,
      dstEnd: dEnd,
      prefix: 32 - Math.log2(c),
      sourceText: `${intToIpv4(srcStart)}/${32 - Math.log2(c)}`,
      translatedText: `${intToIpv4(dStart)}/${32 - Math.log2(c)}`,
    })
  }
  return mappings
}

/** /24 内对齐的随机 CIDR，前缀 24..28；偶发非法（主机位非零） */
function randomCidr() {
  if (rand(10) === 0) return '10.1.2.3/24'
  const prefix = 24 + rand(5)
  const size = 2 ** (32 - prefix)
  const start = (BASE + rand(256 / size) * size) >>> 0
  return `${intToIpv4(start)}/${prefix}`
}

function makeRules(): RuleInput[] {
  const n = 1 + rand(6)
  return Array.from({ length: n }, (_, i) => {
    const a = rand(MAX_PORT + 1)
    const b = a + rand(MAX_PORT + 1 - a)
    // 偏向宽覆盖（/0 与 /24），保证目标内经常有前级放行的报文参与碰撞计算
    const pick = rand(10)
    const cidr =
      pick < 3 ? '0.0.0.0/0' : pick < 6 ? '10.1.2.0/24' : randomCidr()
    return {
      id: `A${i}`,
      name: `A${i}`,
      cidr,
      portStart: String(a),
      portEnd: String(b),
      protocol: PROTOS[rand(3)],
      action: ACTIONS[rand(3)],
      enabled: rand(8) !== 0, // 偶发停用
    }
  })
}

/** 随机非空放行动作列表（动作池的非空子集，可能含规则中不存在的动作） */
function makeAllowList(): string[] {
  const pool = [...ACTIONS, 'permit']
  const out: string[] = []
  for (const a of pool) if (rand(2) === 0) out.push(a)
  return out.length > 0 ? out : ['allow']
}

/** 目标：映射源网段并集内的随机对齐子网段（保证完全落在映射内且 CIDR 规范；
 *  允许跨多条映射源网段，否则永远只有一条映射有放行报文、不可能碰撞） */
function makeTarget(mappings: NormalizedSnatMapping[]) {
  const uStart = Math.min(...mappings.map((m) => m.srcStart))
  const uEnd = Math.max(...mappings.map((m) => m.srcEnd))
  // 起点不必与并集起点对齐：取并集内任意 s 对齐块即保证 CIDR 规范
  const candidates: number[] = []
  for (const s of [16, 32, 64, 128, 256]) {
    const lo = Math.ceil(uStart / s) * s
    const hi = Math.floor((uEnd + 1 - s) / s) * s
    if (hi >= lo) candidates.push(s)
  }
  // 偏向较大的目标块（更可能跨多条映射源网段），否则均匀随机
  const s =
    rand(2) === 0
      ? candidates[candidates.length - 1]
      : candidates[rand(candidates.length)]
  const lo = Math.ceil(uStart / s) * s
  const count = Math.floor((uEnd + 1 - s) / s) - Math.ceil(uStart / s) + 1
  const start = (lo + rand(count) * s) >>> 0
  const a = rand(MAX_PORT + 1)
  const b = a + rand(MAX_PORT + 1 - a)
  return {
    cidr: `${intToIpv4(start)}/${32 - Math.log2(s)}`,
    portStart: String(a),
    portEnd: String(b),
    protocol: PROTOS[rand(3)],
  }
}

function firstHit(
  valid: ReturnType<typeof validateRules>['valid'],
  ip: number,
  port: number,
  proto: 'TCP' | 'UDP',
) {
  const active = valid.filter((r) => r.enabled)
  return active.find(
    (rule) =>
      ip >= rule.ipStart &&
      ip <= rule.ipEnd &&
      port >= rule.portStart &&
      port <= rule.portEnd &&
      (rule.protocol === 'ANY' || rule.protocol === proto),
  )
}

let rounds = 0
let collisionRounds = 0
for (let round = 0; round < 400; round++) {
  const mappings = makeMappings()
  const rules1 = makeRules()
  const allow1 = makeAllowList()
  const targetInput = makeTarget(mappings)
  const { valid: valid1 } = validateRules(rules1)
  const { target, errors } = validateTandemTarget(targetInput)
  assert.equal(errors.length, 0)
  const result = analyzeSnatCollision(rules1, allow1, mappings, target!)

  // 暴力逐报文：放行判定 → 投影 → 转换后单元覆盖集合
  const mappingOf = (ip: number) =>
    mappings.findIndex((m) => ip >= m.srcStart && ip <= m.srcEnd)
  const cover = new Map<string, Set<number>>()
  let released = 0
  const protos: Array<'TCP' | 'UDP'> =
    target!.protocol === 'ANY' ? ['TCP', 'UDP'] : [target!.protocol as 'TCP' | 'UDP']
  for (let ip = target!.ipStart; ip <= target!.ipEnd; ip++) {
    const mi = mappingOf(ip)
    assert.ok(mi >= 0, `round ${round}: 目标地址应落在映射源网段内`)
    for (let port = target!.portStart; port <= target!.portEnd; port++) {
      for (const proto of protos) {
        const hit = firstHit(valid1, ip, port, proto)
        if (!hit || !allow1.includes(hit.action)) continue
        released++
        const m = mappings[mi]
        const tip = (m.dstStart + (ip - m.srcStart)) >>> 0
        const tKey = `${tip}.${port}.${proto}`
        let set = cover.get(tKey)
        if (!set) {
          set = new Set()
          cover.set(tKey, set)
        }
        set.add(mi)
      }
    }
  }

  // 暴力逐对碰撞与去重总量
  const pairCount = new Map<string, number>()
  let union = 0
  for (const set of cover.values()) {
    if (set.size < 2) continue
    union++
    const list = [...set].sort((x, y) => x - y)
    for (let i = 0; i < list.length; i++) {
      for (let j = i + 1; j < list.length; j++) {
        const pk = `${list[i]}.${list[j]}`
        pairCount.set(pk, (pairCount.get(pk) ?? 0) + 1)
      }
    }
  }

  const dump = `rules=${JSON.stringify(rules1)} allow1=${allow1} mappings=${JSON.stringify(mappings)} target=${JSON.stringify(targetInput)}`

  // 放行总量 / 去重总量对账（每个枚举报文恰为 1 条报文空间）
  assert.equal(result.releasedSize, released, `round ${round} releasedSize; ${dump}`)
  assert.equal(result.totalSize, union, `round ${round} totalSize; ${dump}`)
  assert.equal(
    result.regions.reduce((s, g) => s + g.size, 0),
    union,
    `round ${round} 去重区域行合计; ${dump}`,
  )

  // 逐对碰撞对账：引擎对集合与暴力对集合完全一致
  assert.equal(
    result.pairs.length,
    pairCount.size,
    `round ${round} 碰撞对数 engine=${result.pairs.length} brute=${pairCount.size}; ${dump}`,
  )
  for (const p of result.pairs) {
    const key = `${p.a}.${p.b}`
    const expected = pairCount.get(key)
    assert.ok(expected !== undefined, `round ${round} 引擎多出碰撞对 ${key}; ${dump}`)
    assert.equal(p.size, expected, `round ${round} 碰撞对 ${key} 大小; ${dump}`)
    assert.equal(
      p.regions.reduce((s, g) => s + g.size, 0),
      expected,
      `round ${round} 碰撞对 ${key} 区域行合计; ${dump}`,
    )
    pairCount.delete(key)
  }
  assert.equal(pairCount.size, 0, `round ${round} 暴力多出碰撞对; ${dump}`)

  // 网段重叠但不碰撞清单对账：与暴力结果逐一比对
  const netOverlap = (a: number, b: number) =>
    Math.max(mappings[a].dstStart, mappings[b].dstStart) <=
    Math.min(mappings[a].dstEnd, mappings[b].dstEnd)
  const expectedNonColliding: Array<{ a: number; b: number }> = []
  for (let a = 0; a < mappings.length; a++) {
    for (let b = a + 1; b < mappings.length; b++) {
      if (netOverlap(a, b) && !result.pairs.some((p) => p.a === a && p.b === b)) {
        expectedNonColliding.push({ a, b })
      }
    }
  }
  assert.deepEqual(
    result.nonCollidingOverlaps,
    expectedNonColliding,
    `round ${round} 网段重叠不碰撞清单; ${dump}`,
  )

  // 精确区域逐报文覆盖：每个暴力碰撞转换后报文都落在去重区域内，
  // 且每个被 ≥2 条映射覆盖的转换后报文落在对应碰撞对的区域内
  const inRegions = (
    regions: typeof result.regions,
    ip: number,
    port: number,
    proto: 'TCP' | 'UDP',
  ) => {
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
  for (const [tKey, set] of cover) {
    if (set.size < 2) continue
    const [tip, port, proto] = tKey.split('.')
    const ip = Number(tip)
    const portNum = Number(port)
    const pr = proto as 'TCP' | 'UDP'
    assert.ok(
      inRegions(result.regions, ip, portNum, pr),
      `round ${round} 转换后碰撞报文 ${tKey} 不在去重区域内; ${dump}`,
    )
    for (const p of result.pairs) {
      if (set.has(p.a) && set.has(p.b)) {
        assert.ok(
          inRegions(p.regions, ip, portNum, pr),
          `round ${round} 转换后碰撞报文 ${tKey} 不在碰撞对 ${p.a}.${p.b} 区域内; ${dump}`,
        )
      }
    }
  }

  // 见证报文暴力复现：两条原始报文都经前级首命中放行、
  // 分属各自映射源网段、互不相同，且转换后完全相同并落在该对碰撞区域内
  for (const p of result.pairs) {
    const w = p.witness
    assert.notEqual(w.packetA.srcIp, w.packetB.srcIp, `round ${round} 见证两侧应不同; ${dump}`)
    for (const [mi, pkt] of [
      [p.a, w.packetA],
      [p.b, w.packetB],
    ] as const) {
      const ip = parseCidrStrict(`${pkt.srcIp}/32`).start
      const m = mappings[mi]
      assert.ok(
        ip >= m.srcStart && ip <= m.srcEnd,
        `round ${round} 见证原始地址应属映射 ${mi} 源网段; ${dump}`,
      )
      const hit = firstHit(valid1, ip, pkt.srcPort, pkt.protocol)
      assert.ok(
        hit && allow1.includes(hit.action),
        `round ${round} 见证原始报文应经前级放行; ${dump}`,
      )
      assert.equal(
        intToIpv4((m.dstStart + (ip - m.srcStart)) >>> 0),
        w.translated.srcIp,
        `round ${round} 见证转换后地址不符; ${dump}`,
      )
      assert.equal(pkt.srcPort, w.translated.srcPort)
      assert.equal(pkt.protocol, w.translated.protocol)
      assert.equal(pkt.translatedSrcIp, w.translated.srcIp)
    }
    assert.ok(
      inRegions(
        p.regions,
        parseCidrStrict(`${w.translated.srcIp}/32`).start,
        w.translated.srcPort,
        w.translated.protocol,
      ),
      `round ${round} 见证转换后报文应落在该对碰撞区域内; ${dump}`,
    )
  }

  if (result.pairs.length > 0) collisionRounds++
  rounds++
}
// 生成器 sanity：必须真的覆盖到碰撞场景，否则对照失去意义
assert.ok(
  collisionRounds >= 40,
  `碰撞轮数过少（${collisionRounds}/${rounds}），生成器应保证相当比例的轮次存在实际碰撞`,
)
console.log(
  `转换后源身份碰撞分析模糊对照 ${rounds} 轮全部通过 ✔（其中 ${collisionRounds} 轮存在实际碰撞）`,
)
