/**
 * 转换后源身份碰撞分析（只读）。
 *
 * 源地址转换路径分析之上、**独立于后级规则**的附加分析：多条等长源地址
 * 映射的转换后网段允许重叠——若两条映射各自把「目标内经前级首命中放行」
 * 的原始报文投影到同一个转换后报文（转换后 IPv4 × 端口 × 协议完全相同），
 * 则两个不同的原始源身份在转换后空间无法区分，即发生一次
 * 「转换后源身份碰撞」。
 *
 * 计算方式：
 *   1. 前级 = 当前规则列表，按**原始地址**首命中；仅首命中动作在前级
 *      放行列表内的目标报文参与——未命中、动作不放行、非法规则与停用
 *      规则的处理与转换路径分析完全一致（非法 / 停用不参与首命中计算）；
 *   2. 目标边界、前级规则边界与映射源网段边界共同切分原始空间原子
 *      （每个原子完整落在一条映射源网段内，转换方式在原子内唯一）；
 *   3. 每条映射把属于自己的放行 IP 原子按主机位一一平移投影到转换后
 *      空间（端口与协议不改写）；全部投影区间再共同切分出转换后空间
 *      的 IP 原子，端口维与原始空间共用同一套端口原子；
 *   4. 逐转换后单元 (转换后 IP 原子 × 端口原子 × 协议) 登记覆盖它的
 *      映射集合；同一单元被 ≥2 条映射覆盖即碰撞，对覆盖集合中的每个
 *      无序映射对登记该单元；单条映射内部主机位一一对应，不会自碰撞；
 *   5. 每对碰撞映射给出碰撞空间大小、精确转换后区域（协议 → 连续
 *      端口段 × 规范 CIDR 行，复用 buildExactRegions）与确定性、可
 *      复制的见证（两条原始报文映射到同一转换后报文）；
 *   6. 总量按**转换后报文去重**：多个映射对碰撞同一转换后报文只计一次。
 *
 * 转换后网段重叠但放行区域的投影不相交（地址段 / 端口 / 协议任一维度
 * 不交）时**不报碰撞**，仅作为「网段重叠但实际不交」的映射对计数说明。
 * 分析全程只读，不修改任何规则，也不读取后级规则与后级放行动作。
 */
import {
  atomCellSize,
  buildExactRegions,
  buildIpAtoms,
  buildOwnerMap,
  buildPortAtoms,
  concreteProtocolOf,
  containedIndices,
  decodeCellKey,
  exampleIp,
  firstKey,
  protocolDimIndices,
  validateRules,
} from './engine'
import { intToIpv4 } from './iputil'
import { parseAllowActions, validateTandemTarget } from './tandem'
import type {
  NormalizedTandemTarget,
  TandemStageStats,
  TandemTargetInput,
} from './tandem'
import { parseSnatMappings, targetCoveredByMappings } from './snat'
import type { NormalizedSnatMapping, SnatPacket } from './snat'
import type { ExactRegionGroup, Protocol, RuleInput } from './types'

type ConcreteProtocol = Exclude<Protocol, 'ANY'>

// ---------------------------------------------------------------------------
// 输入与结果类型
// ---------------------------------------------------------------------------

/** 碰撞分析的表单输入：只含前级放行动作、源地址映射与目标（与后级无关） */
export interface SnatCollisionFormInput {
  allow1Text: string
  mappingsText: string
  target: TandemTargetInput
}

/** 碰撞见证：两条不同的原始报文经各自映射转换后成为同一条转换后报文 */
export interface SnatCollisionWitness {
  /** 第一条映射侧的原始报文（附转换后地址） */
  packetA: SnatPacket
  /** 第二条映射侧的原始报文（附转换后地址，与 packetA 转换后地址相同） */
  packetB: SnatPacket
  /** 二者共同映射到的转换后报文 */
  translated: {
    srcIp: string
    srcPort: number
    protocol: ConcreteProtocol
  }
}

/** 一对映射的碰撞明细 */
export interface SnatCollisionPair {
  /** 两条映射在映射列表中的下标（a < b） */
  a: number
  b: number
  /** 该对的碰撞空间大小（转换后报文空间） */
  size: number
  /** 碰撞原子单元数 */
  cells: number
  /** 精确的转换后碰撞区域（协议 → 连续端口段 × 规范 CIDR 行） */
  regions: ExactRegionGroup[]
  /** 确定性见证：两条原始报文映射到同一转换后报文（可复制复现） */
  witness: SnatCollisionWitness
}

export interface SnatCollisionResult {
  generatedAt: string
  target: NormalizedTandemTarget
  /** 实际使用的前级放行动作列表（已解析、去重） */
  allow1: string[]
  /** 实际使用的源地址映射（已规范化，源网段两两不重叠） */
  mappings: NormalizedSnatMapping[]
  /** 目标内经前级首命中放行、参与碰撞计算的报文空间大小 */
  releasedSize: number
  /** 参与碰撞计算的原子单元数 */
  releasedCells: number
  /** 全部碰撞单元按转换后报文去重后的总空间大小 */
  totalSize: number
  /** 去重后的碰撞原子单元数 */
  totalCells: number
  /** 去重后的整体转换后碰撞区域 */
  regions: ExactRegionGroup[]
  /** 实际发生碰撞的映射对（按碰撞空间降序，其次按下标） */
  pairs: SnatCollisionPair[]
  /** 转换后网段相交但放行区域投影不交的映射对（不报碰撞，仅列出说明） */
  nonCollidingOverlaps: Array<{ a: number; b: number }>
  stage1: TandemStageStats
}

export type SnatCollisionOutcome =
  | { ok: true; result: SnatCollisionResult }
  | { ok: false; errors: string[] }

// ---------------------------------------------------------------------------
// 主分析流程
// ---------------------------------------------------------------------------

/**
 * 在给定前级规则、放行动作列表、源地址映射与目标上执行转换后源身份碰撞
 * 分析。纯函数：不修改任何输入规则，不使用后级规则。调用前须保证映射
 * 合法（等长、源网段不重叠）且目标完全落在映射源网段内
 * （evaluateSnatCollision 已校验）。
 */
export function analyzeSnatCollision(
  stage1Rules: RuleInput[],
  allow1: string[],
  mappings: NormalizedSnatMapping[],
  target: NormalizedTandemTarget,
  now: Date = new Date(),
): SnatCollisionResult {
  // 非法规则与停用规则按既有语义排除，不参与首命中计算
  const v1 = validateRules(stage1Rules)
  const active1 = v1.valid.filter((r) => r.enabled)
  const stage1Stats: TandemStageStats = {
    total: stage1Rules.length,
    active: active1.length,
    invalid: v1.invalid.length,
    disabled: v1.valid.length - active1.length,
  }

  // 原始空间原子切分：目标边界、前级规则边界与映射源网段边界共同参与；
  // 源网段边界保证每个目标原子完整落在某条源网段内（所属映射唯一）
  const ipAtoms = buildIpAtoms(active1, [
    { start: target.ipStart, end: target.ipEnd },
    ...mappings.map((m) => ({ start: m.srcStart, end: m.srcEnd })),
  ])
  const portAtoms = buildPortAtoms(active1, [
    { start: target.portStart, end: target.portEnd },
  ])
  const owner1 = buildOwnerMap(active1, ipAtoms, portAtoms)
  const allowSet1 = new Set(allow1)

  // 每个 IP 原子所属的映射（源网段两两不重叠，至多一条；目标内原子必有一条）
  const mappingOfAtom = new Array<number>(ipAtoms.length).fill(-1)
  mappings.forEach((m, mi) => {
    for (const i of containedIndices(ipAtoms, m.srcStart, m.srcEnd)) {
      mappingOfAtom[i] = mi
    }
  })

  // 目标内仅「前级首命中且动作在放行列表内」的单元参与，按所属映射归集。
  // 未命中、动作不放行的单元不进入投影；它们不可能参与碰撞。
  const ipIdx = containedIndices(ipAtoms, target.ipStart, target.ipEnd)
  const portIdx = containedIndices(portAtoms, target.portStart, target.portEnd)
  const protoIdx = protocolDimIndices(target.protocol)
  const releasedByMapping: Array<Set<string>> = mappings.map(() => new Set())
  let releasedSize = 0
  let releasedCells = 0
  for (const ip of ipIdx) {
    const mi = mappingOfAtom[ip]
    if (mi < 0) continue // 目标已被校验完全落在映射源网段并集内，此处仅防御
    for (const port of portIdx) {
      const size = atomCellSize(ipAtoms[ip], portAtoms[port])
      for (const proto of protoIdx) {
        const key = `${ip}.${port}.${proto}`
        const pos1 = owner1.get(key)
        if (pos1 === undefined || !allowSet1.has(active1[pos1].action)) continue
        releasedByMapping[mi].add(key)
        releasedSize += size
        releasedCells += 1
      }
    }
  }

  // 每条映射把放行 IP 原子按主机位平移投影到转换后空间（端口 / 协议不变）。
  // 全部投影区间共同切分转换后 IP 原子：保证每个转换后原子相对每条映射
  // 要么整体被其放行投影覆盖、要么整体不覆盖，碰撞可逐单元精确判定。
  const projected: Array<{ start: number; end: number }> = []
  const projectionOf = new Map<string, { start: number; end: number }>()
  mappings.forEach((m, mi) => {
    const ips = new Set<number>()
    for (const key of releasedByMapping[mi]) ips.add(decodeCellKey(key).ip)
    for (const ip of ips) {
      const atom = ipAtoms[ip]
      const range = {
        start: (m.dstStart + (atom.start - m.srcStart)) >>> 0,
        end: (m.dstStart + (atom.end - m.srcStart)) >>> 0,
      }
      projectionOf.set(`${mi}.${ip}`, range)
      projected.push(range)
    }
  })
  const tIpAtoms = buildIpAtoms([], projected)

  // 逐转换后单元登记覆盖它的映射集合（端口维与协议维不发生改写，直接沿用原 key）
  const cover = new Map<string, Set<number>>()
  mappings.forEach((_m, mi) => {
    for (const key of releasedByMapping[mi]) {
      const { ip, port, proto } = decodeCellKey(key)
      const range = projectionOf.get(`${mi}.${ip}`)!
      for (const tip of containedIndices(tIpAtoms, range.start, range.end)) {
        const tKey = `${tip}.${port}.${proto}`
        let set = cover.get(tKey)
        if (!set) {
          set = new Set()
          cover.set(tKey, set)
        }
        set.add(mi)
      }
    }
  })

  // 同一转换后单元被 ≥2 条映射覆盖即碰撞：登记到覆盖集合的每个无序映射对；
  // unionKeys 按转换后单元去重——多对映射碰撞同一转换后报文只计一次
  const pairKeys = new Map<string, Set<string>>()
  const unionKeys = new Set<string>()
  for (const [tKey, set] of cover) {
    if (set.size < 2) continue
    unionKeys.add(tKey)
    const list = [...set].sort((x, y) => x - y)
    for (let i = 0; i < list.length; i++) {
      for (let j = i + 1; j < list.length; j++) {
        const pk = `${list[i]}.${list[j]}`
        let keys = pairKeys.get(pk)
        if (!keys) {
          keys = new Set()
          pairKeys.set(pk, keys)
        }
        keys.add(tKey)
      }
    }
  }

  const summarize = (keys: Set<string>) => {
    let size = 0
    for (const key of keys) {
      const { ip, port } = decodeCellKey(key)
      size += atomCellSize(tIpAtoms[ip], portAtoms[port])
    }
    return size
  }

  /**
   * 碰撞见证：取该对字典序最小的碰撞转换后单元，按引擎统一选点规则取
   * 转换后代表地址（原子块内第 2 个地址、段首端口），再分别逆映射回两条
   * 映射的源网段。逆映射地址必落在该单元对应的放行原始原子内
   * （转换后原子是投影区间的子集，平移是双向一一对应），因此两条原始
   * 报文都确实经前级放行，且转换后完全相同。
   */
  const buildWitness = (a: number, b: number, tKey: string): SnatCollisionWitness => {
    const { ip, port, proto } = decodeCellKey(tKey)
    const tIp = exampleIp(tIpAtoms[ip])
    const srcPort = portAtoms[port].start
    const protocol = concreteProtocolOf(proto)
    const translatedText = intToIpv4(tIp)
    const originalFor = (mi: number): SnatPacket => {
      const m = mappings[mi]
      return {
        srcIp: intToIpv4((m.srcStart + (tIp - m.dstStart)) >>> 0),
        srcPort,
        protocol,
        translatedSrcIp: translatedText,
      }
    }
    return {
      packetA: originalFor(a),
      packetB: originalFor(b),
      translated: { srcIp: translatedText, srcPort, protocol },
    }
  }

  const pairs: SnatCollisionPair[] = []
  for (const [pk, keys] of pairKeys) {
    const [a, b] = pk.split('.').map(Number)
    pairs.push({
      a,
      b,
      size: summarize(keys),
      cells: keys.size,
      regions: buildExactRegions(keys, tIpAtoms, portAtoms),
      witness: buildWitness(a, b, firstKey(keys)),
    })
  }
  pairs.sort((x, y) => y.size - x.size || x.a - y.a || x.b - y.b)

  // 转换后网段相交但实际放行区域投影不交的映射对：不报碰撞，仅列出说明
  const nonCollidingOverlaps: Array<{ a: number; b: number }> = []
  for (let a = 0; a < mappings.length; a++) {
    for (let b = a + 1; b < mappings.length; b++) {
      const ma = mappings[a]
      const mb = mappings[b]
      const netOverlap =
        Math.max(ma.dstStart, mb.dstStart) <= Math.min(ma.dstEnd, mb.dstEnd)
      if (netOverlap && !pairKeys.has(`${a}.${b}`)) {
        nonCollidingOverlaps.push({ a, b })
      }
    }
  }

  return {
    generatedAt: now.toISOString(),
    target,
    allow1: [...allow1],
    mappings: mappings.map((m) => ({ ...m })),
    releasedSize,
    releasedCells,
    totalSize: summarize(unionKeys),
    totalCells: unionKeys.size,
    regions: buildExactRegions(unionKeys, tIpAtoms, portAtoms),
    pairs,
    nonCollidingOverlaps,
    stage1: stage1Stats,
  }
}

/**
 * 面板入口：校验前级放行动作列表、源地址映射与目标（后级规则不参与）。
 * 任一致命错误都阻止分析；全部通过后执行碰撞分析。
 * 目标必须完全落在映射源网段（并集）内，与转换路径分析同一套校验。
 */
export function evaluateSnatCollision(
  stage1Rules: RuleInput[],
  form: SnatCollisionFormInput,
  now: Date = new Date(),
): SnatCollisionOutcome {
  const errors: string[] = []

  const { target, errors: targetErrors } = validateTandemTarget(form.target)
  errors.push(...targetErrors)

  const allow1 = parseAllowActions(form.allow1Text)
  if (allow1.length === 0) {
    errors.push('前级放行动作列表不能为空（至少填写一个动作，多个动作用逗号或空格分隔）')
  }

  const { mappings, errors: mappingErrors } = parseSnatMappings(form.mappingsText)
  errors.push(...mappingErrors)

  if (target && mappingErrors.length === 0 && !targetCoveredByMappings(target, mappings)) {
    errors.push(
      `目标 ${target.cidrText} 未完全落在映射源网段内：` +
        '源地址转换要求目标中的每个地址都能按主机位一一映射',
    )
  }

  if (errors.length > 0 || !target) return { ok: false, errors }
  return {
    ok: true,
    result: analyzeSnatCollision(stage1Rules, allow1, mappings, target, now),
  }
}
