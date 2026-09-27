/**
 * 转换后源身份碰撞分析（只读）。
 *
 * 源地址转换（SNAT）下，多条等长映射的**转换后网段**允许重叠：两个不同的
 * 原始报文可能经各自映射平移后成为**同一个转换后报文**（转换后源 IP、
 * 源端口、协议完全相同）——后级策略将无法区分这两条报文的来源身份，
 * 称为「转换后源身份碰撞」。
 *
 * 本分析复用「源地址转换路径分析」的当前规则（前级）、前级放行动作列表、
 * 源地址映射与目标输入，**独立于后级规则**：
 *
 *   1. 仅目标空间（IPv4 CIDR × 端口区间 × 协议）内**经前级首命中放行**
 *      的报文参与计算——前级未命中任何规则、或首命中动作不在前级放行
 *      列表内的报文不参与；非法与停用规则按既有语义排除并计数说明；
 *   2. 按每条等长映射，把放行的原始 IPv4 × 端口 × 协议区域按主机位
 *      平移**投影到转换后空间**（端口与协议不改写）；
 *   3. 对全部映射**逐对求交**：某转换后报文同时落在两条映射的投影内，
 *      即存在两条不同的原始报文映射到它，记为一次碰撞。转换后网段虽
 *      重叠、但实际放行区域不交时不报碰撞；
 *   4. 多对映射重叠于同一转换后报文时，**总量按转换后报文去重**
 *      （同一转换后报文无论被多少对映射共享，只计一次）。
 *
 * 实现：原始空间按「目标 + 映射源网段 + 前级规则」边界切分原子并构建
 * 前级 owner 表；再把每条映射在「目标 ∩ 源网段」内的原子逐一平移到
 * 转换后空间，以全部投影像的边界做第二次原子切分。每个转换后原子相对
 * 每条映射要么整体落在某个投影像内（其原像完整落在同一原始原子内，
 * 前级归属一致）、要么整体无关，因此逐单元统计精确无近似。每个转换后
 * 单元的「贡献映射」= 原像经前级首命中且动作放行的映射；贡献者 ≥ 2 即
 * 碰撞单元。分析全程只读，不修改任何规则。
 */
import {
  atomCellSize,
  buildExactRegions,
  buildIpAtoms,
  buildOwnerMap,
  buildPortAtoms,
  containedIndices,
  decodeCellKey,
  firstKey,
  packetFromKey,
  protocolDimIndices,
  validateRules,
} from './engine'
import { intToIpv4, ipv4ToInt } from './iputil'
import { parseAllowActions, validateTandemTarget } from './tandem'
import type {
  NormalizedTandemTarget,
  TandemStageStats,
} from './tandem'
import {
  parseSnatMappings,
  targetCoveredByMappings,
} from './snat'
import type { NormalizedSnatMapping, SnatFormInput } from './snat'
import type { ExactRegionGroup, Protocol, RuleInput } from './types'

type ConcreteProtocol = Exclude<Protocol, 'ANY'>

// ---------------------------------------------------------------------------
// 结果类型
// ---------------------------------------------------------------------------

/** 一个具体报文（可复制复现） */
export interface SnatCollisionPacket {
  srcIp: string
  srcPort: number
  protocol: ConcreteProtocol
}

/**
 * 碰撞见证：两条不同的原始报文（分别落在两条映射的源网段内、
 * 均经前级首命中放行）映射到同一个转换后报文。
 */
export interface SnatCollisionWitness {
  /** 经第一条映射的原始报文 */
  firstOriginal: SnatCollisionPacket
  /** 经第二条映射的原始报文 */
  secondOriginal: SnatCollisionPacket
  /** 两条原始报文共同的转换后报文 */
  translated: SnatCollisionPacket
}

/** 一对映射的碰撞明细 */
export interface SnatCollisionPair {
  /** 两条映射在映射列表中的下标（first < second，按映射文本行序） */
  first: number
  second: number
  firstMapping: { sourceText: string; translatedText: string }
  secondMapping: { sourceText: string; translatedText: string }
  /** 碰撞空间大小（转换后报文数：IP 数 × 端口数，ANY 目标为两协议合计） */
  size: number
  /** 碰撞单元数（转换后空间原子切分下） */
  cells: number
  /** 精确转换后区域（协议 → 连续端口段 × 规范 CIDR 行） */
  regions: ExactRegionGroup[]
  /** 确定性见证（对内字典序最小单元，选点规则与引擎示例报文一致） */
  witness: SnatCollisionWitness
}

export interface SnatCollisionResult {
  generatedAt: string
  target: NormalizedTandemTarget
  /** 前级实际使用的放行动作列表（已解析、去重） */
  allow1: string[]
  /** 实际使用的源地址映射（已规范化，源网段两两不重叠） */
  mappings: NormalizedSnatMapping[]
  stage1: TandemStageStats
  /** 目标内经前级首命中放行、参与碰撞计算的报文空间大小 */
  allowedSize: number
  allowedCells: number
  /** 碰撞总量：按转换后报文去重（多对重叠于同一报文只计一次） */
  totalSize: number
  totalCells: number
  /** 全部碰撞的精确转换后区域（各对碰撞区域的并集，去重） */
  totalRegions: ExactRegionGroup[]
  /** 逐对碰撞明细（按碰撞空间降序，同量按映射下标升序） */
  pairs: SnatCollisionPair[]
}

export type SnatCollisionOutcome =
  | { ok: true; result: SnatCollisionResult }
  | { ok: false; errors: string[] }

// ---------------------------------------------------------------------------
// 主分析流程
// ---------------------------------------------------------------------------

/** 一条映射的投影像：原始原子平移到转换后空间后的区间及其来源 */
interface ProjectionImage {
  start: number
  end: number
  /** 映射下标 */
  m: number
  /** 原像所在的原始空间原子下标 */
  origIdx: number
}

/**
 * 在给定前级规则、前级放行动作列表、源地址映射与目标上执行碰撞分析。
 * 纯函数：不修改任何输入规则。调用前须保证映射合法（等长、源网段不重叠）
 * 且目标完全落在映射源网段内（evaluateSnatCollision 已校验）。
 */
export function analyzeSnatCollision(
  stage1Rules: RuleInput[],
  allow1: string[],
  mappings: NormalizedSnatMapping[],
  target: NormalizedTandemTarget,
  now: Date = new Date(),
): SnatCollisionResult {
  // 非法规则与停用规则均按既有语义排除，不参与首命中计算
  const v1 = validateRules(stage1Rules)
  const active1 = v1.valid.filter((r) => r.enabled)
  const stage1Stats: TandemStageStats = {
    total: stage1Rules.length,
    active: active1.length,
    invalid: v1.invalid.length,
    disabled: v1.valid.length - active1.length,
  }

  // 原始空间原子切分：目标边界、映射源网段边界与前级规则边界共同切分，
  // 保证每个原始原子完整落在某条映射源网段 ∩ 目标内（或完全在外），
  // 且相对每条前级规则要么整体命中、要么整体不命中
  const ipAtoms = buildIpAtoms(active1, [
    { start: target.ipStart, end: target.ipEnd },
    ...mappings.map((m) => ({ start: m.srcStart, end: m.srcEnd })),
  ])
  const portAtoms = buildPortAtoms(active1, [
    { start: target.portStart, end: target.portEnd },
  ])
  const owner1 = buildOwnerMap(active1, ipAtoms, portAtoms)
  const allowSet1 = new Set(allow1)

  const portIdx = containedIndices(portAtoms, target.portStart, target.portEnd)
  const protoIdx = protocolDimIndices(target.protocol)

  /** 原始单元 (ipIdx, port, proto) 是否经前级首命中放行 */
  const allowedAt = (ipAtomIdx: number, port: number, proto: number): boolean => {
    const pos1 = owner1.get(`${ipAtomIdx}.${port}.${proto}`)
    return pos1 !== undefined && allowSet1.has(active1[pos1].action)
  }

  // 每条映射：把「目标 ∩ 源网段」内的原始原子按主机位平移到转换后空间
  const images: ProjectionImage[] = []
  mappings.forEach((m, mi) => {
    const lo = Math.max(m.srcStart, target.ipStart)
    const hi = Math.min(m.srcEnd, target.ipEnd)
    if (lo > hi) return
    for (const idx of containedIndices(ipAtoms, lo, hi)) {
      const atom = ipAtoms[idx]
      images.push({
        start: (m.dstStart + (atom.start - m.srcStart)) >>> 0,
        end: (m.dstStart + (atom.end - m.srcStart)) >>> 0,
        m: mi,
        origIdx: idx,
      })
    }
  })

  // 参与计算的放行报文空间（原始空间逐单元统计；映射源网段两两不重叠，
  // 不会重复计数）。未命中前级或动作不放行的单元不参与碰撞计算
  let allowedSize = 0
  let allowedCells = 0
  for (const im of images) {
    for (const port of portIdx) {
      const size = atomCellSize(ipAtoms[im.origIdx], portAtoms[port])
      for (const proto of protoIdx) {
        if (allowedAt(im.origIdx, port, proto)) {
          allowedSize += size
          allowedCells += 1
        }
      }
    }
  }

  // 转换后空间原子切分：全部投影像的边界共同切分。同一映射的投影像
  // 两两不重叠（原像互斥、平移保持相对位置），不同映射的像可任意重叠
  const tAtoms = buildIpAtoms(
    [],
    images.map((im) => ({ start: im.start, end: im.end })),
  )

  // 每个转换后原子的候选来源（映射 + 原像原子）：同一映射至多一条像覆盖它
  const candidates = new Map<number, ProjectionImage[]>()
  for (const im of images) {
    for (const tIdx of containedIndices(tAtoms, im.start, im.end)) {
      let list = candidates.get(tIdx)
      if (!list) {
        list = []
        candidates.set(tIdx, list)
      }
      list.push(im)
    }
  }

  // 逐单元重放：转换后单元的贡献映射 = 原像经前级首命中放行的候选映射
  const totalKeys = new Set<string>()
  const pairKeys = new Map<string, Set<string>>() // "i|j"（i<j）-> 转换后单元 key
  for (const [tIdx, imgs] of candidates) {
    if (imgs.length < 2) continue // 单条映射独占的转换后原子不可能碰撞
    for (const port of portIdx) {
      for (const proto of protoIdx) {
        const contributors: number[] = []
        for (const im of imgs) {
          if (allowedAt(im.origIdx, port, proto)) contributors.push(im.m)
        }
        if (contributors.length < 2) continue
        const key = `${tIdx}.${port}.${proto}`
        totalKeys.add(key)
        for (let a = 0; a < contributors.length; a++) {
          for (let b = a + 1; b < contributors.length; b++) {
            const pk = `${contributors[a]}|${contributors[b]}`
            let set = pairKeys.get(pk)
            if (!set) {
              set = new Set()
              pairKeys.set(pk, set)
            }
            set.add(key)
          }
        }
      }
    }
  }

  const summarizeKeys = (keys: Iterable<string>) => {
    let size = 0
    for (const key of keys) {
      const { ip, port } = decodeCellKey(key)
      size += atomCellSize(tAtoms[ip], portAtoms[port])
    }
    return size
  }

  /**
   * 碰撞见证：取对内字典序最小的转换后单元，其代表报文（选点规则与引擎
   * 示例报文一致）分别按两条映射逆平移回原始空间，得到两条不同的原始
   * 报文——它们都落在目标 ∩ 各自源网段内且经前级放行（贡献者判定保证），
   * 映射后是同一个转换后报文。
   */
  const buildWitness = (
    key: string,
    first: number,
    second: number,
  ): SnatCollisionWitness => {
    const translated = packetFromKey(key, tAtoms, portAtoms)
    const tIp = ipv4ToInt(translated.srcIp)
    const preimage = (mi: number): SnatCollisionPacket => {
      const m = mappings[mi]
      return {
        srcIp: intToIpv4((m.srcStart + (tIp - m.dstStart)) >>> 0),
        srcPort: translated.srcPort,
        protocol: translated.protocol,
      }
    }
    return {
      firstOriginal: preimage(first),
      secondOriginal: preimage(second),
      translated,
    }
  }

  const pairs: SnatCollisionPair[] = []
  for (const [pk, keys] of pairKeys) {
    const [first, second] = pk.split('|').map(Number)
    pairs.push({
      first,
      second,
      firstMapping: {
        sourceText: mappings[first].sourceText,
        translatedText: mappings[first].translatedText,
      },
      secondMapping: {
        sourceText: mappings[second].sourceText,
        translatedText: mappings[second].translatedText,
      },
      size: summarizeKeys(keys),
      cells: keys.size,
      regions: buildExactRegions(keys, tAtoms, portAtoms),
      witness: buildWitness(firstKey(keys), first, second),
    })
  }
  pairs.sort((a, b) => b.size - a.size || a.first - b.first || a.second - b.second)

  return {
    generatedAt: now.toISOString(),
    target,
    allow1: [...allow1],
    mappings: mappings.map((m) => ({ ...m })),
    stage1: stage1Stats,
    allowedSize,
    allowedCells,
    totalSize: summarizeKeys(totalKeys),
    totalCells: totalKeys.size,
    totalRegions: buildExactRegions(totalKeys, tAtoms, portAtoms),
    pairs,
  }
}

/**
 * 面板入口：仅校验碰撞分析自身依赖的输入（目标、前级放行动作列表、
 * 源地址映射），**不校验后级规则**——碰撞分析与后级无关，后级 JSON
 * 缺失或非法不影响本分析。任一自身输入错误都阻止分析。
 */
export function evaluateSnatCollision(
  stage1Rules: RuleInput[],
  form: Pick<SnatFormInput, 'allow1Text' | 'mappingsText' | 'target'>,
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
