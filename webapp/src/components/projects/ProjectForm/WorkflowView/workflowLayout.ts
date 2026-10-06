/**
 * Three-band layout: data nodes above, tools in center, data nodes below.
 *
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │  (Domain) (Subdomain) (IP)    (Port) (Service)    (BaseURL) ...    │  <- upper data band
 * │                                                                     │
 * │  [Input] [Discovery] [OSINT] [PortScan] [Httpx] [ResEnum] [Nuclei] │  <- center tool band
 * │                                                                     │
 * │  (DNSRecord) (ExtDomain)      (Technology)        (Vuln) (CVE) ... │  <- lower data band
 * └─────────────────────────────────────────────────────────────────────┘
 *
 * Data nodes are split above/below to keep edges from crossing over tools.
 */

import {
  WORKFLOW_TOOLS,
  UNIVERSAL_DATA_NODES,
  TRANSITIONAL_DATA_NODES,
  getToolProduces,
  getToolConsumes,
  getToolEnriches,
} from './workflowDefinition'

// ---- Dimension constants ----
export const TOOL_NODE_WIDTH = 190
export const TOOL_NODE_HEIGHT = 56
export const DATA_NODE_WIDTH = 100
export const DATA_NODE_HEIGHT = 30
export const INPUT_NODE_WIDTH = 110
export const INPUT_NODE_HEIGHT = 70

// Spacing
const COL_GAP = 50            // horizontal gap between tool groups
const DATA_H_GAP = 12         // horizontal gap between data nodes in same band
const MAX_BAND_SLOTS = 2      // data nodes side by side in a tool column's band before it wraps
const BAND_GAP = 40          // vertical gap between center band and data bands
const DATA_V_GAP = 10         // vertical gap between stacked data nodes in same column
const MARGIN_X = 40
const MARGIN_Y = 20

// Ordered unique groups
const ORDERED_GROUPS = [...new Set(WORKFLOW_TOOLS.map(t => t.group))].sort((a, b) => a - b)

interface PositionedNode {
  id: string
  x: number
  y: number
}

/**
 * Determine which group column a transitional data node belongs to.
 * Places it just before its first consumer (forward edges) while
 * not going before its earliest producer.
 */
function getDataNodeGroup(nodeType: string): number {
  let minConsumer = Infinity
  for (const tool of WORKFLOW_TOOLS) {
    if (getToolConsumes(tool.id).includes(nodeType)) {
      minConsumer = Math.min(minConsumer, tool.group)
    }
  }

  let minProducer = Infinity
  for (const tool of WORKFLOW_TOOLS) {
    if (getToolProduces(tool.id).includes(nodeType) || getToolEnriches(tool.id).includes(nodeType)) {
      minProducer = Math.min(minProducer, tool.group)
    }
  }

  if (minConsumer === Infinity) {
    let maxProducer = 0
    for (const tool of WORKFLOW_TOOLS) {
      if (getToolProduces(tool.id).includes(nodeType) || getToolEnriches(tool.id).includes(nodeType)) {
        maxProducer = Math.max(maxProducer, tool.group)
      }
    }
    return maxProducer
  }

  const idx = ORDERED_GROUPS.indexOf(minConsumer)
  const precedingGroup = idx > 0 ? ORDERED_GROUPS[idx - 1] : ORDERED_GROUPS[0]
  return Math.max(precedingGroup, minProducer)
}

/**
 * Assign each data node to a specific row in the upper or lower band.
 * Row 0 is closest to the center tool band, higher rows are farther.
 * Spreading nodes across multiple rows prevents edge overlap.
 *
 * Returns { band: 'upper'|'lower', row: number }
 */
function getDataPlacement(nodeType: string): { band: 'upper' | 'lower'; row: number } {
  // Explicit row map for clean edge routing.
  // Nodes with many connections get their own row (farther from center)
  // so edges have vertical space to route without overlapping.
  const placements: Record<string, { band: 'upper' | 'lower'; row: number }> = {
    // Universal -- 4 rows, most-connected nodes farthest from tools
    Domain:      { band: 'upper', row: 3 },
    Subdomain:   { band: 'upper', row: 2 },
    IP:          { band: 'upper', row: 1 },

    // Transitional upper -- staggered to avoid overlapping horizontal edges
    BaseURL:     { band: 'upper', row: 0 },
    Port:        { band: 'upper', row: 1 },
    Endpoint:    { band: 'upper', row: 2 },
    Service:     { band: 'upper', row: 3 },
    CVE:         { band: 'upper', row: 0 },

    // Transitional lower -- 4 rows, spread by column proximity
    DNSRecord:       { band: 'lower', row: 0 },
    Certificate:     { band: 'lower', row: 1 },
    Technology:      { band: 'lower', row: 1 },
    Parameter:       { band: 'lower', row: 0 },
    ExternalDomain:  { band: 'lower', row: 3 },
    Header:          { band: 'lower', row: 1 },
    Secret:          { band: 'lower', row: 2 },
    Vulnerability:   { band: 'lower', row: 0 },
    MitreData:       { band: 'lower', row: 3 },
    Capec:           { band: 'lower', row: 1 },
    Package:            { band: 'lower', row: 2 },
    MalPackageFinding:  { band: 'lower', row: 3 },
  }

  return placements[nodeType] ?? { band: 'lower', row: 0 }
}

/**
 * X slot of each node in a data band. Nodes take slots left to right and wrap
 * after `maxSlots`, so a crowded band stacks on its rows instead of widening
 * its column and pushing the tool stack away from the neighbouring columns.
 * A wrapped node moves on to the next slot when its own row is taken there.
 */
function assignBandSlots(items: { row: number }[], maxSlots: number): number[] {
  const perRow = new Map<number, number>()
  for (const d of items) perRow.set(d.row, (perRow.get(d.row) ?? 0) + 1)
  // Never fewer slots than the fullest row needs, or two of its nodes would overlap.
  const slotCount = Math.max(Math.min(items.length, maxSlots), ...perRow.values())

  const taken = new Set<string>()
  return items.map((d, i) => {
    let slot = i % slotCount
    while (taken.has(`${slot}:${d.row}`)) slot = (slot + 1) % slotCount
    taken.add(`${slot}:${d.row}`)
    return slot
  })
}

export function computeLayout(
  nodeIds: { id: string; type: 'input' | 'tool' | 'data'; group: number; width: number; height: number }[],
): PositionedNode[] {

  // ---- 1. Assign data nodes to groups, bands, and rows ----
  type DataPlacement = { id: string; group: number; band: 'upper' | 'lower'; row: number; width: number; height: number }
  const dataNodes: DataPlacement[] = []

  for (const n of nodeIds) {
    if (n.type !== 'data') continue
    const nodeType = n.id.replace('data-', '')
    const group = UNIVERSAL_DATA_NODES.has(nodeType) ? 0 : getDataNodeGroup(nodeType)
    const { band, row } = getDataPlacement(nodeType)
    dataNodes.push({ id: n.id, group, band, row, width: n.width, height: n.height })
  }

  // ---- 2. Compute X positions for each group column ----
  // Each group column has: data nodes (spread horizontally) above, tools stacked vertically in center, data nodes below
  // X position is shared across all three bands for a given group

  // Build group columns: for each group, collect tools and data
  // A band's nodes with their X offsets from the band's left edge
  type DataBand = { nodes: DataPlacement[]; offsets: number[]; width: number }
  type GroupColumn = {
    group: number
    tools: { id: string; width: number; height: number }[]
    upper: DataBand
    lower: DataBand
  }

  function layoutBand(group: number, band: 'upper' | 'lower'): DataBand {
    const nodes = dataNodes.filter(d => d.group === group && d.band === band)
    if (nodes.length === 0) return { nodes, offsets: [], width: 0 }
    // The input column never wraps: its seed nodes feed most tools, and giving
    // each its own X keeps the vertical runs of those edges from overlapping.
    const slots = assignBandSlots(nodes, group === 0 ? nodes.length : MAX_BAND_SLOTS)
    const pitch = Math.max(...nodes.map(d => d.width)) + DATA_H_GAP
    return {
      nodes,
      offsets: slots.map(slot => slot * pitch),
      width: (Math.max(...slots) + 1) * pitch - DATA_H_GAP,
    }
  }

  const groupColumns: GroupColumn[] = []

  // Group 0: Input + universal data
  const inputNode = nodeIds.find(n => n.type === 'input')
  groupColumns.push({
    group: 0,
    tools: inputNode ? [{ id: inputNode.id, width: inputNode.width, height: inputNode.height }] : [],
    upper: layoutBand(0, 'upper'),
    lower: layoutBand(0, 'lower'),
  })

  // Tool groups
  for (const group of ORDERED_GROUPS) {
    const tools = nodeIds
      .filter(n => n.type === 'tool' && n.group === group)
      .map(n => ({ id: n.id, width: n.width, height: n.height }))
    groupColumns.push({ group, tools, upper: layoutBand(group, 'upper'), lower: layoutBand(group, 'lower') })
  }

  // Compute width of each column (widest of: tools width, upper data band, lower data band)
  const colWidths: number[] = groupColumns.map(col => {
    const toolW = col.tools.length > 0 ? Math.max(...col.tools.map(t => t.width)) : 0
    return Math.max(toolW, col.upper.width, col.lower.width)
  })

  // Assign X start for each column
  const colX: number[] = []
  let curX = MARGIN_X
  for (let i = 0; i < groupColumns.length; i++) {
    colX.push(curX)
    curX += colWidths[i] + COL_GAP
  }

  // ---- 3. Compute Y positions for the three bands ----
  // Center band Y: all tools aligned in a horizontal row
  // Upper data band: above center, offset by BAND_GAP
  // Lower data band: below center, offset by BAND_GAP

  // Find tallest tool column to set center band height
  let maxToolStackHeight = INPUT_NODE_HEIGHT
  for (const col of groupColumns) {
    if (col.tools.length === 0) continue
    let h = 0
    for (const t of col.tools) h += t.height + DATA_V_GAP
    h -= DATA_V_GAP
    maxToolStackHeight = Math.max(maxToolStackHeight, h)
  }

  // Upper/lower bands use multiple rows to spread data nodes vertically
  const DATA_ROW_OFFSET = DATA_NODE_HEIGHT + DATA_V_GAP
  // Find max row index used in each band
  let maxUpperRow = 0
  let maxLowerRow = 0
  for (const d of dataNodes) {
    if (d.band === 'upper') maxUpperRow = Math.max(maxUpperRow, d.row)
    if (d.band === 'lower') maxLowerRow = Math.max(maxLowerRow, d.row)
  }
  const maxUpperHeight = (maxUpperRow + 1) * DATA_ROW_OFFSET - DATA_V_GAP
  const maxLowerHeight = (maxLowerRow + 1) * DATA_ROW_OFFSET - DATA_V_GAP

  // Y anchors
  const upperBandY = MARGIN_Y  // top of upper data band
  const centerBandY = upperBandY + (maxUpperHeight > 0 ? maxUpperHeight + BAND_GAP : 0)
  const lowerBandY = centerBandY + maxToolStackHeight + BAND_GAP

  // ---- 4. Place all nodes ----
  const positions: PositionedNode[] = []

  for (let i = 0; i < groupColumns.length; i++) {
    const col = groupColumns[i]
    const x = colX[i]
    const w = colWidths[i]

    // Center tools vertically in the center band
    const totalToolHeight = col.tools.reduce((sum, t) => sum + t.height + DATA_V_GAP, -DATA_V_GAP)
    let toolY = centerBandY + (maxToolStackHeight - totalToolHeight) / 2
    for (const tool of col.tools) {
      // Center tool horizontally in column
      const toolX = x + (w - tool.width) / 2
      positions.push({ id: tool.id, x: toolX, y: toolY })
      toolY += tool.height + DATA_V_GAP
    }

    // Upper data nodes: band centered in the column, each node at its assigned row
    // Row 0 is closest to tools, higher rows are farther up
    const upperX = x + (w - col.upper.width) / 2
    col.upper.nodes.forEach((d, j) => {
      // Higher row number = farther from tools = lower Y value (closer to top)
      const y = upperBandY + (maxUpperRow - d.row) * DATA_ROW_OFFSET
      positions.push({ id: d.id, x: upperX + col.upper.offsets[j], y })
    })

    // Lower data nodes: band centered in the column, each node at its assigned row
    // Row 0 is closest to tools, higher rows are farther down
    const lowerX = x + (w - col.lower.width) / 2
    col.lower.nodes.forEach((d, j) => {
      const y = lowerBandY + d.row * DATA_ROW_OFFSET
      positions.push({ id: d.id, x: lowerX + col.lower.offsets[j], y })
    })
  }

  return positions
}
