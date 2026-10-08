/**
 * vhostSniCustomWordlist is pasted text, one hostname or prefix per line.
 *
 * It was declared `project_file`, so every MCP write of a real list was refused
 * as "not an absolute path", and the recon-side path check pinned whatever the
 * form saved back to "". The vhost module parses the text itself and opens no
 * file, so a path check was never the right control for it.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {} }))

import { filterReconSettings } from './filter'
import { field } from './registry'

const write = (value: unknown) =>
  filterReconSettings({ vhostSniCustomWordlist: value }, { mode: 'update' })

describe('the vhost custom wordlist takes inline hostnames', () => {
  test('it is declared a hostname list, not a path', () => {
    expect(field('vhostSniCustomWordlist')!.validator).toBe('hostname_list')
  })

  test('prefixes, full names, comments, blank lines and CRLF are accepted', () => {
    const r = write('# staging edges\nadmin\r\n\nhidden.acme.com\n  dev-01  \n_internal.acme.com')
    expect(r.ok).toBe(true)
  })

  test('an empty list is "none"', () => {
    expect(write('').ok).toBe(true)
  })

  test.each([
    ['/etc/passwd'],
    ['admin\n../../etc/passwd'],
    ['https://admin.acme.com/'],
    ['admin staging'],
  ])('%j is refused, naming the line', (value) => {
    const r = write(value)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error).toMatch(/line \d+/)
  })

  test('a non-string is refused', () => {
    expect(write(['admin']).ok).toBe(false)
  })

  test('a list far beyond any wordlist is refused', () => {
    expect(write('a\n'.repeat(600_000)).ok).toBe(false)
  })

  test('a 5,000-name list fits', () => {
    const big = Array.from({ length: 5000 }, (_, i) => `host${i}.acme.com`).join('\n')
    expect(write(big).ok).toBe(true)
  })
})
