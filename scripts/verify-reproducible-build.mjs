#!/usr/bin/env node
/**
 * Reproducible build verification — `npm run verify:build`
 *
 * Rebuilds the package from the current git HEAD (the exact commit that will
 * be published) in a clean temp checkout and compares every shipped artifact
 * byte-for-byte (SHA-256) against the working-tree lib/.
 *
 * Guarantees: the publishable artifact is exactly the commit's deterministic
 * build output — no drift from uncommitted edits, no stale lib/.
 *
 * Exit code: 0 = identical; 1 = any diff (fails the release gate).
 */
import { execSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = fileURLToPath(new URL('..', import.meta.url))

function sha256(file) {
  return createHash('sha256').update(readFileSync(file)).digest('hex')
}

function collectJsFiles(dir) {
  const out = []
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) out.push(...collectJsFiles(p))
    else if (name.endsWith('.js') || name.endsWith('.d.ts')) out.push(p)
  }
  return out.sort()
}

if (!existsSync(join(ROOT, '.git'))) {
  console.error('✗ not a git checkout — reproducible-build check requires git')
  process.exit(1)
}

const work = mkdtempSync(join(tmpdir(), 'tmguard-verify-build-'))
try {
  // Export the exact commit that would be published.
  const head = execSync('git rev-parse HEAD', { cwd: ROOT, encoding: 'utf8' }).trim()
  execSync(`git archive ${head} | tar -x -C ${work}`, { cwd: ROOT, shell: true })

  // Build the clean checkout (its own prepare/build).
  execSync('npm run build', { cwd: work, stdio: 'pipe' })

  const repoLib = collectJsFiles(join(ROOT, 'lib'))
  const cleanLib = collectJsFiles(join(work, 'lib'))

  if (repoLib.length !== cleanLib.length) {
    console.error(`✗ lib/ file count differs: worktree ${repoLib.length} vs clean ${cleanLib.length}`)
    process.exit(1)
  }

  let identical = 0
  let differs = 0
  for (let i = 0; i < repoLib.length; i++) {
    const a = repoLib[i].replace(ROOT, '').replace(/^\/+/, '')
    const b = cleanLib[i].replace(work, '').replace(/^\/+/, '')
    if (a !== b) {
      console.error(`✗ path mismatch: ${a} vs ${b}`)
      differs++
      continue
    }
    const ha = sha256(repoLib[i])
    const hb = sha256(cleanLib[i])
    if (ha === hb) {
      identical++
      console.log(`IDENTICAL  ${a}`)
    } else {
      differs++
      console.error(`DIFFERS    ${a}`)
    }
  }

  // Shipped non-lib files must also match the commit (README/CHANGELOG/LICENSE/cordis.patch.yml/package.json).
  const extra = ['README.md', 'CHANGELOG.md', 'LICENSE', 'cordis.patch.yml', 'package.json']
  for (const f of extra) {
    if (!existsSync(join(ROOT, f)) || !existsSync(join(work, f))) {
      console.error(`✗ missing shipped file ${f}`)
      differs++
      continue
    }
    const ha = sha256(join(ROOT, f))
    const hb = sha256(join(work, f))
    if (ha === hb) {
      identical++
      console.log(`IDENTICAL  ${f}`)
    } else {
      differs++
      console.error(`DIFFERS    ${f}  (uncommitted change — commit it or stash it)`)
    }
  }

  console.log('')
  console.log(`HEAD = ${head}`)
  if (differs === 0) {
    console.log(`PASS: ${identical} files byte-identical to git HEAD build`)
    process.exit(0)
  } else {
    console.error(`FAIL: ${differs} file(s) differ from HEAD build — commit/stash changes first`)
    process.exit(1)
  }
} finally {
  rmSync(work, { recursive: true, force: true })
}
