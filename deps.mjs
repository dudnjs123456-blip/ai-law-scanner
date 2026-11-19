/**
 * 의존성 취약점 점검: 잠금 파일(package-lock.json, requirements.txt)의 정확한 버전을
 * 공개 취약점 데이터베이스 OSV(https://osv.dev, Google 운영)와 대조한다.
 *
 * 인터넷이 필요해서 scan() 과 따로 돌린다. 취약점 DB 는 날마다 바뀌므로 스냅숏 테스트에는 넣지 않는다.
 */
import fs from 'node:fs';
import path from 'node:path';

const OSV = 'https://api.osv.dev/v1';
const SEV_RANK = { CRITICAL: 0, HIGH: 1, MODERATE: 2, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };
const SEV_KO = { CRITICAL: '치명적', HIGH: '높음', MODERATE: '보통', MEDIUM: '보통', LOW: '낮음', UNKNOWN: '등급 없음' };

/** 잠금 파일에서 "이름@버전" 목록을 뽑는다 */
export function readLockfiles(root, all) {
  const pkgs = new Map();
  const add = (ecosystem, name, version, dev, file, via = null) => {
    if (!name || !version || !/^\d/.test(version)) return;
    const key = `${ecosystem}:${name}@${version}`;
    const prev = pkgs.get(key);
    if (!prev) pkgs.set(key, { ecosystem, name, version, dev: !!dev, file, via });
    else if (!dev) prev.dev = false; // 하나라도 실제 서비스에서 쓰면 서비스용으로 본다
  };
  for (const rel of all.filter((r) => /(^|\/)package-lock\.json$/.test(r) && !/node_modules\//.test(r))) {
    try {
      const lock = JSON.parse(fs.readFileSync(path.join(root, rel), 'utf8'));
      if (lock.packages) {
        for (const [p, info] of Object.entries(lock.packages)) {
          if (!p.includes('node_modules/') || info.link) continue;
          // node_modules/next/node_modules/postcss → postcss 는 next 안에 들어 있는 복사본 (next 를 올려야 고쳐진다)
          const parts = p.split('node_modules/').map((s) => s.replace(/\/$/, '')).filter(Boolean);
          add('npm', parts[parts.length - 1], info.version, info.dev || info.devOptional, rel, parts.length > 1 ? parts[parts.length - 2] : null);
        }
      } else if (lock.dependencies) {
        const walk = (deps) => { for (const [name, info] of Object.entries(deps)) { add('npm', name, info.version, info.dev, rel); if (info.dependencies) walk(info.dependencies); } };
        walk(lock.dependencies);
      }
    } catch { /* 깨진 잠금 파일은 건너뛴다 */ }
  }
  for (const rel of all.filter((r) => /(^|\/)requirements[^/]*\.txt$/.test(r))) {
    try {
      for (const line of fs.readFileSync(path.join(root, rel), 'utf8').split('\n')) {
        const m = line.trim().match(/^([A-Za-z0-9._-]+)\s*==\s*([0-9][^\s;#]*)/);
        if (m) add('PyPI', m[1].toLowerCase(), m[2], false, rel);
      }
    } catch { /* 무시 */ }
  }
  return [...pkgs.values()];
}

async function postJson(url, body, timeoutMs) {
  const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) throw new Error(`osv ${res.status}`);
  return res.json();
}

function severityOf(v) {
  const s = (v.database_specific?.severity || '').toUpperCase();
  return SEV_RANK[s] !== undefined ? s : 'UNKNOWN';
}
function fixedVersion(v, pkg) {
  for (const a of v.affected ?? []) {
    if (a.package?.name?.toLowerCase() !== pkg.name.toLowerCase()) continue;
    for (const r of a.ranges ?? []) for (const e of r.events ?? []) if (e.fixed) return e.fixed;
  }
  return null;
}

const ITEM = { id: 'dependencies', owasp: 'A06', title: '알려진 취약점이 있는 패키지' };

/** 보안 점검 항목 하나를 돌려준다 (judgeSecurity 결과와 같은 모양) */
export async function checkDependencies(root, all, { timeoutMs = 12_000, maxDetails = 40 } = {}) {
  const pkgs = readLockfiles(root, all);
  const hasManifest = all.some((r) => /(^|\/)(package\.json|requirements[^/]*\.txt|pyproject\.toml)$/.test(r) && !/node_modules\//.test(r));
  if (!pkgs.length) {
    return hasManifest
      ? { ...ITEM, s: 'ask', why: '정확한 패키지 버전이 적힌 잠금 파일(package-lock.json 등)이 없어서 취약점을 대조하지 못했어요.', fix: ['npm install 로 package-lock.json 을 만들어 저장소에 함께 올리기'], evidence: [] }
      : { ...ITEM, s: 'lo', why: '외부 패키지 목록 파일이 없어요.', fix: [], evidence: [] };
  }
  try {
    // 1) 패키지마다 취약점 ID 조회 (한 번에 최대 1000개)
    const hits = [];
    for (let i = 0; i < pkgs.length; i += 1000) {
      const chunk = pkgs.slice(i, i + 1000);
      const out = await postJson(`${OSV}/querybatch`, { queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })) }, timeoutMs);
      out.results.forEach((r, j) => { for (const v of r.vulns ?? []) hits.push({ pkg: chunk[j], id: v.id }); });
    }
    if (!hits.length) return { ...ITEM, s: 'lo', why: `패키지 ${pkgs.length}개를 공개 취약점 DB(OSV)와 대조했는데, 알려진 취약점이 없어요.`, fix: [], evidence: [] };

    // 2) 취약점 상세(심각도·고쳐진 버전)
    const ids = [...new Set(hits.map((h) => h.id))].slice(0, maxDetails);
    const details = new Map();
    for (let i = 0; i < ids.length; i += 8) {
      await Promise.all(ids.slice(i, i + 8).map(async (id) => {
        try { const r = await fetch(`${OSV}/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(timeoutMs) }); if (r.ok) details.set(id, await r.json()); } catch { /* 상세가 없어도 ID 는 보여 준다 */ }
      }));
    }
    const rows = hits.map((h) => {
      const v = details.get(h.id);
      const sev = v ? severityOf(v) : 'UNKNOWN';
      return { ...h, sev, summary: v?.summary ?? '', fixed: v ? fixedVersion(v, h.pkg) : null };
    }).sort((a, b) => (a.pkg.dev - b.pkg.dev) || (SEV_RANK[a.sev] - SEV_RANK[b.sev]));

    const prodSerious = rows.filter((r) => !r.pkg.dev && (r.sev === 'CRITICAL' || r.sev === 'HIGH'));
    const affected = new Set(rows.map((r) => `${r.pkg.name}@${r.pkg.version}`));
    const evidence = rows.slice(0, 10).map((r) => ({
      file: r.pkg.file, line: 0,
      code: `${r.pkg.name}@${r.pkg.version}${r.pkg.via ? ` (${r.pkg.via} 안에 포함)` : ''}${r.pkg.dev ? ' (개발용)' : ''} — ${r.id} [${SEV_KO[r.sev]}]${r.summary ? ` ${r.summary.slice(0, 90)}` : ''}${r.fixed ? ` → ${r.fixed} 에서 고쳐짐` : ''}`,
    }));
    const parents = [...new Set(rows.filter((r) => r.pkg.via).map((r) => r.pkg.via))];
    return {
      ...ITEM,
      s: prodSerious.length ? 'hi' : 'mid',
      why: `패키지 ${pkgs.length}개 중 ${affected.size}개에 알려진 취약점 ${new Set(rows.map((r) => r.id)).size}개가 있어요.${prodSerious.length ? ` 개발용 표시가 없는 패키지에 심각도 높음 이상이 ${prodSerious.length}건 있어요. 빌드에만 쓰이는지, 실제 서비스에서 사용자 입력을 다루는지에 따라 실제 위험은 달라요.` : ' 심각도 높음 이상은 개발용 패키지에만 있거나 없어요.'}`,
      fix: [
        ...(parents.length ? [`취약한 패키지 일부는 ${parents.join(', ')} 안에 들어 있는 복사본이에요. 그 패키지를 최신 버전으로 올려야 고쳐져요`] : []),
        'npm audit fix 로 자동으로 올릴 수 있는 것부터 올리기', '"고쳐짐" 버전 이상으로 올린 뒤 기능 테스트하기', '개발용 패키지는 서비스에 포함되지 않으면 우선순위를 낮춰도 돼요'],
      evidence,
    };
  } catch (e) {
    return { ...ITEM, s: 'ask', why: '공개 취약점 DB(OSV)에 연결하지 못해서 이번에는 대조하지 못했어요. 잠시 후 다시 진단해 주세요.', fix: [], evidence: [] };
  }
}
