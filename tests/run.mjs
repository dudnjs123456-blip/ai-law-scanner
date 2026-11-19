#!/usr/bin/env node
/**
 * 진단 엔진 회귀 테스트
 *
 *   npm test              모든 테스트
 *   npm test -- --offline 인터넷이 필요한 테스트(고정 커밋 저장소)는 건너뛴다
 *   npm test -- --update  스냅숏 기대 결과를 지금 결과로 다시 쓴다 (규칙을 일부러 바꿨을 때만)
 *
 * 1) 스냅숏: 테스트용 코드와 고정 커밋 저장소의 판정 전체가 기대 결과(tests/expected.json)와 같아야 한다
 * 2) 변형: 정상 앱에서 한 가지만 바꿨을 때 노린 판정만 바뀌어야 한다 (규칙이 정말 그 근거로 판정하는지 확인)
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan } from '../scan.mjs';
import { fetchRepo } from '../lib/fetch-repo.mjs';
import { checkDependencies } from '../deps.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const EXPECTED = path.join(ROOT, 'tests', 'expected.json');
const args = process.argv.slice(2);
const OFFLINE = args.includes('--offline');
const UPDATE = args.includes('--update');

/** 판정을 "항목 → 상태" 표로 */
const verdicts = (r) => Object.fromEntries([
  ...r.findings.map((x) => [`${x.law}:${x.title}`, x.s]),
  ...r.security.map((x) => [`보안:${x.title}`, x.s]),
]);

const tmp = (name) => fs.mkdtempSync(path.join(os.tmpdir(), `ai-law-test-${name}-`));
function copyFixture(name) {
  const dir = tmp(name);
  fs.cpSync(path.join(ROOT, 'fixtures', name), dir, { recursive: true });
  return dir;
}
function edit(dir, rel, fn) {
  const file = path.join(dir, rel);
  const before = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
  const after = fn(before);
  if (after === before) throw new Error(`변형이 적용되지 않았어요: ${rel}`);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, after);
}
/** 테스트 실행 중에만 만드는 가짜 키 (저장소에는 올리지 않는다) */
const fakeKey = (prefix) => prefix + Array.from({ length: 40 }, (_, i) => 'aB3dE5gH7jK9mN1pQ2sT4vW6yZ8'[(i * 7) % 27]).join('');

// ───────────────────────── 테스트 목록 ─────────────────────────

const SNAPSHOTS = [
  { name: 'fixture/good-app', load: () => path.join(ROOT, 'fixtures', 'good-app') },
  { name: 'fixture/prose-mention', load: () => path.join(ROOT, 'fixtures', 'prose-mention') },
  { name: 'repo/ONE@dcd75b8', online: true, repo: { owner: 'dudnjs123456-blip', repo: 'ONE', sha: 'dcd75b8887eec1307dd5e2568c237db6cc14aec1' } },
  { name: 'repo/introduce@e57aedd', online: true, repo: { owner: 'dudnjs123456-blip', repo: 'introduce', sha: 'e57aedd2899c246c185a4ce22bdcd8d0153c52f9' } },
];

const GOOD_LABEL = '<p>이 이미지는 AI가 생성했어요. 워터마크가 포함돼요.</p>';
const MUTATIONS = [
  {
    name: 'AI 표시 문구를 지우면 표시 의무 위반',
    base: 'good-app',
    apply: (d) => edit(d, 'src/components/DrawPanel.tsx', (s) => s.replace(GOOD_LABEL, '<p>그림이 완성됐어요.</p>')),
    expect: { 'ai-basic:생성형 AI 결과물 표시': 'hi', 'ai-basic:AI 이용 사실 사전 고지': 'hi', 'eu:챗봇·생성물 투명성 (EU 이용자 대상)': 'ask' },
  },
  {
    name: '코드에 Anthropic 키를 넣으면 비밀키 노출',
    base: 'good-app',
    apply: (d) => edit(d, 'src/lib/config.ts', () => `export const CLAUDE_KEY = '${fakeKey('sk-ant-api03-')}';\n`),
    expect: { '보안:비밀키 노출': 'hi' },
  },
  {
    name: '설명용 가짜 키(sk-xxxx)는 비밀키로 세지 않음',
    base: 'good-app',
    apply: (d) => edit(d, 'README.md', () => 'OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 처럼 넣으세요\n'),
    expect: { '보안:비밀키 노출': 'lo' },
  },
  {
    name: '.env 파일을 올리면 주의',
    base: 'good-app',
    apply: (d) => edit(d, '.env', () => 'OPENAI_API_KEY=\n'),
    expect: { '보안:비밀키 노출': 'mid' },
  },
  {
    name: 'NEXT_PUBLIC_ 로 AI 키를 쓰면 브라우저로 키가 샘',
    base: 'good-app',
    apply: (d) => edit(d, 'src/components/KeyBadge.tsx', () => "export default function KeyBadge() { return <span>{process.env.NEXT_PUBLIC_OPENAI_API_KEY ? 'on' : 'off'}</span>; }\n"),
    expect: { '보안:브라우저로 새는 AI 키': 'hi' },
  },
  {
    name: 'AI 응답 화면에 dangerouslySetInnerHTML 을 쓰면 HTML 삽입 위험',
    base: 'good-app',
    apply: (d) => edit(d, 'src/components/DrawPanel.tsx', (s) => s.replace(GOOD_LABEL, `${GOOD_LABEL}<div dangerouslySetInnerHTML={{ __html: '' }} />`)),
    expect: { '보안:AI 응답의 HTML 삽입': 'hi', 'ai-basic:생성형 AI 결과물 표시': 'ok' },
  },
  {
    name: '요청 횟수 제한을 넣으면 비용 제한 잘한 점',
    base: 'good-app',
    apply: (d) => edit(d, 'src/app/api/draw/route.ts', (s) => s.replace('const client = new OpenAI();', 'const client = new OpenAI();\nconst limiter = rateLimit({ perMinute: 5 });')),
    expect: { '보안:AI 호출 횟수·비용 제한': 'ok' },
  },
  {
    name: '사용자 값을 시스템 지시문에 넣으면 프롬프트 인젝션 주의',
    base: 'good-app',
    apply: (d) => edit(d, 'src/app/api/draw/route.ts', (s) => s.replace("const { prompt } = await req.json();", "const body = await req.json();\n  const { prompt } = body;\n  const chat = await client.chat.completions.create({ model: 'gpt-4o', messages: [{ role: 'system', content: body.style }] });")),
    expect: { '보안:프롬프트 인젝션': 'mid' },
  },
  {
    name: '같은 도구 이름이 주석(개발 메모)에 있으면 흔적으로 셈',
    base: 'prose-mention',
    apply: (d) => edit(d, 'src/components/About.jsx', (s) => `// 음성 파일은 ElevenLabs 로 미리 만들었다\n${s}`),
    // AI 도구로 만든 에셋은 저작권 항목에도 함께 걸리는 게 맞다
    expect: { 'unfair:유명인 목소리·얼굴 무단 사용': 'ask', 'copyright:AI로 만든 에셋의 권리': 'ask' },
  },
  {
    name: 'Supabase 테이블에 RLS 가 없으면 위험 높음',
    base: 'good-app',
    apply: (d) => edit(d, 'supabase/migrations/0001_init.sql', () => 'create table public.notes (id uuid primary key, user_id uuid, body text);\n'),
    expect: { '보안:Supabase 테이블 보안(RLS)': 'hi' },
  },
  {
    name: 'RLS 는 켰지만 누구나 고칠 수 있는 정책이면 주의',
    base: 'good-app',
    apply: (d) => edit(d, 'supabase/migrations/0001_init.sql', () => 'create table public.notes (id uuid primary key, user_id uuid, body text);\nalter table public.notes enable row level security;\ncreate policy "anyone edit" on public.notes for update using (true);\n'),
    expect: { '보안:Supabase 테이블 보안(RLS)': 'mid' },
  },
  {
    name: 'RLS 와 본인 데이터만 다루는 정책이면 잘한 점',
    base: 'good-app',
    apply: (d) => edit(d, 'supabase/migrations/0001_init.sql', () => '-- 메모 테이블\ncreate table if not exists public.notes (id uuid primary key, user_id uuid, body text);\nalter table public.notes enable row level security;\ncreate policy "own read" on public.notes for select using (auth.uid() = user_id);\ncreate policy "own write" on public.notes for update using (auth.uid() = user_id) with check (auth.uid() = user_id);\n'),
    expect: { '보안:Supabase 테이블 보안(RLS)': 'ok' },
  },
  {
    name: '사용자 값을 SQL 문자열에 이어 붙이면 SQL 주입 위험',
    base: 'good-app',
    apply: (d) => edit(d, 'src/app/api/draw/route.ts', (s) => s.replace('const { prompt } = await req.json();', 'const { prompt } = await req.json();\n  const rows = await db.query(`select * from notes where id = ${req.url}`);')),
    expect: { '보안:사용자 입력 주입': 'hi' },
  },
  {
    name: '사용자 값으로 시스템 명령을 실행하면 명령어 주입 위험',
    base: 'good-app',
    apply: (d) => edit(d, 'src/app/api/draw/route.ts', (s) => s.replace('const { prompt } = await req.json();', 'const { prompt } = await req.json();\n  execSync(`convert ${req.url} out.png`);')),
    expect: { '보안:사용자 입력 주입': 'hi' },
  },
  {
    name: '사용자가 준 주소로 서버가 요청하면 SSRF 주의',
    base: 'good-app',
    apply: (d) => edit(d, 'src/app/api/draw/route.ts', (s) => s.replace('const { prompt } = await req.json();', "const { prompt } = await req.json();\n  const page = await fetch(req.headers.get('x-target'));")),
    expect: { '보안:사용자 입력 주입': 'mid' },
  },
  {
    name: 'CORS 를 모든 사이트에 열면 주의',
    base: 'good-app',
    apply: (d) => edit(d, 'src/app/api/draw/route.ts', (s) => s.replace('return Response.json(img);', "return Response.json(img, { headers: { 'Access-Control-Allow-Origin': '*' } });")),
    expect: { '보안:CORS 전체 허용': 'mid' },
  },
];

// 의존성 취약점 (인터넷 필요). 오래전에 알려진 취약점은 DB 에서 사라지지 않으므로 결과가 안정적이다
const ONLINE = [
  {
    name: '취약점이 알려진 lodash 4.17.15 (다른 패키지 안에 포함) → 위험 높음',
    files: {
      'package.json': JSON.stringify({ name: 'deps-test', version: '1.0.0', dependencies: { 'legacy-utils': '1.0.0' } }),
      'package-lock.json': JSON.stringify({ name: 'deps-test', lockfileVersion: 3, packages: {
        '': { name: 'deps-test', version: '1.0.0' },
        'node_modules/legacy-utils': { version: '1.0.0' },
        'node_modules/legacy-utils/node_modules/lodash': { version: '4.17.15' },
      } }),
    },
    check: (item) => [
      item.s === 'hi' || `판정: 기대 hi → 실제 ${item.s} (${item.why})`,
      item.evidence.some((e) => e.code.includes('lodash@4.17.15 (legacy-utils 안에 포함)')) || '근거에 "lodash@4.17.15 (legacy-utils 안에 포함)" 이 없어요',
      item.fix.some((t) => t.includes('legacy-utils')) || '고칠 방법에 legacy-utils 를 올리라는 안내가 없어요',
    ],
  },
  {
    name: '잠금 파일 없이 package.json 만 있으면 확인 필요',
    files: { 'package.json': JSON.stringify({ name: 'deps-test', dependencies: { lodash: '^4.17.0' } }) },
    check: (item) => [item.s === 'ask' || `판정: 기대 ask → 실제 ${item.s}`],
  },
];

// ───────────────────────── 실행 ─────────────────────────

const expected = fs.existsSync(EXPECTED) ? JSON.parse(fs.readFileSync(EXPECTED, 'utf8')) : {};
const snapshotOut = { ...expected };
let pass = 0, fail = 0, skip = 0;
const log = (ok, name, detail = '') => { console.log(`${ok === null ? '·' : ok ? '✓' : '✗'} ${name}${detail ? `\n${detail}` : ''}`); ok === null ? skip++ : ok ? pass++ : fail++; };

console.log('[스냅숏]');
for (const t of SNAPSHOTS) {
  if (t.online && OFFLINE) { log(null, `${t.name} (건너뜀: --offline)`); continue; }
  let dir = null;
  try {
    let root;
    if (t.repo) { dir = tmp('repo'); await fetchRepo({ ...t.repo, dir }); root = dir; } else root = t.load();
    const got = verdicts(scan(root));
    if (UPDATE || !expected[t.name]) { snapshotOut[t.name] = got; log(true, `${t.name} (기대 결과 ${UPDATE ? '갱신' : '새로 저장'})`); continue; }
    const want = expected[t.name];
    const keys = [...new Set([...Object.keys(want), ...Object.keys(got)])];
    const diffs = keys.filter((k) => want[k] !== got[k]).map((k) => `    ${k}: 기대 ${want[k] ?? '(없음)'} → 실제 ${got[k] ?? '(없음)'}`);
    log(diffs.length === 0, t.name, diffs.join('\n'));
  } catch (e) {
    log(false, t.name, `    오류: ${e.message}`);
  } finally {
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  }
}

console.log('\n[변형]');
for (const m of MUTATIONS) {
  const dir = copyFixture(m.base);
  try {
    const before = verdicts(scan(dir));
    m.apply(dir);
    const after = verdicts(scan(dir));
    const wrong = Object.entries(m.expect).filter(([k, v]) => after[k] !== v).map(([k, v]) => `    ${k}: 기대 ${v} → 실제 ${after[k] ?? '(없음)'}`);
    // 노리지 않은 판정이 함께 바뀌면 규칙이 엉뚱한 근거에 반응한다는 뜻
    const side = Object.keys(after).filter((k) => !(k in m.expect) && before[k] !== after[k]).map((k) => `    (함께 바뀜) ${k}: ${before[k]} → ${after[k]}`);
    log(wrong.length === 0 && side.length === 0, m.name, [...wrong, ...side].join('\n'));
  } catch (e) {
    log(false, m.name, `    오류: ${e.message}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

console.log('\n[의존성 취약점]');
for (const t of ONLINE) {
  if (OFFLINE) { log(null, `${t.name} (건너뜀: --offline)`); continue; }
  const dir = tmp('deps');
  try {
    for (const [rel, body] of Object.entries(t.files)) fs.writeFileSync(path.join(dir, rel), body);
    const all = fs.readdirSync(dir, { recursive: true }).map((p) => String(p).replace(/\\/g, '/'));
    const problems = t.check(await checkDependencies(dir, all)).filter((x) => x !== true);
    log(problems.length === 0, t.name, problems.map((p) => `    ${p}`).join('\n'));
  } catch (e) {
    log(false, t.name, `    오류: ${e.message}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

if (UPDATE || JSON.stringify(snapshotOut) !== JSON.stringify(expected)) {
  if (UPDATE || Object.keys(snapshotOut).length > Object.keys(expected).length) fs.writeFileSync(EXPECTED, `${JSON.stringify(snapshotOut, null, 2)}\n`);
}
console.log(`\n통과 ${pass} · 실패 ${fail}${skip ? ` · 건너뜀 ${skip}` : ''}`);
process.exitCode = fail ? 1 : 0;
