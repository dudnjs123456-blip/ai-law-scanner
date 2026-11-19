#!/usr/bin/env node
/**
 * AI 법령 코드 진단기 (MVP)
 *
 * 사용법:
 *   node scan.mjs <폴더 경로 | 깃 주소> [--json report.json] [--keep]
 *
 * 원칙
 *  - 코드는 읽기만 한다. 설치·빌드·실행을 절대 하지 않는다 (정적 분석).
 *  - 깃 주소를 받으면 임시 폴더에 내려받고, 진단이 끝나면 지운다 (--keep 이면 남긴다).
 *  - 심볼릭 링크는 따라가지 않는다 (저장소 밖 파일을 읽지 않기 위해).
 *  - 판정은 법률 자문이 아닌 실무 준비용 참고 자료다.
 *
 * 진단하는 법령: AI 기본법 · 개인정보보호법 · 성폭력처벌법/공직선거법(딥페이크)
 *               · 부정경쟁방지법(퍼블리시티권) · 저작권법 · 표시광고법 · EU AI Act
 */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { judgeSecurity, needsSecurityContent } from './security.mjs';
import { checkDependencies } from './deps.mjs';

// ───────────────────────── 설정 ─────────────────────────

const SKIP_DIRS = new Set(['node_modules', '.git', '.next', 'dist', 'build', 'out', 'coverage', '.vercel', 'vendor', 'venv', '.venv', '__pycache__', '.turbo', '.cache']);
const SRC_EXT = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.vue', '.svelte', '.html']);
const MAX_BYTES = 1_000_000;

/** 내용을 읽어야 하는 파일인가 (나머지는 이름만 본다) */
export const needsContent = (rel) => SRC_EXT.has(path.extname(rel).toLowerCase()) || /(^|\/)(package\.json|package-lock\.json|requirements[^/]*\.txt|pyproject\.toml)$/.test(rel) || /\.sql$/i.test(rel) || needsSecurityContent(rel);

/** 생성형 AI SDK·API. 모두 해외 회사 서버로 데이터가 나간다 */
const SDKS = [
  { name: 'Anthropic Claude', npm: ['@anthropic-ai/sdk'], py: ['anthropic'], hosts: ['api.anthropic.com'], kind: 'text' },
  { name: 'OpenAI', npm: ['openai'], py: ['openai'], hosts: ['api.openai.com'], kind: 'text' },
  { name: 'Google Gemini', npm: ['@google/genai', '@google/generative-ai'], py: ['google.genai', 'google.generativeai'], hosts: ['generativelanguage.googleapis.com'], kind: 'text' },
  { name: 'Vercel AI SDK', npm: ['ai', '@ai-sdk/'], py: [], hosts: [], kind: 'text' },
  { name: 'LangChain', npm: ['langchain', '@langchain/'], py: ['langchain'], hosts: [], kind: 'text' },
  { name: 'Mistral', npm: ['@mistralai/mistralai'], py: ['mistralai'], hosts: ['api.mistral.ai'], kind: 'text' },
  { name: 'Cohere', npm: ['cohere-ai'], py: ['cohere'], hosts: ['api.cohere.'], kind: 'text' },
  { name: 'Groq', npm: ['groq-sdk'], py: ['groq'], hosts: ['api.groq.com'], kind: 'text' },
  { name: 'Replicate', npm: ['replicate'], py: ['replicate'], hosts: ['api.replicate.com'], kind: 'image' },
  { name: 'Stability AI', npm: [], py: ['stability_sdk'], hosts: ['api.stability.ai'], kind: 'image' },
  { name: 'fal.ai', npm: ['@fal-ai/client', '@fal-ai/serverless-client'], py: ['fal_client'], hosts: ['fal.run'], kind: 'image' },
  { name: 'Hugging Face', npm: ['@huggingface/inference'], py: ['huggingface_hub', 'transformers', 'diffusers'], hosts: ['api-inference.huggingface.co', 'router.huggingface.co'], kind: 'text' },
  { name: 'ElevenLabs', npm: ['elevenlabs', '@elevenlabs/elevenlabs-js'], py: ['elevenlabs'], hosts: ['api.elevenlabs.io'], kind: 'audio' },
];

const KIND_PATTERNS = [
  ['video', /generateVideo|videos\.(create|generate)|\bsora\b|\bveo-\d|runwayml/i],
  ['image', /images\.(generate|edit)|generateImage|text-to-image|txt2img|\bimagen\b|dall-?e|\bflux\b|stable-diffusion|sdxl/i],
  ['audio', /audio\.speech|text[-_]?to[-_]?speech|textToSpeech|generateSpeech|elevenlabs/i],
];
export const KIND_KO = { text: '글', image: '이미지', audio: '음성', video: '영상' };

const DISCLOSE = /AI\s?(?:가|로|이)?\s?(?:생성|만든|만들|작성|제작|답변|대답|대사)|인공지능\s?(?:이|으로)|AI[- ]generated|generated (?:by|with) AI|AI\s?(?:대화|캐릭터|NPC|챗봇|어시스턴트|상담)/i;
const WATERMARK = /\bc2pa\b|watermark|워터마크/i;
const HIDE_AI = /(?:\bAI\b|인공지능|언어\s?모델|챗봇)[^\n]{0,40}?(?:모른다|모름|밝히지|숨기|말하지\s?마|아니라고)|(?:never|don't|do not)\s+(?:reveal|mention|admit)[^\n]{0,40}?(?:\bAI\b|language model|assistant)/i;
const DEV_TOOLS = /\b(Firefly|Midjourney|DALL-?E|Stable Diffusion|ElevenLabs|Suno|Udio|Runway|Leonardo\.ai|Ideogram|Kling)\b/gi;
const VOICE_TOOLS = /elevenlabs|suno|udio/i;
const DEEPFAKE_HINT = /얼굴|인물|실사|초상|portrait|face ?swap|photoreal|voice ?clon|목소리 ?복제|voices\/add/i;
const REVIEW_HINT = /후기|리뷰|\breviews?\b|testimonial/i;
const LOGIN = /type=["']password["']|auth\.(?:signUp|signInWithPassword|signInWithOtp|signInWithOAuth)|createUserWithEmailAndPassword|next-auth|@clerk\/|@auth0\//;
const PRIVACY = /개인정보\s?처리\s?방침|privacy policy|개인정보\s?(?:수집|이용)\s?(?:동의|안내)/i;
const TEXT_INPUT = /<(?:input|textarea)\b/;
const HIGH_IMPACT = [
  ['채용·인사 평가', /채용|이력서|면접\s?평가|resume|candidate|hiring/i],
  ['대출·신용 심사', /대출\s?심사|신용\s?(?:평가|점수)|credit[-_ ]?scor|loan/i],
  ['보건의료', /진료|처방|진단|의료|diagnos|patient|medical/i],
  ['학생 평가', /학생\s?평가|성적|채점|grading/i],
  ['생체인식', /얼굴\s?인식|face[-_ ]?recogni|biometric|지문\s?(?:인식|등록|스캔)/i],
];

// ───────────────────────── 파일 읽기 ─────────────────────────

function walk(root) {
  const files = [];
  const stack = [''];
  while (stack.length) {
    const rel = stack.pop();
    let entries;
    try { entries = fs.readdirSync(path.join(root, rel), { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) stack.push(r); continue; }
      if (e.isFile()) files.push(r);
    }
  }
  return files.sort();
}

function stripComments(src, ext) {
  if (ext === '.py') return src.replace(/(^|[ \t])#[^\n]*/g, '$1');
  if (ext === '.html') return src.replace(/<!--[\s\S]*?-->/g, (m) => m.replace(/[^\n]/g, ' '));
  return src
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/(^|[^:\\'"`])\/\/[^\n]*/g, '$1');
}

const lineOf = (text, idx) => text.slice(0, idx).split('\n').length;
const lineText = (raw, n) => (raw.split('\n')[n - 1] ?? '').trim().slice(0, 160);
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const isDevPath = (p) => /(^|\/)(scripts?|tools?|bin|tests?|__tests__|spec|e2e|fixtures?)\//i.test(p) || /[.-](test|spec|sim)\.[a-z]+$/i.test(p);
const noExt = (p) => p.replace(/\.[^./]+$/, '');

function endpointOf(p) {
  let m = p.match(/(?:^|\/)app\/(.*?)\/?route\.[jt]sx?$/);
  if (m && m[1].includes('api')) return '/' + m[1].replace(/\([^)]*\)\//g, '').replace(/^.*?(api\/)/, '$1');
  m = p.match(/(?:^|\/)pages\/(api\/.+?)(?:\/index)?\.[jt]sx?$/);
  return m ? '/' + m[1] : null;
}

function firstHit(files, re) {
  for (const g of files) { const m = re.exec(g.code); if (m) { const ln = lineOf(g.code, m.index); return { file: g.rel, line: ln, code: lineText(g.raw, ln) }; } }
  return null;
}

// ───────────────────────── 증거 모으기 ─────────────────────────

export function scan(root) {
  const all = walk(root);
  const src = [];
  for (const rel of all) {
    const ext = path.extname(rel).toLowerCase();
    if (!SRC_EXT.has(ext)) continue;
    const full = path.join(root, rel);
    if (fs.statSync(full).size > MAX_BYTES) continue;
    const raw = fs.readFileSync(full, 'utf8');
    src.push({ rel, ext, raw, code: stripComments(raw, ext) });
  }
  const byRel = new Map(src.map((f) => [f.rel, f]));
  const appSrc = src.filter((f) => !isDevPath(f.rel));

  /** 파일이 가져다 쓰는 같은 저장소 안 파일들 */
  const importsOf = (g) => {
    const out = [];
    for (const m of g.code.matchAll(/(?:from\s+|import\(\s*|require\(\s*)['"]([^'"]+)['"]/g)) {
      const spec = m[1];
      if (!/^(\.|@\/|~\/)/.test(spec)) continue;
      const tail = spec.replace(/^(@|~)\//, '').replace(/^(\.\.?\/)+/, '');
      const hit = src.find((x) => noExt(x.rel).endsWith(tail) || noExt(x.rel).endsWith(`${tail}/index`));
      if (hit) out.push(hit.rel);
    }
    return out;
  };
  const importersOf = (rel) => {
    const r = new RegExp(`['"][^'"]*/${esc(path.basename(noExt(rel)))}['"]`);
    return appSrc.filter((g) => g.rel !== rel && r.test(g.code)).map((g) => g.rel);
  };

  // 실행 중 AI 호출
  const sites = [];
  for (const f of src) {
    for (const s of SDKS) {
      let idx = -1;
      for (const m of s.npm) {
        const spec = m.endsWith('/') ? `${esc(m)}[^'"]*` : `${esc(m)}(?:/[^'"]*)?`;
        const hit = new RegExp(`(?:from\\s+|require\\(\\s*|import\\(\\s*)['"]${spec}['"]`).exec(f.code);
        if (hit) { idx = hit.index; break; }
      }
      if (idx < 0 && f.ext === '.py') for (const m of s.py) { const hit = new RegExp(`^\\s*(?:from|import)\\s+${esc(m)}\\b`, 'm').exec(f.code); if (hit) { idx = hit.index; break; } }
      if (idx < 0) for (const h of s.hosts) { const i = f.code.indexOf(h); if (i >= 0) { idx = i; break; } }
      if (idx < 0) continue;
      const kind = (KIND_PATTERNS.find(([, r]) => r.test(f.code)) ?? [s.kind])[0];
      const line = lineOf(f.code, idx);
      sites.push({ file: f.rel, line, code: lineText(f.raw, line), sdk: s.name, kind, dev: isDevPath(f.rel), endpoint: endpointOf(f.rel) });
    }
  }

  const live = sites.filter((s) => !s.dev);
  const aiContext = new Set();
  for (const s of live) {
    aiContext.add(s.file);
    for (const i of importsOf(byRel.get(s.file))) aiContext.add(i);
    let callers = [];
    if (s.endpoint) {
      const r = new RegExp(`['"\`]${esc(s.endpoint)}(?:['"\`?/])`);
      callers = appSrc.filter((g) => g.rel !== s.file && r.test(g.code)).map((g) => g.rel);
    } else if (/\.(tsx|jsx|vue|svelte|html)$/.test(s.file)) callers = [s.file];
    const ui = new Set(callers);
    for (const c of callers) for (const i of importersOf(c)) ui.add(i);
    s.ui = [...ui].filter((u) => /\.(tsx|jsx|vue|svelte|html)$/.test(u));
    s.exposed = callers.length > 0;
    s.disclosure = [];
    for (const u of s.ui) {
      const g = byRel.get(u);
      const m = DISCLOSE.exec(g.code) || (s.kind !== 'text' && WATERMARK.exec(g.code));
      if (m) { const ln = lineOf(g.code, m.index); s.disclosure.push({ file: u, line: ln, code: lineText(g.raw, ln) }); }
    }
    s.userInput = s.ui.map((u) => firstHit([byRel.get(u)], TEXT_INPUT)).find(Boolean) ?? null;
    const near = [...s.ui, s.file].map((u) => byRel.get(u).code).join('\n');
    s.deepfakeHint = s.kind !== 'text' && DEEPFAKE_HINT.test(near);
  }
  const ctxFiles = [...aiContext].map((r) => byRel.get(r));

  const globalDisclosure = firstHit(appSrc.filter((x) => /(layout|page|terms|privacy|about|intro|title)[^/]*\.(tsx|jsx|vue|svelte|html)$/i.test(x.rel)), DISCLOSE);
  const hiding = [];
  for (const g of appSrc) for (const m of g.code.matchAll(new RegExp(HIDE_AI.source, 'gi'))) { const ln = lineOf(g.code, m.index); hiding.push({ file: g.rel, line: ln, code: lineText(g.raw, ln) }); }

  const devAssets = {};
  const add = (tool, ev) => { const k = tool.toLowerCase().replace('-', ''); (devAssets[k] ??= { tool, count: 0, evidence: [] }); devAssets[k].count++; if (devAssets[k].evidence.length < 3) devAssets[k].evidence.push(ev); };
  // 개발 메모(주석)에 적힌 도구 이름만 센다. 화면 글자나 코드 속 문자열은 그 도구를 "소개"하는 글일 수 있어서 뺀다
  // (예: 포트폴리오 소개글의 "ElevenLabs로 만든 목소리"는 이 저장소가 AI 음성을 쓴다는 뜻이 아니다)
  for (const g of src) {
    const seen = new Set();
    const codeLines = g.code.split('\n');
    for (const m of g.raw.matchAll(new RegExp(DEV_TOOLS.source, 'gi'))) {
      const ln = lineOf(g.raw, m.index);
      const key = m[1].toLowerCase() + ln;
      if (seen.has(key)) continue;
      seen.add(key);
      if ((codeLines[ln - 1] ?? '').toLowerCase().includes(m[1].toLowerCase())) continue; // 주석을 지워도 남아 있으면 코드·화면 글자다
      add(m[1], { file: g.rel, line: ln, code: lineText(g.raw, ln) });
    }
  }
  for (const rel of all) { const m = path.basename(rel).match(new RegExp(DEV_TOOLS.source, 'i')); if (m) add(m[1], { file: rel, line: 0, code: '(파일 이름)' }); }

  const highImpact = [];
  for (const [area, r] of HIGH_IMPACT) { const h = firstHit(ctxFiles, r); if (h) highImpact.push({ area, ...h }); }

  const ev = {
    files: all.length, sourceFiles: src.length, sites, globalDisclosure, hiding, devAssets: Object.values(devAssets), highImpact,
    login: firstHit(appSrc, LOGIN),
    privacy: firstHit(appSrc, PRIVACY) ?? (all.some((f) => /(^|\/)privacy|처리방침/i.test(f)) ? { file: all.find((f) => /(^|\/)privacy|처리방침/i.test(f)), line: 0, code: '(파일)' } : null),
    reviewGen: firstHit(ctxFiles, REVIEW_HINT),
  };
  ev.findings = judge(ev);
  ev.security = judgeSecurity({ root, all, src, appSrc, byRel, importsOf, sites });
  return ev;
}

/** scan() + 인터넷이 필요한 점검(의존성 취약점). 서버와 CLI 가 쓴다 */
export async function scanFull(root) {
  const ev = scan(root);
  ev.security.push(await checkDependencies(root, walk(root)));
  return ev;
}

// ───────────────────────── 법령별 판정 ─────────────────────────
// s: hi 위반 가능성 높음 · mid 검토 필요 · ask 확인 필요(코드로 알 수 없음) · ok 조치 확인됨 · lo 해당 가능성 낮음

function judge(ev) {
  const live = ev.sites.filter((s) => !s.dev);
  const exposed = live.filter((s) => s.exposed);
  const missing = exposed.filter((s) => !s.disclosure.length);
  const media = live.filter((s) => s.kind !== 'text');
  const withInput = exposed.filter((s) => s.userInput);
  const voiceDev = ev.devAssets.filter((a) => VOICE_TOOLS.test(a.tool));
  const at = (s) => ({ file: s.file, line: s.line, code: s.code });
  const F = [];
  const f = (law, article, title, s, why, fix = [], evidence = []) => F.push({ law: law.id, article, title, s, why, fix, evidence: evidence.filter(Boolean) });

  // AI 기본법
  const L = LAWS[0];
  if (!live.length) f(L, '제31조 제1항', 'AI 이용 사실 사전 고지', 'lo', '서비스 실행 중에 생성형 AI를 부르는 코드가 없어요.');
  else if (!exposed.length) f(L, '제31조 제1항', 'AI 이용 사실 사전 고지', 'mid', `생성형 AI 호출 ${live.length}곳이 이용자 화면에 닿는지 코드로 추적하지 못했어요.`, [], live.map(at));
  else if (missing.length && !ev.globalDisclosure) f(L, '제31조 제1항', 'AI 이용 사실 사전 고지', 'hi', `생성형 AI 결과가 이용자 화면으로 나가는데, 화면 어디에서도 AI 안내 문구를 찾지 못했어요.`,
    ['AI 기능을 처음 쓰기 전에 "AI가 만든 콘텐츠"라는 안내를 띄우기', '이용약관이나 서비스 소개에 AI 사용 사실 적기'], exposed.map(at));
  else f(L, '제31조 제1항', 'AI 이용 사실 사전 고지', 'ok', '이용자 화면에서 AI 안내 문구를 찾았어요. 첫 이용 전에 보이는지 확인하세요.', [], [ev.globalDisclosure, ...exposed.flatMap((s) => s.disclosure)]);

  if (!live.length) f(L, '제31조 제2항', '생성형 AI 결과물 표시', 'lo', '실행 중에 결과물을 생성하는 AI가 없어요.');
  else if (missing.length) f(L, '제31조 제2항', '생성형 AI 결과물 표시', 'hi', `AI 결과물이 보이는 화면에 "AI가 만들었다"는 표시가 없어요.`,
    ['결과물 옆에 "AI 생성" 표시 넣기', '이미지·음성이면 워터마크와 안내창을 함께 쓰기'], missing.flatMap((s) => s.ui.map((u) => ({ file: u, line: 0, code: `${s.endpoint ?? s.file} 결과를 보여주는 화면` }))));
  else if (exposed.length) f(L, '제31조 제2항', '생성형 AI 결과물 표시', 'ok', '결과물이 보이는 화면에서 표시를 찾았어요.', [], exposed.flatMap((s) => s.disclosure));
  else f(L, '제31조 제2항', '생성형 AI 결과물 표시', 'mid', '결과물이 어느 화면에 보이는지 확인이 필요해요.', [], live.map(at));

  if (!media.length) f(L, '제31조 제3항', '딥페이크 결과물 명확 표시', 'lo', live.length ? '실행 중 AI가 글만 만들어요. 실제 사진·목소리·영상과 헷갈릴 결과물이 없어요.' : '실행 중 생성형 AI가 없어요.');
  else f(L, '제31조 제3항', '딥페이크 결과물 명확 표시', media.some((s) => s.deepfakeHint) ? 'hi' : 'mid', '이미지·음성·영상을 만들어요. 실제와 헷갈릴 수 있으면 눈에 보이게 표시해야 해요.', ['결과물에 이용자가 바로 알아볼 수 있는 표시 넣기'], media.map(at));

  if (!live.length || !ev.highImpact.length) f(L, '제33조 ~ 제35조', '고영향 AI 사업자 책무', 'lo', live.length ? 'AI가 쓰이는 코드에서 의료·채용·대출 같은 고영향 영역 단서를 찾지 못했어요.' : '실행 중 AI가 없어요.');
  else f(L, '제33조 ~ 제35조', '고영향 AI 사업자 책무', 'mid', `AI가 쓰이는 코드에 고영향 영역 단서(${ev.highImpact.map((h) => h.area).join(', ')})가 있어요.`, ['고영향 해당 여부와 판단 근거를 문서로 남기기', '위험관리·이용자 보호 방안 세우기'], ev.highImpact);

  f(L, '제36조', '국내대리인 지정', 'ask', '코드로는 알 수 없어요. 해외 회사이면서 시행령 규모 기준을 넘을 때만 해당해요.');

  // 개인정보보호법
  const P = LAWS[1];
  if (ev.login && !ev.privacy) f(P, '제30조', '개인정보 처리방침 공개', 'hi', '회원가입·로그인으로 개인정보를 받는데 개인정보 처리방침을 찾지 못했어요.',
    ['개인정보 처리방침 페이지를 만들고 첫 화면·가입 화면에 링크 걸기', '수집 항목, 목적, 보관 기간, 파기 방법 적기'], [ev.login]);
  else if (ev.login) f(P, '제30조', '개인정보 처리방침 공개', 'ok', '로그인 기능과 개인정보 처리방침을 모두 찾았어요.', [], [ev.privacy]);
  else f(P, '제30조', '개인정보 처리방침 공개', 'lo', '코드에서 회원가입·로그인 기능을 찾지 못했어요.');

  if (withInput.length) f(P, '제28조의8', '개인정보 국외 이전 고지', ev.privacy ? 'mid' : 'hi', `이용자가 직접 입력한 글이 해외 AI 회사(${[...new Set(withInput.map((s) => s.sdk))].join(', ')}) 서버로 전송돼요. 이름이나 연락처 같은 개인정보가 섞일 수 있어요.`,
    ['처리방침에 국외 이전 항목(받는 회사, 나라, 항목, 목적) 적기', '입력창에 "개인정보를 입력하지 마세요" 안내 넣기'], withInput.flatMap((s) => [at(s), s.userInput]));
  else f(P, '제28조의8', '개인정보 국외 이전 고지', live.length ? 'ask' : 'lo', live.length ? '해외 AI로 보내는 데이터에 개인정보가 있는지 확인이 필요해요.' : '해외 AI로 데이터를 보내는 코드가 없어요.');

  if (ev.highImpact.length && live.length) f(P, '제37조의2', '자동화된 결정 거부·설명 요구권', 'mid', 'AI가 개인에게 중대한 영향을 주는 결정을 자동으로 한다면 거부·설명 요구에 응할 절차가 필요해요.', ['사람이 다시 검토하는 절차와 설명 창구 만들기'], ev.highImpact);
  else f(P, '제37조의2', '자동화된 결정 거부·설명 요구권', 'lo', 'AI가 개인의 권리에 영향을 주는 결정을 자동으로 내리는 단서가 없어요.');

  // 딥페이크 처벌법
  const D = LAWS[2];
  if (media.some((s) => s.deepfakeHint)) f(D, '성폭력처벌법 제14조의2 · 공직선거법 제82조의8', '딥페이크 악용 방지', 'hi', '실존 인물의 얼굴이나 목소리를 합성할 수 있는 기능이 있어요. 악용되면 서비스도 책임 논란에 휘말릴 수 있어요.', ['실존 인물 합성 금지 정책과 신고 기능 만들기', '선거 기간 후보자 합성 차단'], media.map(at));
  else f(D, '성폭력처벌법 제14조의2 · 공직선거법 제82조의8', '딥페이크 악용 방지', 'lo', '실존 인물을 합성하는 기능을 찾지 못했어요.');

  // 아청법
  const K = LAWS.find((l) => l.id === 'child');
  const visual = media.filter((s) => s.kind === 'image' || s.kind === 'video');
  if (visual.length) f(K, '제11조', 'AI 아동·청소년 성착취물 차단', 'mid', '이미지·영상을 생성하는 기능이 있어요. AI로 만든 가상 인물도 아동·청소년으로 인식되는 성적 표현물이면 처벌 대상이에요.', ['프롬프트와 결과물을 걸러내는 안전 필터 켜기', '신고 기능과 처리 절차 만들기'], visual.map(at));
  else f(K, '제11조', 'AI 아동·청소년 성착취물 차단', 'lo', '이미지·영상을 생성하는 기능이 없어요.');

  // 부정경쟁방지법
  const U = LAWS.find((l) => l.id === 'unfair');
  if (voiceDev.length || media.some((s) => s.kind === 'audio')) f(U, '제2조 제1호 타목', '유명인 목소리·얼굴 무단 사용', 'ask', 'AI 음성을 쓰고 있어요. 그 목소리가 실존 인물을 복제한 것이라면 본인 동의가 필요해요.', ['목소리 출처(기본 제공 음성인지, 복제 음성인지) 기록해 두기', '복제 음성이면 본인 동의서 받기'], voiceDev.flatMap((a) => a.evidence.slice(0, 1)));
  else f(U, '제2조 제1호 타목', '유명인 목소리·얼굴 무단 사용', 'lo', 'AI 음성이나 인물 합성 흔적이 없어요.');

  // 저작권법
  const C = LAWS.find((l) => l.id === 'copyright');
  if (ev.devAssets.length) f(C, '문체부 생성형 AI 저작권 안내서', 'AI로 만든 에셋의 권리', 'ask', `AI 도구(${ev.devAssets.map((a) => a.tool).join(', ')})로 만든 에셋이 있어요. 위반은 아니지만, AI가 혼자 만든 부분은 저작권 보호를 받기 어려워요.`, ['프롬프트와 수정 과정을 기록해 사람의 기여 남기기', '각 AI 도구의 상업적 이용 약관 확인하기'], ev.devAssets.flatMap((a) => a.evidence.slice(0, 1)));
  else f(C, '문체부 생성형 AI 저작권 안내서', 'AI로 만든 에셋의 권리', 'lo', 'AI 도구로 만든 에셋 흔적이 없어요.');

  // 표시광고법
  const A = LAWS.find((l) => l.id === 'ads');
  if (ev.reviewGen && live.length) f(A, '추천·보증 심사지침', 'AI 생성 후기·리뷰', 'mid', 'AI가 쓰이는 코드에 후기·리뷰 관련 내용이 있어요. AI로 만든 후기를 실제 후기처럼 보이게 하면 안 돼요.', ['AI가 쓴 후기는 실제 이용 후기와 구분해 표시하기'], [ev.reviewGen]);
  else f(A, '추천·보증 심사지침', 'AI 생성 후기·리뷰', 'lo', 'AI로 후기나 리뷰를 만드는 코드가 없어요.');

  // EU AI Act
  const E = LAWS.find((l) => l.id === 'eu');
  if (!live.length) f(E, 'Article 50', '챗봇·생성물 투명성 (EU 이용자 대상)', 'lo', '실행 중 생성형 AI가 없어요.');
  else if (missing.length) f(E, 'Article 50', '챗봇·생성물 투명성 (EU 이용자 대상)', 'ask', 'EU 이용자에게 서비스한다면 2026년 8월 2일부터 AI와 대화 중이라는 사실을 알려야 해요. 지금은 표시가 없어요.', ['한국 기준으로 표시를 넣으면 EU 기준도 대부분 함께 충족돼요'], exposed.map(at));
  else f(E, 'Article 50', '챗봇·생성물 투명성 (EU 이용자 대상)', 'ok', 'AI 표시를 찾았어요. EU 기준으로도 확인하세요.');

  return F;
}

/** 페이지의 법령 모음과 같은 순서·이름 */
export const LAWS = [
  { id: 'ai-basic', name: 'AI 기본법' },
  { id: 'privacy', name: '개인정보보호법' },
  { id: 'deepfake', name: '딥페이크 처벌법' },
  { id: 'child', name: '아청법' },
  { id: 'unfair', name: '부정경쟁방지법' },
  { id: 'copyright', name: '저작권법' },
  { id: 'ads', name: '표시광고법' },
  { id: 'eu', name: 'EU AI Act' },
];

// ───────────────────────── 깃 주소 처리 ─────────────────────────

function cloneRepo(url) {
  if (!/^(https:\/\/|git@)[\w.@:/~-]+$/.test(url)) throw new Error('지원하지 않는 주소 형식이에요. https:// 또는 git@ 주소를 넣어주세요.');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-law-scan-'));
  execFileSync('git', ['-c', `core.hooksPath=${path.join(dir, '.no-hooks')}`, '-c', 'protocol.file.allow=never', 'clone', '--depth', '1', '--no-recurse-submodules', '--quiet', url, path.join(dir, 'repo')],
    { stdio: ['ignore', 'ignore', 'pipe'], env: { ...process.env, GIT_TERMINAL_PROMPT: '0' } });
  return { dir, root: path.join(dir, 'repo') };
}
const commitOf = (root) => { try { return execFileSync('git', ['-C', root, 'log', '-1', '--format=%h|%s|%cs'], { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim().split('|'); } catch { return null; } };

// ───────────────────────── 출력 ─────────────────────────

const LABEL = { hi: '위반 가능성 높음', mid: '검토 필요', ask: '확인 필요', ok: '조치 확인됨', lo: '해당 가능성 낮음' };
const ICON = { hi: '🔴', mid: '🟡', ask: '❔', ok: '🟢', lo: '⚪' };

function printText(r) {
  const out = [`\nAI 법령 코드 진단 — ${r.meta.repo}`, r.meta.commit ? `커밋: ${r.meta.commit} (${r.meta.commitDate})` : '', `파일 ${r.files}개 (소스 ${r.sourceFiles}개) 읽음 · 실행한 코드 없음`];
  for (const law of LAWS) {
    const items = r.findings.filter((x) => x.law === law.id);
    out.push(`\n[${law.name}]`);
    for (const x of items) {
      out.push(`${ICON[x.s]} ${x.title} (${x.article}) — ${LABEL[x.s]}`, `   ${x.why}`);
      for (const e of x.evidence.slice(0, 3)) out.push(`   · ${e.file}${e.line ? ':' + e.line : ''}`);
    }
  }
  const SEC = { hi: '위험 높음', mid: '주의', ok: '잘한 점', lo: '문제 없음', ask: '확인 필요' };
  const SEC_ICON = { hi: '🔴', mid: '🟡', ok: '🟢', lo: '⚪', ask: '❔' };
  out.push('\n[보안 점검]');
  for (const x of r.security ?? []) {
    out.push(`${SEC_ICON[x.s]} ${x.title} (${x.owasp}) — ${SEC[x.s]}`, `   ${x.why}`);
    for (const e of x.evidence.slice(0, 3)) out.push(`   · ${e.file}${e.line ? ':' + e.line : ''}`);
  }
  out.push('\n※ 법률 자문이 아닌 참고용 진단입니다.\n');
  console.log(out.filter((x) => x !== '').join('\n'));
}

// ───────────────────────── 실행 ─────────────────────────

if (process.argv[1]?.replace(/\\/g, '/').endsWith('scan.mjs')) {
  const args = process.argv.slice(2);
  const take = (n) => { const i = args.indexOf(n); return i >= 0 ? args.splice(i, 2)[1] : null; };
  const keep = args.includes('--keep') && args.splice(args.indexOf('--keep'), 1);
  const jsonOut = take('--json');
  const target = args[0];
  if (!target) { console.error('사용법: node scan.mjs <폴더 | 깃 주소> [--json 파일] [--keep]'); process.exit(2); }

  let root = target, tmp = null;
  try {
    if (/^(https:\/\/|git@)/.test(target)) { console.error('저장소를 내려받는 중… (코드는 실행하지 않아요)'); ({ dir: tmp, root } = cloneRepo(target)); }
    if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) throw new Error(`폴더를 찾을 수 없어요: ${root}`);
    const ev = await scanFull(root);
    const c = commitOf(root);
    const r = { meta: { repo: target.replace(/\.git$/, ''), commit: c?.[0] ?? null, commitMsg: c?.[1] ?? null, commitDate: c?.[2] ?? null, scannedAt: new Date().toISOString().slice(0, 10), scanner: '0.2' }, ...ev };
    printText(r);
    if (jsonOut) fs.writeFileSync(jsonOut, JSON.stringify(r, null, 2));
  } catch (e) {
    console.error('진단 실패:', e.message); process.exitCode = 1;
  } finally {
    if (tmp && !keep) fs.rmSync(tmp, { recursive: true, force: true });
    else if (tmp) console.error(`내려받은 코드: ${root}`);
  }
}
