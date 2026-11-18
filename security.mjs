/**
 * 보안 점검 (AI 서비스 중심, OWASP Top 10 for LLM Applications 를 참고)
 *
 * 판정: hi 위험 높음 · mid 주의 · ok 잘한 점 · lo 문제 없음 · ask 확인 필요
 * 비밀키는 절대 그대로 내보내지 않는다. 앞 6자리와 길이만 보여 준다.
 */
import fs from 'node:fs';
import path from 'node:path';

const SECRET_PATTERNS = [
  ['Anthropic API 키', /(?<![\w-])sk-ant-[A-Za-z0-9_-]{30,}/g],
  ['OpenAI API 키', /(?<![\w-])sk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{30,}/g],
  ['Google API 키', /(?<![\w-])AIza[0-9A-Za-z_-]{35}/g],
  ['GitHub 토큰', /(?<![\w-])(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})/g],
  ['AWS 액세스 키', /(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])/g],
  ['Stripe 비밀 키', /(?<![\w-])sk_live_[0-9a-zA-Z]{24,}/g],
  ['Slack 토큰', /(?<![\w-])xox[abpors]-[0-9A-Za-z-]{10,}/g],
  ['개인 키', /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/g],
];
const JWT = /(?<![\w-])eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
/** 설명용으로 적어 둔 가짜 값 (sk-xxxx…, your-key 등) */
const looksFake = (v) => /x{6,}|\*{4,}|\.{3}|your|example|dummy|placeholder|<|>/i.test(v) || /(.)\1{7,}/.test(v);
const mask = (v) => `${v.slice(0, 6)}…(${v.length}자)`;

/** 비밀키를 찾아볼 설정·문서 파일 */
const TEXT_CONFIG = /\.(json|ya?ml|toml|ini|cfg|conf|properties|txt|md|sh|ps1)$|(^|\/)\.env(\.[\w.-]+)?$/i;
const LOCKFILE = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?)$/;
export const isEnvFile = (rel) => /(^|\/)\.env(\.[\w.-]+)?$/i.test(rel);
const isExampleEnv = (rel) => /\.(example|sample|template|dist|defaults?)$/i.test(rel);
export const needsSecurityContent = (rel) => TEXT_CONFIG.test(rel) && !LOCKFILE.test(rel);

const PUBLIC_AI_KEY = /\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|PUBLIC)_[A-Z0-9_]*(?:OPENAI|ANTHROPIC|CLAUDE|GEMINI|GOOGLE_AI|GROQ|MISTRAL|COHERE|REPLICATE|ELEVENLABS|HUGGINGFACE|HF|LLM|AI)[A-Z0-9_]*(?:KEY|TOKEN|SECRET)\b/;
const BROWSER_SDK = /dangerouslyAllowBrowser\s*:\s*true/;
const SYSTEM_SLOT = /role\s*:\s*['"`]system['"`]|\bsystem\s*:/;
const USER_DATA = /\b(?:body|req|request|input|params|query|searchParams|formData|userInput|prompt)\b/;
const RATE_LIMIT = /\b(?:rate[-_ ]?limit(?:er|ing)?|ratelimit|limiter|throttle\w*|tooMany\w*)\b|status\s*:\s*429/i;
const AUTH = /\b(?:getUser|getSession|getServerSession|currentUser|verifyToken|supabase\.auth|clerk|authorization)\b|jwt\.verify|\bauth\(\)/i;
const INPUT_LIMIT = /\.slice\(\s*-?\d|max_tokens|maxTokens|MAX_[A-Z_]*(?:LEN|LENGTH|CHARS|TURNS|TOKENS)\b/;
const RAW_HTML = /dangerouslySetInnerHTML|\.innerHTML\s*=|\bv-html\b|\{@html\b/;
const DYNAMIC_CODE = /\beval\s*\(|new\s+Function\s*\(/;

const lineOf = (text, idx) => text.slice(0, idx).split('\n').length;
const lineText = (raw, n) => (raw.split('\n')[n - 1] ?? '').trim().slice(0, 160);

function findLines(file, re) {
  const out = [];
  file.code.split('\n').forEach((l, i) => { if (re.test(l)) out.push({ file: file.rel, line: i + 1, code: lineText(file.raw, i + 1) }); });
  return out;
}

export function judgeSecurity({ root, all, src, appSrc, byRel, importsOf, sites }) {
  const S = [];
  const item = (id, owasp, title, s, why, fix = [], evidence = []) => S.push({ id, owasp, title, s, why, fix, evidence: evidence.filter(Boolean).slice(0, 6) });
  const live = sites.filter((s) => !s.dev);
  const serverSites = live.filter((s) => s.endpoint);
  const exposed = live.filter((s) => s.exposed);

  // 1) 비밀키 노출
  const texts = src.map((f) => ({ rel: f.rel, raw: f.raw }));
  for (const rel of all) {
    if (!needsSecurityContent(rel) || byRel.has(rel)) continue;
    const full = path.join(root, rel);
    try { if (fs.statSync(full).size <= 1_000_000) texts.push({ rel, raw: fs.readFileSync(full, 'utf8') }); } catch { /* 읽을 수 없는 파일은 건너뛴다 */ }
  }
  const leaks = [];
  for (const t of texts) {
    for (const [kind, re] of SECRET_PATTERNS) {
      for (const m of t.raw.matchAll(new RegExp(re.source, 'g'))) {
        if (kind !== '개인 키' && looksFake(m[0])) continue;
        const ln = lineOf(t.raw, m.index);
        leaks.push({ kind, example: isExampleEnv(t.rel), file: t.rel, line: ln, code: lineText(t.raw, ln).replaceAll(m[0], kind === '개인 키' ? m[0] : mask(m[0])) });
      }
    }
    for (const m of t.raw.matchAll(JWT)) {
      try {
        const payload = JSON.parse(Buffer.from(m[0].split('.')[1], 'base64url').toString('utf8'));
        if (payload.role !== 'service_role') continue; // anon 키는 공개해도 되는 키다
        const ln = lineOf(t.raw, m.index);
        leaks.push({ kind: 'Supabase 관리자 키(service_role)', example: isExampleEnv(t.rel), file: t.rel, line: ln, code: lineText(t.raw, ln).replaceAll(m[0], mask(m[0])) });
      } catch { /* JWT 가 아니면 무시 */ }
    }
  }
  const envFiles = all.filter((r) => isEnvFile(r) && !isExampleEnv(r));
  const realLeaks = leaks.filter((l) => !l.example);
  if (realLeaks.length) item('secrets', 'LLM02', '비밀키 노출', 'hi', `저장소에 실제 비밀키로 보이는 값이 ${realLeaks.length}개 있어요 (${[...new Set(realLeaks.map((l) => l.kind))].join(', ')}). 공개 저장소라면 이미 누구나 볼 수 있어요.`,
    ['해당 키를 발급한 곳에서 바로 폐기하고 새로 발급하기', '키는 코드 대신 환경변수(Vercel 환경변수 등)에 넣기', 'Git 기록에도 남아 있으니 기록 정리 도구로 지우기'], realLeaks);
  else if (envFiles.length || leaks.length) item('secrets', 'LLM02', '비밀키 노출', 'mid', envFiles.length ? '환경변수 파일이 저장소에 올라가 있어요. 지금은 키 형식의 값을 못 찾았지만, 비밀 값이 들어갈 위험이 커요.' : '예시 파일에 실제 키처럼 보이는 값이 있어요. 진짜 키라면 폐기해야 해요.',
    ['.env 파일은 .gitignore 에 넣고 저장소에서 지우기', '예시 파일에는 가짜 값만 적기'], [...envFiles.map((f) => ({ file: f, line: 0, code: '(환경변수 파일)' })), ...leaks]);
  else item('secrets', 'LLM02', '비밀키 노출', 'lo', '코드와 설정 파일에서 비밀키로 보이는 값을 찾지 못했어요.');

  // 2) 브라우저로 새는 AI 키
  const publicKey = appSrc.flatMap((f) => findLines(f, PUBLIC_AI_KEY));
  for (const rel of envFiles) { try { const raw = fs.readFileSync(path.join(root, rel), 'utf8'); raw.split('\n').forEach((l, i) => { if (PUBLIC_AI_KEY.test(l)) publicKey.push({ file: rel, line: i + 1, code: l.split('=')[0].trim() + '=(값 숨김)' }); }); } catch { /* 무시 */ } }
  const browserSdk = appSrc.flatMap((f) => findLines(f, BROWSER_SDK));
  const clientSites = live.filter((s) => !s.endpoint && (/\.(tsx|jsx|vue|svelte|html)$/.test(s.file) || /['"]use client['"]/.test(byRel.get(s.file)?.code ?? '')));
  if (publicKey.length || browserSdk.length) item('client-key', 'LLM02', '브라우저로 새는 AI 키', 'hi', 'AI API 키가 브라우저에 그대로 전달되는 코드가 있어요. 방문자 누구나 개발자 도구로 키를 꺼내 쓸 수 있어요.',
    ['AI 호출은 서버(API 경로)에서만 하고, 키 이름에서 NEXT_PUBLIC_ 같은 공개 접두어 빼기'], [...publicKey, ...browserSdk]);
  else if (clientSites.length) item('client-key', 'LLM02', '브라우저로 새는 AI 키', 'mid', '화면 코드에서 AI SDK를 직접 불러요. 키가 브라우저에 실리지 않는지 확인이 필요해요.', ['AI 호출을 서버 API 경로로 옮기기'], clientSites.map((s) => ({ file: s.file, line: s.line, code: s.code })));
  else if (serverSites.length) item('client-key', 'LLM02', '브라우저로 새는 AI 키', 'ok', 'AI 호출을 서버에서만 하고 있어요. API 키가 브라우저로 나가지 않아요.', [], serverSites.map((s) => ({ file: s.file, line: s.line, code: s.code })));
  else item('client-key', 'LLM02', '브라우저로 새는 AI 키', 'lo', '실행 중에 AI를 부르는 코드가 없어요.');

  // 서버 쪽 AI 코드 (호출 파일 + 가져다 쓰는 파일)
  const serverFiles = [...new Set(serverSites.flatMap((s) => [s.file, ...importsOf(byRel.get(s.file))]))].map((r) => byRel.get(r)).filter(Boolean);

  // 3) 프롬프트 인젝션: 사용자가 보낸 값이 시스템 지시문에 섞이는지
  const injected = [];
  for (const f of serverFiles) {
    // 같은 줄에 시스템 자리와 사용자 값이 함께 있을 때만 센다 (윗줄·아랫줄까지 보면 옆 줄의 값에 잘못 걸린다)
    f.code.split('\n').forEach((l, i) => {
      if (SYSTEM_SLOT.test(l) && USER_DATA.test(l.replace(SYSTEM_SLOT, ''))) injected.push({ file: f.rel, line: i + 1, code: lineText(f.raw, i + 1) });
    });
  }
  if (injected.length) item('prompt-injection', 'LLM01', '프롬프트 인젝션', 'mid', '사용자(브라우저)가 보낸 값이 AI의 시스템 지시문에 들어가요. 이용자가 값을 조작해 AI에게 원래 규칙을 무시하라고 지시할 수 있어요.',
    ['시스템 지시문에는 서버가 직접 만든 값만 넣기', '브라우저가 보낸 값은 허용 목록·길이 제한으로 걸러서 넣기', 'AI 응답도 서버에서 한 번 더 검사하기'], injected);
  else if (serverSites.length) item('prompt-injection', 'LLM01', '프롬프트 인젝션', 'lo', '시스템 지시문에 사용자 값이 직접 들어가는 코드를 찾지 못했어요. 사용자 메시지 자체를 통한 인젝션은 정적 분석으로 막을 수 없어서 응답 검사가 필요해요.');
  else item('prompt-injection', 'LLM01', '프롬프트 인젝션', 'lo', '서버에서 AI를 부르는 코드가 없어요.');

  // 4) AI 응답을 HTML 로 그대로 넣기
  const uiFiles = [...new Set(exposed.flatMap((s) => s.ui))].map((r) => byRel.get(r)).filter(Boolean);
  const rawHtml = uiFiles.flatMap((f) => findLines(f, RAW_HTML));
  if (rawHtml.length) item('output-html', 'LLM05', 'AI 응답의 HTML 삽입', 'hi', 'AI 응답을 보여 주는 화면에서 HTML을 그대로 넣는 코드가 있어요. AI가 악성 스크립트를 내놓으면 방문자 브라우저에서 실행될 수 있어요(XSS).',
    ['AI 응답은 글자(text)로만 넣기', 'HTML이 꼭 필요하면 DOMPurify 같은 도구로 걸러서 넣기'], rawHtml);
  else if (uiFiles.length) item('output-html', 'LLM05', 'AI 응답의 HTML 삽입', 'ok', 'AI 응답을 보여 주는 화면이 HTML을 그대로 넣지 않아요.', [], uiFiles.map((f) => ({ file: f.rel, line: 0, code: '(AI 응답을 보여 주는 화면)' })));
  else item('output-html', 'LLM05', 'AI 응답의 HTML 삽입', 'lo', 'AI 응답을 보여 주는 화면을 찾지 못했어요.');

  // 5) AI 호출 횟수·비용 제한
  if (serverSites.length) {
    const limited = serverFiles.flatMap((f) => findLines(f, RATE_LIMIT));
    const authed = serverFiles.flatMap((f) => findLines(f, AUTH));
    const sized = serverFiles.flatMap((f) => findLines(f, INPUT_LIMIT));
    const extra = [authed.length ? '로그인 확인은 있어요' : '로그인 확인도 찾지 못했어요', sized.length ? '입력·응답 길이 제한은 있어요' : '입력·응답 길이 제한도 찾지 못했어요'].join(', ');
    if (limited.length) item('consumption', 'LLM10', 'AI 호출 횟수·비용 제한', 'ok', `AI를 부르는 서버에 요청 횟수 제한이 있어요. ${extra}.`, [], limited);
    else item('consumption', 'LLM10', 'AI 호출 횟수·비용 제한', 'mid', `AI를 부르는 서버(${serverSites.map((s) => s.endpoint).join(', ')})에서 요청 횟수 제한을 찾지 못했어요. 누군가 반복해서 부르면 AI 요금이 크게 나올 수 있어요. ${extra}.`,
      ['사용자·IP별로 1분당 요청 횟수 제한하기', 'AI 회사 대시보드에서 월 사용 한도 걸기', '화면 쪽 제한은 우회할 수 있으니 서버에서 제한하기'], [...serverSites.map((s) => ({ file: s.file, line: s.line, code: s.code })), ...sized.slice(0, 2)]);
  } else item('consumption', 'LLM10', 'AI 호출 횟수·비용 제한', 'lo', '서버에서 AI를 부르는 코드가 없어요.');

  // 6) 위험한 코드 실행
  const dyn = appSrc.flatMap((f) => findLines(f, DYNAMIC_CODE));
  if (dyn.length) item('dynamic-code', 'A03', '문자열을 코드로 실행', 'mid', 'eval이나 new Function으로 문자열을 코드로 실행하는 곳이 있어요. 그 문자열에 사용자 입력이나 AI 응답이 섞이면 원격 코드 실행으로 이어질 수 있어요.',
    ['문자열 실행 대신 JSON.parse나 미리 정한 함수 표 쓰기'], dyn);
  else item('dynamic-code', 'A03', '문자열을 코드로 실행', 'lo', 'eval이나 new Function을 쓰는 곳이 없어요.');

  return S;
}
