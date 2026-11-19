/**
 * 기사 핵심 요약 — 외부 AI 없이, 본문에서 중요한 문장을 골라낸다 (추출 요약).
 *
 * 구조
 *   extractArticle(url, html)  기사 HTML → 본문 글자
 *   summarize({ title, text }) 본문 → { points, cves, action }
 *
 * 나중에 자체 LLM 으로 바꿀 때는 ENGINES 에 엔진 하나를 추가하고 SUMMARY_ENGINE 환경변수로 고르면 된다.
 * 엔진은 { title, text, lang } 을 받아 { points: string[], action: string|null } 을 돌려주면 된다.
 */

const ENT = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', middot: '·', hellip: '…', rsquo: '’', lsquo: '‘', rdquo: '”', ldquo: '“', ndash: '–', mdash: '—' };
const decode = (s) =>
  s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
    if (e[0] === '#') {
      const n = /^#x/i.test(e) ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isFinite(n) && n > 0 && n < 0x110000 ? String.fromCodePoint(n) : '';
    }
    return ENT[e.toLowerCase()] ?? m;
  });

// 사이트별 본문 위치. 못 찾으면 페이지 전체의 <p> 를 쓴다.
const BODY_MARKERS = [
  /id="article-view-content-div"/i, // 데일리시큐
  /class="articleBody"/i, // BleepingComputer
  /class="content_html"/i, // 보호나라
  /itemprop="articleBody"/i,
  /<article\b/i,
];
// 본문 끝에 붙는 관련 기사·구독 안내 같은 것
const NOISE = /신고해\s?주셨|제보해\s?주셨|무단\s?전재|재배포\s?금지|기자\s*[a-z0-9._%+-]+@|저작권자|Copyright|All rights reserved|subscribe|newsletter|Found this article|Follow us|Related Articles|sponsored|광고|구독/i;

export function extractArticle(html) {
  let scope = html.replace(/<(script|style|noscript|svg|nav|header|footer|aside|form|figure|figcaption)\b[\s\S]*?<\/\1>/gi, ' ');
  for (const re of BODY_MARKERS) {
    const m = scope.match(re);
    if (m) { scope = scope.slice(m.index, m.index + 80_000); break; }
  }
  const paras = [...scope.matchAll(/<(p|li|h2|h3)\b[^>]*>([\s\S]*?)<\/\1>/gi)]
    .map((m) => decode(m[2].replace(/<br\s*\/?>/gi, '\n').replace(/<[^>]+>/g, ' ')).replace(/[ \t ]+/g, ' ').trim())
    .filter((p) => p.length >= 20 && !NOISE.test(p));
  return paras.join('\n');
}

// GitHub 권고 설명(마크다운) → 글자
export function markdownToText(md) {
  return String(md ?? '')
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/`([^`]*)`/g, '$1')
    .replace(/!\[[^\]]*\]\([^)]*\)/g, ' ')
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    // 문단 안의 줄바꿈은 이어 붙인다 (목록·제목·빈 줄은 그대로)
    .replace(/\r/g, '')
    .replace(/^#+.*$/gm, '\n') // "### Impact" 같은 소제목은 지운다
    .replace(/([^\n])\n(?![\n\s]*([-*|>]|\d+\.))/g, '$1 ')
    .replace(/^\s*[-*]\s+/gm, '')
    .replace(/[*_>|]/g, ' ');
}

function sentences(text) {
  return text
    .split(/\n+/)
    .flatMap((line) => line.split(/(?<=[.!?。])\s+(?=[A-Z가-힣"'“‘(\[])|(?<=다\.)\s*|(?<=니다\.)\s*/))
    .map((s) => s.replace(/^[\s□■◦o•·\-–]+(?=\S)/, '').replace(/\s+/g, ' ').trim())
    // 참고 링크만 있는 줄([1] https://…)은 뺀다
    .filter((s) => s.replace(/\[\d+\]|https?:\/\/\S+/g, '').trim().length >= 25 && s.length <= 400 && !NOISE.test(s));
}

const STOP = new Set('the a an and or of to in on for with by is are was were be been this that these those it its as at from has have had which who will would can could may also more than into about after before their they them there been not but said says new'.split(' '));
// 한글은 두 글자씩(바이그램) 잘라 조사·어미가 달라도 같은 낱말로 잡히게 하고, 영어는 낱말 단위로 센다
function tokens(s) {
  const out = [];
  for (const w of s.toLowerCase().match(/[가-힣]+|[a-z0-9][a-z0-9._-]*/g) ?? []) {
    if (/^[가-힣]/.test(w)) { for (let i = 0; i < w.length - 1; i++) out.push(w.slice(i, i + 2)); }
    else if (w.length > 2 && !STOP.has(w)) out.push(w);
  }
  return out;
}

const KEY = /CVE-\d{4}-\d+|취약점|업데이트|패치|권고|유출|악성|공격|해킹|랜섬웨어|탈취|원격|인증|vulnerab|patch|update|exploit|attack|malicious|malware|breach|leak|remote code|bypass|credential|ransomware/i;
const ACTION = /업데이트\s?(권고|하|해야|필요|수행|적용)|패치\s?(적용|권고)|최신\s?버전|버전으로|조치|삭제|비활성화|교체|변경\s?권고|upgrade|update to|patched in|fixed in|apply|mitigat|workaround|disable|rotate|remove the/i;

const QUOTE = /밝혔다|말했다|전했다|강조했다|겠다["”']|^["“]|\bsaid\b|\bsays\b|\btold\b/;

function extractive({ title, text }) {
  const list = [...new Set(sentences(text))].slice(0, 120);
  if (!list.length) return { points: [], action: null };
  const tf = new Map();
  for (const s of list) for (const t of new Set(tokens(s))) tf.set(t, (tf.get(t) ?? 0) + 1);
  const titleT = new Set(tokens(title ?? ''));
  const scored = list.map((s, i) => {
    const ts = [...new Set(tokens(s))];
    const freq = ts.reduce((a, t) => a + (tf.get(t) > 1 ? Math.log(1 + tf.get(t)) : 0), 0) / Math.sqrt(ts.length + 1);
    const inTitle = ts.filter((t) => titleT.has(t)).length / (titleT.size || 1);
    const pos = i === 0 ? 1.2 : i < 3 ? 0.6 : i < 6 ? 0.25 : 0;
    return { s, i, score: freq + 2 * inTitle + pos + (KEY.test(s) ? 0.5 : 0) };
  });
  // 해야 할 일 — 조치를 말하는 첫 문장. 남의 말을 옮긴 문장("~하겠다"고 밝혔다)은 빼고 고른다
  const act = scored.find((x) => ACTION.test(x.s) && !QUOTE.test(x.s));
  const points = scored.filter((x) => x !== act).sort((a, b) => b.score - a.score).slice(0, 3).sort((a, b) => a.i - b.i).map((x) => x.s);
  return { points, action: act ? act.s : null };
}

const ENGINES = { extractive };
export const ENGINE = ENGINES[process.env.SUMMARY_ENGINE] ? process.env.SUMMARY_ENGINE : 'extractive';

export async function summarize({ title, text, lang }) {
  const body = String(text ?? '').slice(0, 60_000);
  const r = await ENGINES[ENGINE]({ title, text: body, lang });
  const cves = [...new Set(`${title} ${body}`.match(/CVE-\d{4}-\d{4,}/g) ?? [])].slice(0, 8);
  return { engine: ENGINE, points: r.points, action: r.action, cves };
}
