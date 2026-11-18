/**
 * POST /api/scan  { url: "https://github.com/회사/저장소" }
 *
 * GitHub 공개 저장소를 압축 파일로 받아 임시 폴더에 풀고, scan.mjs 로 진단한 뒤 바로 지운다.
 * - 받은 코드는 실행하지 않는다 (읽기만 한다)
 * - 파일과 폴더만 풀고, 심볼릭 링크 같은 특수 항목은 건너뛴다
 * - 저장소 크기, 내려받는 양, 파일 수, 요청 횟수를 제한한다
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { x as untar } from 'tar';
import { scan, needsContent } from '../../../scan.mjs';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 60;

// 소스 코드만 풀고 이미지·음성 같은 큰 파일은 이름만 남기므로, 저장소 자체는 커도 괜찮다
const MAX_REPO_KB = 500_000; // GitHub 가 알려주는 저장소 크기 (커밋 기록 포함, 약 500MB)
const MAX_DOWNLOAD = 300 * 1024 * 1024; // 내려받는 압축 파일 크기
const MAX_FILES = 20_000;
const PER_MINUTE = 5; // 한 사람(IP)당 1분에 진단 5번

const recent = new Map();
function tooMany(ip) {
  const now = Date.now();
  const list = (recent.get(ip) ?? []).filter((t) => now - t < 60_000);
  list.push(now);
  recent.set(ip, list);
  return list.length > PER_MINUTE;
}

function parseRepo(input) {
  const m = String(input ?? '').trim().match(/^(?:https:\/\/(?:www\.)?github\.com\/|git@github\.com:)?([A-Za-z0-9-]+)\/([A-Za-z0-9._-]+?)(?:\.git)?\/?$/);
  return m ? { owner: m[1], repo: m[2] } : null;
}

const github = (p) =>
  fetch(`https://api.github.com${p}`, {
    headers: {
      'User-Agent': 'ai-law-scanner',
      Accept: 'application/vnd.github+json',
      ...(process.env.GITHUB_TOKEN ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}),
    },
  });

const fail = (status, error) => Response.json({ error }, { status });

export async function POST(req) {
  const ip = (req.headers.get('x-forwarded-for') ?? '').split(',')[0].trim() || 'local';
  if (tooMany(ip)) return fail(429, '요청이 너무 잦아요. 1분 뒤에 다시 시도해 주세요.');

  let body;
  try { body = await req.json(); } catch { return fail(400, '요청 형식이 올바르지 않아요.'); }
  const t = parseRepo(body?.url);
  if (!t) return fail(400, 'GitHub 저장소 주소를 넣어주세요. 예: https://github.com/회사/저장소');

  // 1) 저장소 정보 (크기, 기본 브랜치)
  const info = await github(`/repos/${t.owner}/${t.repo}`);
  if (info.status === 404) return fail(404, '저장소를 찾을 수 없어요. 주소를 확인해 주세요. 비공개 저장소는 아직 진단할 수 없어요.');
  if (info.status === 403 || info.status === 429) return fail(503, 'GitHub 요청 한도에 걸렸어요. 잠시 후 다시 시도해 주세요.');
  if (!info.ok) return fail(502, 'GitHub에서 저장소 정보를 받지 못했어요.');
  const repo = await info.json();
  if (repo.size > MAX_REPO_KB) return fail(413, `저장소가 너무 커요(약 ${Math.round(repo.size / 1024)}MB). 지금은 500MB 이하만 진단할 수 있어요.`);

  // 2) 최신 커밋
  const cr = await github(`/repos/${t.owner}/${t.repo}/commits/${encodeURIComponent(repo.default_branch)}`);
  if (!cr.ok) return fail(502, '최신 커밋 정보를 받지 못했어요.');
  const commit = await cr.json();

  // 3) 그 커밋의 코드를 받아 임시 폴더에 풀기
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-law-'));
  try {
    const dl = await fetch(`https://codeload.github.com/${t.owner}/${t.repo}/tar.gz/${commit.sha}`, { headers: { 'User-Agent': 'ai-law-scanner' } });
    if (!dl.ok || !dl.body) return fail(502, '코드를 내려받지 못했어요.');
    // 먼저 끝까지 받고(크기 제한을 넘으면 중단) 한 번에 푼다. 받으면서 푸는 것보다 빠르다
    const parts = [];
    let bytes = 0;
    for await (const chunk of dl.body) {
      bytes += chunk.length;
      if (bytes > MAX_DOWNLOAD) throw new Error('too_big');
      parts.push(chunk);
    }
    let files = 0;
    const nameOnly = []; // 내용 없이 이름만 남길 파일 (이미지·음성·3D 모델 등)
    await pipeline(
      Readable.from([Buffer.concat(parts)]),
      untar({
        cwd: dir,
        strip: 1,
        filter: (p, entry) => {
          if (entry.type === 'Directory') return true;
          if (entry.type !== 'File' || ++files > MAX_FILES) return false;
          const rel = p.split('/').slice(1).join('/'); // 맨 앞 폴더(저장소-커밋)를 뺀 경로
          if (needsContent(rel)) return true;
          nameOnly.push(rel);
          return false;
        },
      }),
    );
    // 이름만 남길 파일은 빈 파일로 만든다. 저장소 밖으로 나가는 경로는 무시한다
    for (const rel of nameOnly) {
      const target = path.resolve(dir, rel);
      if (!rel || !target.startsWith(dir + path.sep)) continue;
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, '');
    }

    // 4) 진단
    const result = scan(dir);
    return Response.json({
      meta: {
        repo: `https://github.com/${repo.full_name}`,
        commit: commit.sha.slice(0, 7),
        commitMsg: (commit.commit?.message ?? '').split('\n')[0],
        commitDate: (commit.commit?.committer?.date ?? '').slice(0, 10),
        scannedAt: new Date().toISOString().slice(0, 10),
        scanner: '0.3',
        truncated: files > MAX_FILES,
      },
      ...result,
    });
  } catch (e) {
    if (e?.message === 'too_big') return fail(413, '내려받는 코드가 300MB를 넘어서 진단을 멈췄어요.');
    console.error('scan failed', e);
    return fail(500, '진단 중 오류가 났어요. 잠시 후 다시 시도해 주세요.');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
