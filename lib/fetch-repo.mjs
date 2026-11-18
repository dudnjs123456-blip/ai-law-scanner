/**
 * GitHub 저장소의 한 커밋을 압축 파일로 받아 폴더에 푼다. 진단 서버와 테스트가 함께 쓴다.
 * - 끝까지 받은 뒤(크기 제한을 넘으면 중단) 한 번에 푼다. 받으면서 푸는 것보다 빠르다
 * - 파일과 폴더만 풀고, 심볼릭 링크 같은 특수 항목은 건너뛴다
 * - 진단에 내용이 필요 없는 파일(이미지·음성·3D 모델 등)은 빈 파일로 이름만 남긴다
 */
import fs from 'node:fs';
import path from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { x as untar } from 'tar';
import { needsContent } from '../scan.mjs';

export async function fetchRepo({ owner, repo, sha, dir, maxDownload = 300 * 1024 * 1024, maxFiles = 20_000 }) {
  const dl = await fetch(`https://codeload.github.com/${owner}/${repo}/tar.gz/${sha}`, { headers: { 'User-Agent': 'ai-law-scanner' } });
  if (!dl.ok || !dl.body) throw Object.assign(new Error('download_failed'), { status: dl.status });

  const parts = [];
  let bytes = 0;
  for await (const chunk of dl.body) {
    bytes += chunk.length;
    if (bytes > maxDownload) throw new Error('too_big');
    parts.push(chunk);
  }

  let files = 0;
  const nameOnly = [];
  await pipeline(
    Readable.from([Buffer.concat(parts)]),
    untar({
      cwd: dir,
      strip: 1,
      filter: (p, entry) => {
        if (entry.type === 'Directory') return true;
        if (entry.type !== 'File' || ++files > maxFiles) return false;
        const rel = p.split('/').slice(1).join('/'); // 맨 앞 폴더(저장소-커밋)를 뺀 경로
        if (needsContent(rel)) return true;
        nameOnly.push(rel);
        return false;
      },
    }),
  );
  // 이름만 남길 파일은 빈 파일로 만든다. 저장소 밖으로 나가는 경로는 무시한다
  const base = path.resolve(dir);
  for (const rel of nameOnly) {
    const target = path.resolve(base, rel);
    if (!rel || !target.startsWith(base + path.sep)) continue;
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, '');
  }
  return { bytes, files, truncated: files > maxFiles };
}
