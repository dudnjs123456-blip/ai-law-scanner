# AI 법령 코드 진단

깃 저장소 주소를 넣으면 코드를 읽어서 AI 기본법, 개인정보보호법 등 AI 관련 법령에 걸릴 만한 부분을 찾아주는 서비스예요.

- 받은 코드는 **실행하지 않고 읽기만** 해요. 진단이 끝나면 바로 지워요.
- 판정은 미리 정한 규칙으로 해요. 같은 코드를 넣으면 항상 같은 결과가 나와요.
- 법률 자문이 아닌 실무 준비용 참고 자료예요.

## 구성

| 파일 | 역할 |
|---|---|
| `scan.mjs` | 진단 엔진. 규칙과 법령별 판정이 모두 여기 있어요 |
| `app/api/scan/route.js` | 진단 서버. GitHub에서 코드를 받아 `scan.mjs`로 진단해요 |
| `public/index.html` | 화면. 법령 모음, 코드 진단, 질문으로 진단 탭 |
| `public/reports/example.json` | 첫 화면에 보여주는 예시 결과 (투게더 게임) |
| `fixtures/` | 진단 엔진 테스트용 코드 |

## 내 컴퓨터에서 실행

```bash
npm install
npm run dev        # http://localhost:3000
```

진단 엔진만 따로 돌릴 수도 있어요.

```bash
node scan.mjs https://github.com/회사/저장소
node scan.mjs ./내-프로젝트-폴더 --json 결과.json
```

## 테스트

```bash
npm test                # 전체 (고정 커밋 저장소를 내려받으므로 인터넷 필요)
npm test -- --offline   # 인터넷 없이 도는 테스트만
npm test -- --update    # 규칙을 일부러 바꿨을 때 스냅숏 기대 결과 갱신
```

- **스냅숏 테스트:** 테스트용 코드(`fixtures/`)와 고정 커밋의 Together·포트폴리오 저장소 판정 전체가 `tests/expected.json`과 같아야 해요.
- **변형 테스트:** 정상 앱에서 한 가지만 바꿨을 때(AI 표시 삭제, 비밀키 추가 등) 노린 판정만 바뀌어야 해요. 노리지 않은 판정이 함께 바뀌면 실패예요.
- GitHub에 올리면 GitHub Actions가 전체 테스트를 돌리고, Vercel은 빌드 전에 인터넷 없이 도는 테스트를 돌려서 실패하면 배포하지 않아요.
- 오탐을 고칠 때는 같은 상황을 담은 테스트를 먼저 추가하세요.

## 보안 점검

AI 서비스에서 자주 생기는 문제를 [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/)를 참고해 점검해요.

| 항목 | 기준 |
|---|---|
| 비밀키 노출 (LLM02) | Anthropic·OpenAI·Google·GitHub·AWS·Stripe·Slack 키, 개인 키, Supabase 관리자 키, 저장소에 올라간 `.env` |
| 브라우저로 새는 AI 키 (LLM02) | `NEXT_PUBLIC_` 같은 공개 접두어의 AI 키, `dangerouslyAllowBrowser: true` |
| 프롬프트 인젝션 (LLM01) | 사용자가 보낸 값이 시스템 지시문에 직접 들어가는지 |
| AI 응답의 HTML 삽입 (LLM05) | AI 응답을 보여 주는 화면의 `dangerouslySetInnerHTML`, `innerHTML` |
| AI 호출 횟수·비용 제한 (LLM10) | AI를 부르는 서버의 요청 횟수 제한, 로그인 확인, 입력 길이 제한 |
| 문자열을 코드로 실행 | `eval`, `new Function` |

찾은 비밀키는 앞 6자리와 길이만 보여 줘요.

## Vercel에 배포

1. 이 폴더를 GitHub 저장소로 올려요.
2. [vercel.com/new](https://vercel.com/new)에서 그 저장소를 가져와요(Import). 설정은 기본값 그대로 두면 돼요.
3. (권장) Vercel 프로젝트의 Settings → Environment Variables에 `GITHUB_TOKEN`을 넣어요.
   - GitHub 토큰이 없으면 GitHub API를 시간당 60번만 부를 수 있어요. 진단 한 번에 2번 부르니까 시간당 약 30번 진단할 수 있어요.
   - 토큰은 GitHub → Settings → Developer settings → Fine-grained tokens에서 만들고, 권한은 "Public repositories (read-only)"만 주면 돼요.

## 제한

- GitHub 공개 저장소만 진단해요. 비공개 저장소는 아직 지원하지 않아요.
- 저장소 500MB(커밋 기록 포함), 내려받는 양 300MB, 파일 2만 개까지 진단해요.
- 소스 코드와 설정 파일만 내용을 읽어요. 이미지·음성·3D 모델은 파일 이름만 봐요.
- 한 사람(IP)당 1분에 5번까지 진단할 수 있어요.
- 서버 함수는 한 번에 최대 60초 동안 실행돼요.
