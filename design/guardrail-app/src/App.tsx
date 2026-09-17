import { useEffect, useMemo, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { Dialog, DialogContent } from "@/components/ui/dialog";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  ShieldAlert, ShieldCheck, HelpCircle, Crosshair, Box, Wrench, BookOpen,
  RefreshCw, ScanSearch, Globe, Radar, Copy, Check, Play, Sparkles, FileDiff,
} from "lucide-react";

type Cluster = {
  inv: string[]; method: string; route: string; title: string;
  cause: string; ev0: string; ev1: string; fix: string; diff: [string, string][];
};

const CLUSTERS: Cluster[] = [
  { inv: ["I1", "I2", "I6"], method: "GET", route: "/api/v2/workspaces/:id",
    title: "다른 회사의 워크스페이스와 API 토큰이 통째로 노출됩니다",
    cause: "소유권 검사가 없습니다. **owner_id 비교 한 줄**이면 세 가지가 한꺼번에 해결됩니다.",
    ev0: "밥으로 로그인 → 앨리스 워크스페이스(id=1) 요청 → 성공:",
    ev1: '{"id":1,"owner_id":1,"name":"Alice Corp","api_token":"wtok_ali[[R]]"}',
    fix: '"/api/v2/workspaces/:id" 에서 행을 불러온 뒤, owner 컬럼을 인증된 사용자 id 와 비교해 다르면 403/404 를 반환하세요. GET 뿐 아니라 모든 메서드에서 서버 측으로 검사해야 합니다. 다른 검사를 약화시키지 마세요.',
    diff: [["ctx", "  const ws = await db.workspaces.findById(params.id)"], ["add", "+ if (ws.owner_id !== session.user.id)"], ["add", '+   return Response.json({error:"forbidden"},{status:403})'], ["ctx", "  return Response.json(ws)"]] },
  { inv: ["I3", "I6"], method: "GET", route: "/api/internal/metrics",
    title: "로그인도 안 하고 DB 비밀번호를 볼 수 있습니다",
    cause: "내부 전용 엔드포인트에 **인증이 없고**, 응답에 서버 전용 값이 들어 있습니다.",
    ev0: "토큰 없이 요청 → 200 OK:",
    ev1: '{"signups_today":42,"db_password":"prod[[R]]","active_sessions":3}',
    fix: '"/api/internal/metrics" 에 인증 미들웨어를 붙이고, 응답에서 db_password 같은 서버 전용 필드를 제거하세요. 라우트 표를 확인하세요 — 보호된 라우터 밖에 등록된 것이 흔한 원인입니다.',
    diff: [["del", "- export async function GET() {"], ["add", "+ export const GET = withAuth(async () => {"], ["del", "-   return Response.json({ signups_today, db_password, active_sessions })"], ["add", "+   return Response.json({ signups_today, active_sessions })"], ["ctx", "  })"]] },
  { inv: ["I1"], method: "GET", route: "/api/notes/:id",
    title: "아무 글이나 남의 것을 읽을 수 있습니다",
    cause: "ID만 바꾸면 다른 사용자의 글이 그대로 옵니다 (IDOR).",
    ev0: "밥 토큰으로 앨리스 글(id=1) 요청 → 내용 그대로 수신:",
    ev1: '{"id":1,"owner_id":1,"title":"Alice private","body":"alice sec[[R]]"}',
    fix: '"/api/notes/:id" 에서 글을 불러온 뒤 owner_id 를 인증된 사용자와 비교하세요. 삭제(DELETE) 경로에도 같은 검사를 넣으세요 — 읽기만 막고 삭제를 열어두는 실수가 흔합니다.',
    diff: [["ctx", '  const note = db.prepare("SELECT * FROM notes WHERE id=?").get(id)'], ["add", "+ if (note.owner_id !== req.user.id) return res.status(403).end()"], ["ctx", "  res.json(note)"]] },
  { inv: ["I2"], method: "GET", route: "/api/search",
    title: "검색하면 남의 비공개 글까지 결과에 나옵니다",
    cause: "검색 쿼리에 **본인 소유 필터가 없어** 전체 테이블을 뒤집니다.",
    ev0: '밥이 "Alice"로 검색 → 앨리스의 비공개 글이 결과에:',
    ev1: '[{"id":1,"owner_id":1,"title":"Alice private", …}]',
    fix: "검색 쿼리에 WHERE owner_id = :me 를 추가하세요. 목록·검색 API 는 항상 호출자 소유로 범위를 좁혀야 합니다. UI 에서 숨기는 것은 통제가 아닙니다.",
    diff: [["del", "- SELECT * FROM notes WHERE title LIKE ?"], ["add", "+ SELECT * FROM notes WHERE title LIKE ? AND owner_id = ?"]] },
  { inv: ["I2", "I6"], method: "GET", route: "/api/admin/users",
    title: "일반 사용자가 관리자 회원 목록을 통째로 봅니다",
    cause: "로그인만 하면 접근됩니다 — **역할(role) 검사가 없습니다**. 응답엔 비밀번호 해시까지 포함됩니다.",
    ev0: "밥(일반 사용자) 토큰으로 관리자 API 요청 → 200, 3명 전원:",
    ev1: '[{"id":1,"email":"al[[R]]@…","password_hash":"7abd[[R]]"}, …]',
    fix: '"/api/admin/users" 를 역할 검사 뒤로 옮기고(관리자만), 응답에서 password_hash 를 제거하세요. SELECT * 대신 필요한 컬럼만 명시하거나 공용 시리얼라이저로 민감 컬럼을 걸러내세요.',
    diff: [["add", '+ if (req.user.role !== "admin") return res.status(403).end()'], ["del", '- res.json(db.prepare("SELECT * FROM users").all())'], ["add", '+ res.json(db.prepare("SELECT id,email,role FROM users").all())']] },
  { inv: ["auth.uid"], method: "TABLE", route: "documents · Supabase RLS",
    title: "로그인한 사람은 누구나 모든 문서를 읽습니다",
    cause: 'RLS 정책이 **"소유"가 아니라 "로그인 여부"만** 검사합니다. 두 계정이 서로의 문서를 다 봅니다.',
    ev0: "앨리스·밥 각각 조회 → 완전히 동일한 2행 수신:",
    ev1: '[{"id":1,"owner":1,"content":"alice doc"},{"id":2,"owner":2, …}]',
    fix: "documents 테이블의 RLS 정책을 고치세요. USING (auth.uid() IS NOT NULL) 를 USING (owner = auth.uid()) 로 바꾸면 각자 자기 행만 보게 됩니다.",
    diff: [["del", "- CREATE POLICY p ON documents USING (auth.uid() IS NOT NULL);"], ["add", "+ CREATE POLICY p ON documents USING (owner = auth.uid());"]] },
];

const PIPE = [
  ["01 발견", "라우트 자동 탐색", "Cloudflare", "gr-accent"],
  ["02 검사", "불변식 I1~I6", "고유 · RLS·2계정", "gr-accent"],
  ["03 반박", "적대적 반증", "Cloudflare·VulnHunter", "gr-accent"],
  ["04 증명", "격리 실행 PoC", "XBOW·E2B", "gr-pass"],
  ["05 정리", "노이즈 제거", "Aikido", "gr-warn"],
  ["06 고침", "테스트+재검증", "VulnHunter", "gr-crit"],
  ["07 감시", "배포마다 재검사", "Aikido", "gr-accent"],
];

const STREAM: [string, string][] = [
  ["accent", "  GET /api/v2/workspaces/1   Authorization: Bearer <A>"],
  ["", "  route discovered · account A → B"],
  ["crit", "  → 200 OK   ISOLATION BROKEN — cross-account read"],
  ["", "  GET /api/notes/1            swap owner id …"],
  ["", "  DELETE /api/notes/1         probe destructive …"],
  ["", "  GET /api/admin/users        role=user → expect 403"],
  ["crit", "  → 200 OK   BFLA — 3 records incl. password_hash"],
  ["", "  GET /api/internal/metrics   no token …"],
  ["crit", "  → 200 OK   db_password exposed to anon"],
  ["", "  RLS documents   anon → []   (ok)"],
  ["", "  RLS documents   userA vs userB …"],
  ["warn", "  ≠ identical rows — auth.uid() misuse?"],
  ["", "  adversary: disprove candidate #4 …"],
  ["", "  sandbox: replay PoC in isolated VM (net off) …"],
  ["pass", "  ✓ confirmed 6   ✓ passed 48   noise −46%"],
  ["", "  GET /api/cards/1   owner check → 403   (ok)"],
];

function renderRich(s: string) {
  // **bold** and [[R]] redaction
  const parts = s.split(/(\*\*[^*]+\*\*|\[\[R\]\])/g);
  return parts.map((p, i) => {
    if (p === "[[R]]") return <span key={i} className="gr-redact">redacted</span>;
    if (p.startsWith("**")) return <b key={i} className="font-medium text-foreground">{p.slice(2, -2)}</b>;
    return <span key={i}>{p}</span>;
  });
}
function renderEv(s: string) {
  return s.split(/(\[\[R\]\])/g).map((p, i) =>
    p === "[[R]]" ? <span key={i} className="gr-redact">redacted</span> : <span key={i}>{p}</span>);
}

type View = "input" | "scan" | "results";

export default function App() {
  const [view, setView] = useState<View>("input");
  const [url, setUrl] = useState("https://my-vibe-app.vercel.app");
  const [host, setHost] = useState("my-vibe-app.vercel.app");
  const [prog, setProg] = useState(0);
  const [fixIdx, setFixIdx] = useState<number | null>(null);
  const raf = useRef<number>();
  const reduce = useMemo(() => matchMedia("(prefers-reduced-motion: reduce)").matches, []);

  const runScan = () => {
    const h = url.replace(/^https?:\/\//, "").replace(/\/.*$/, "") || "my-vibe-app.vercel.app";
    setHost(h); setView("scan"); setProg(0);
    const dur = reduce ? 400 : 3200;
    const t0 = performance.now();
    const step = (now: number) => {
      const p = Math.min(1, (now - t0) / dur);
      setProg(p);
      if (p < 1) raf.current = requestAnimationFrame(step);
      else setTimeout(() => setView("results"), reduce ? 0 : 260);
    };
    raf.current = requestAnimationFrame(step);
  };
  useEffect(() => () => { if (raf.current) cancelAnimationFrame(raf.current); }, []);

  const stageIdx = Math.min(4, Math.floor(prog * 5));
  const STAGES = ["라우트 발견", "불변식 I1~I6 검사", "적대적 반증", "격리 증명", "결과 정리"];

  return (
    <div className="min-h-screen">
      {/* ============ INPUT ============ */}
      {view === "input" && (
        <section className="mx-auto max-w-5xl px-5 py-10 min-h-screen flex flex-col justify-center">
          <div className="flex items-center gap-2.5">
            <span className="w-3 h-3 rounded" style={{ background: "var(--gr-accent)", boxShadow: "0 0 0 5px #274a63" }} />
            <span className="font-black text-[22px] tracking-wide">가드레일</span>
            <span className="ml-auto font-mono text-[11.5px]" style={{ color: "var(--gr-faint)" }}>XBOW · Cloudflare · VulnHunter · Aikido 기법을 하나로</span>
          </div>
          <div className="font-mono text-xs tracking-[2px] uppercase gr-accent mt-8">바이브코딩 앱 자율 보안 검증</div>
          <h1 className="text-[clamp(28px,5vw,38px)] font-black leading-[1.12] mt-3">찾고 · 반박하고 · 증명하고<br />고치고 · 계속 지킵니다</h1>
          <p className="text-muted-foreground text-[15px] leading-[1.65] mt-3.5 max-w-[64ch]">
            {renderRich("URL만 넣으면 라우트를 스스로 찾아 **불변식 6개**로 검사하고, 독립 에이전트가 **반박**한 뒤, 격리 환경에서 **실제로 뚫어 증명**하고, 고칠 프롬프트까지 줍니다. 배포할 때마다 다시 지켜봅니다.")}
          </p>
          <div className="grid grid-cols-2 md:grid-cols-7 gap-1.5 mt-6">
            {PIPE.map(([n, t, s, cls]) => (
              <div key={n} className="bg-card border rounded-xl px-3 py-2.5">
                <div className={`font-mono text-[10.5px] ${cls}`}>{n}</div>
                <div className="text-xs mt-1 font-medium">{t}</div>
                <div className="text-[10px] mt-0.5" style={{ color: "var(--gr-faint)" }}>{s}</div>
              </div>
            ))}
          </div>
          <div className="flex gap-2.5 items-end flex-wrap mt-6">
            <div className="flex-1 min-w-[260px] flex flex-col gap-1.5">
              <label htmlFor="url" className="text-xs text-muted-foreground tracking-[.3px]">진단할 사이트 주소 <span style={{ color: "var(--gr-faint)" }}>· anon key 넣으면 Supabase RLS까지</span></label>
              <Input id="url" value={url} onChange={(e) => setUrl(e.target.value)} onKeyDown={(e) => e.key === "Enter" && runScan()} className="font-mono h-[52px] text-sm" />
            </div>
            <Button onClick={runScan} className="h-[52px] px-6 font-bold text-[15px] gap-2"><ScanSearch className="w-4 h-4" />30초 무료 진단</Button>
          </div>
          <div className="text-xs mt-3" style={{ color: "var(--gr-faint)" }}>✓ 가입 불필요 &nbsp; ✓ 본인 소유 앱만 &nbsp; ✓ 시크릿은 마스킹 &nbsp; ✓ 예시 데이터로 미리보기 중</div>
        </section>
      )}

      {/* ============ SCAN ============ */}
      {view === "scan" && (
        <section className="mx-auto max-w-5xl px-5 py-10 min-h-screen flex flex-col justify-center gap-4">
          <div className="flex items-center gap-2.5">
            <span className="w-3 h-3 rounded" style={{ background: "var(--gr-accent)", boxShadow: "0 0 0 4px #274a63" }} />
            <span className="font-black text-[19px] tracking-wide">가드레일</span>
            <span className="ml-auto flex items-center gap-2 font-mono text-[13px] text-muted-foreground">
              <span className="w-2 h-2 rounded-full" style={{ background: "var(--gr-pass)", boxShadow: "0 0 8px var(--gr-pass)" }} />
              스캔 중<span className="gr-blink">_</span> · {host}
            </span>
          </div>
          <div className="relative border rounded-2xl overflow-hidden h-[min(52vh,380px)]" style={{ background: "var(--gr-code)", boxShadow: "inset 0 0 60px rgba(77,176,255,.05)" }}>
            <div className="absolute inset-x-0 top-0 z-[3] flex items-center gap-1.5 px-4 py-3 border-b" style={{ background: "hsl(var(--background))", borderColor: "var(--gr-bdsoft)" }}>
              <i className="w-2.5 h-2.5 rounded-full inline-block" style={{ background: "var(--gr-crit)" }} />
              <i className="w-2.5 h-2.5 rounded-full inline-block" style={{ background: "var(--gr-warn)" }} />
              <i className="w-2.5 h-2.5 rounded-full inline-block" style={{ background: "var(--gr-pass)" }} />
              <span className="ml-2.5 font-mono text-xs truncate" style={{ color: "var(--gr-faint)" }}>probing /api/v2/workspaces/:id · account A → B</span>
            </div>
            <div className="absolute left-0 right-0 top-[46px] bottom-0 overflow-hidden px-5">
              <div className="gr-flow font-mono text-[11.5px] leading-[1.5]">
                {STREAM.concat(STREAM).map(([c, t], i) => (
                  <div key={i} className={`opacity-55 whitespace-pre-wrap break-words ${c ? "opacity-90" : ""}`}
                       style={{ color: c === "crit" ? "var(--gr-crit)" : c === "warn" ? "var(--gr-warn)" : c === "pass" ? "var(--gr-pass)" : c === "accent" ? "var(--gr-accent)" : undefined }}>{t}</div>
                ))}
              </div>
            </div>
            <div className="gr-sweep absolute left-0 right-0 h-0.5 z-[2]" style={{ top: "2%", background: "linear-gradient(90deg,transparent,var(--gr-pass),transparent)", boxShadow: "0 0 18px 3px rgba(58,215,135,.55)" }} />
            <div className="absolute left-0 right-0 bottom-0 h-[70px] z-[2]" style={{ background: "linear-gradient(180deg,transparent,var(--gr-code))" }} />
          </div>
          <div className="flex items-baseline gap-2.5 mt-2">
            <span className="font-num font-bold text-2xl gr-accent">{Math.round(prog * 57)}</span>
            <span className="font-mono text-[12.5px] text-muted-foreground">/ 57 라우트 검사 중</span>
          </div>
          <Progress value={prog * 100} className="h-1.5" />
          <div className="flex gap-2 flex-wrap font-mono text-[11.5px] mt-0.5">
            {STAGES.map((s, i) => (
              <span key={s} className="px-2.5 py-1 rounded-md border"
                    style={i < stageIdx ? { background: "var(--gr-passbg)", color: "var(--gr-pass)", borderColor: "var(--gr-passbd)" }
                          : i === stageIdx ? { background: "hsl(var(--card))", color: "var(--gr-accent)", borderColor: "#274a63" }
                          : { background: "hsl(var(--background))", color: "var(--gr-faint)" }}>{s}</span>
            ))}
          </div>
        </section>
      )}

      {/* ============ RESULTS ============ */}
      {view === "results" && (
        <section>
          <header className="sticky top-0 z-20 border-b backdrop-blur" style={{ background: "hsl(var(--background)/.86)" }}>
            <div className="mx-auto max-w-5xl px-5 py-3.5 flex items-center gap-3 flex-wrap">
              <div className="flex items-center gap-2.5 font-black text-xl"><span className="w-2.5 h-2.5 rounded" style={{ background: "var(--gr-accent)", boxShadow: "0 0 0 4px #274a63" }} />가드레일</div>
              <div className="ml-auto flex items-center gap-2 bg-card border rounded-lg px-3 py-1.5 font-mono text-[13px] text-muted-foreground min-w-0">
                <Globe className="w-[15px] h-[15px] shrink-0" /><b className="text-foreground font-medium truncate">{host}</b><span style={{ color: "var(--gr-faint)" }}>· Next.js + Supabase</span>
              </div>
              <Button variant="outline" onClick={() => setView("input")} className="gap-1.5 h-9"><RefreshCw className="w-[15px] h-[15px]" />다시 스캔</Button>
            </div>
          </header>

          <div className="mx-auto max-w-5xl px-5">
            <div className="pt-6 pb-1.5">
              <div className="font-mono text-xs tracking-[2px] uppercase gr-accent">스캔 완료 · 방금</div>
              <h1 className="text-[clamp(24px,4.5vw,34px)] font-black leading-[1.1] mt-2.5">지금 <span className="gr-crit">6곳</span>에서 남의 데이터가 새고 있습니다</h1>
              <p className="text-muted-foreground text-[15px] leading-[1.6] mt-3 max-w-[68ch]">{renderRich("라우트를 스스로 찾아 **불변식 6개**로 검사하고, 독립 에이전트가 **반박**한 뒤, 격리 환경에서 **실제로 뚫어 증명**한 것만 보여드립니다.")}</p>

              <div className="grid md:grid-cols-[1.5fr_1fr] gap-4 mt-5.5" style={{ marginTop: "1.4rem" }}>
                <div className="grid grid-cols-3 gap-3">
                  {[["6", "확정", "실제로 뚫림", "crit", ShieldAlert], ["3", "확인 필요", "당신 판단 필요", "warn", HelpCircle], ["48", "통과", "검사했고 안전", "pass", ShieldCheck]].map(([n, l, s, c, Icon]: any) => (
                    <div key={l} className="relative overflow-hidden border rounded-2xl bg-card p-4">
                      <span className="absolute inset-y-0 left-0 w-1" style={{ background: `var(--gr-${c})` }} />
                      <div className="font-num font-bold text-[44px] leading-none tracking-tight" style={{ color: `var(--gr-${c})` }}>{n}</div>
                      <div className="flex items-center gap-1.5 mt-2.5 text-[13px] text-muted-foreground"><Icon className="w-3.5 h-3.5" />{l}</div>
                      <div className="text-xs mt-0.5" style={{ color: "var(--gr-faint)" }}>{s}</div>
                    </div>
                  ))}
                </div>
                <div className="border rounded-2xl bg-card p-4 flex items-center gap-5">
                  <Donut />
                  <div className="text-[13px] text-muted-foreground leading-[1.7]">
                    <div className="flex items-center gap-1.5"><i className="w-2 h-2 rounded-sm inline-block" style={{ background: "var(--gr-crit)" }} />확정 6</div>
                    <div className="flex items-center gap-1.5"><i className="w-2 h-2 rounded-sm inline-block" style={{ background: "var(--gr-warn)" }} />확인 필요 3</div>
                    <div className="flex items-center gap-1.5"><i className="w-2 h-2 rounded-sm inline-block" style={{ background: "var(--gr-pass)" }} />통과 48</div>
                    <div className="font-mono text-[11px] mt-2" style={{ color: "var(--gr-faint)" }}>불변식 I1~I6 검사</div>
                  </div>
                </div>
              </div>
            </div>

            <SectionHead title="확정된 취약점" meta="심각도순 · 독립 반증 통과분만 · 근본원인별 묶음" />
            <div className="flex flex-col gap-3">
              {CLUSTERS.map((c, i) => (
                <div key={i} className="grid grid-cols-[5px_1fr] border rounded-2xl bg-card overflow-hidden hover:border-[#46597a] transition-colors">
                  <div style={{ background: "var(--gr-crit)" }} />
                  <div className="p-[15px_17px] min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono font-bold text-xs px-2 py-[3px] rounded-md border" style={{ background: "var(--gr-critbg)", color: "var(--gr-crit)", borderColor: "var(--gr-critbd)" }}>5/5</span>
                      <Badge className="gap-1 font-mono text-[11px] font-normal border" style={{ background: "var(--gr-passbg)", color: "var(--gr-pass)", borderColor: "var(--gr-passbd)" }}><ShieldCheck className="w-3 h-3" />반증 통과</Badge>
                      <span className="font-mono text-sm font-medium"><span className="gr-accent font-bold">{c.method}</span> {c.route}</span>
                      <span className="flex gap-1.5 ml-auto">{c.inv.map((v) => <span key={v} className="font-mono text-[11px] text-muted-foreground border rounded px-1.5 py-0.5">{v}</span>)}</span>
                    </div>
                    <div className="font-bold text-[15px] mt-3">{c.title}</div>
                    <div className="text-muted-foreground text-[13.5px] mt-1">근본원인: {renderRich(c.cause)}</div>
                    <div className="mt-3 border rounded-xl overflow-hidden" style={{ background: "var(--gr-code)", borderColor: "var(--gr-bdsoft)" }}>
                      <div className="flex items-center gap-1.5 px-[11px] py-2 border-b font-mono text-[11.5px] tracking-[.4px] uppercase gr-pass" style={{ borderColor: "var(--gr-bdsoft)" }}>
                        <Crosshair className="w-[13px] h-[13px]" />실제로 이렇게 뚫었습니다
                        <span className="ml-auto flex items-center gap-1 text-[10.5px] normal-case tracking-normal" style={{ color: "var(--gr-faint)" }}><Box className="w-[11px] h-[11px]" />격리 VM에서 실행 · XBOW·E2B</span>
                      </div>
                      <pre className="m-0 px-[13px] py-[11px] font-mono text-[12.5px] leading-[1.6] overflow-x-auto whitespace-pre-wrap break-words" style={{ color: "#d4e0ef" }}>{renderEv(c.ev0)}{"\n"}<span style={{ color: "var(--gr-faint)" }}>→</span> {renderEv(c.ev1)}</pre>
                    </div>
                    <div className="flex gap-2.5 mt-3.5 flex-wrap">
                      <Button onClick={() => setFixIdx(i)} className="gap-1.5 h-9 text-[13px]"><Wrench className="w-[15px] h-[15px]" />고치기</Button>
                      <Button variant="outline" onClick={() => setFixIdx(i)} className="gap-1.5 h-9 text-[13px]"><BookOpen className="w-[15px] h-[15px]" />왜 위험한가요?</Button>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            <SectionHead title="확인이 필요합니다" meta="뚫릴 수 있으나 의도 여부는 당신만 압니다" />
            <div className="border rounded-2xl bg-card overflow-hidden">
              <CompactRow icon={<HelpCircle className="w-4 h-4 gr-warn" />} route={<><span className="gr-accent font-bold">PATCH</span> /api/me</>} desc="클라이언트가 보낸 role 값을 서버가 믿을 수 있습니다" why="쓰기 테스트 꺼짐 — 켜면 확정" />
              <CompactRow icon={<HelpCircle className="w-4 h-4 gr-warn" />} route={<><span className="gr-accent font-bold">POST</span> /api/orders/:id/status</>} desc="결제 상태를 되돌릴 수 있는지 — 합법 여부는 앱 규칙에 달림" why="상태 전이 규칙은 당신만" />
              <CompactRow icon={<HelpCircle className="w-4 h-4 gr-warn" />} route={<span>table: api_keys</span>} desc="익명엔 잠겼으나 secret 담은 테이블 — service_role 유출 시 즉시 노출" why="크라운 주얼 · 키 관리" last />
            </div>

            <SectionHead title="통과한 검사" meta="무엇을 검사했는지 알아야 하니까" />
            <div className="border rounded-2xl bg-card overflow-hidden">
              <CompactRow icon={<Check className="w-4 h-4 gr-pass" />} route={<><span className="gr-accent font-bold">GET</span> /api/cards/:id</>} desc="소유권 검사가 제대로 있음 — 밥이 앨리스 카드 요청하면 403" why={<span className="gr-pass">격리 유지 ✓</span>} />
              <CompactRow icon={<Check className="w-4 h-4 gr-pass" />} route={<span>table: private_msgs</span>} desc="RLS 정상 — 로그인해도 자기 메시지만 보임" why={<span className="gr-pass">소유권 정책 ✓</span>} />
              <CompactRow icon={<Check className="w-4 h-4 gr-pass" />} route={<><span className="gr-accent font-bold">GET</span> /api/stats</>} desc="공개 엔드포인트 — 민감 데이터 없음. 권한상승 오탐으로 잡지 않음" why={<span className="gr-pass">의도된 공개 ✓</span>} last />
            </div>

            <div className="my-7 border border-dashed rounded-2xl p-5" style={{ background: "linear-gradient(180deg,hsl(var(--card)),transparent)" }}>
              <h3 className="font-black text-[17px] flex items-center gap-2.5"><Radar className="w-[18px] h-[18px] gr-accent" />배포할 때마다 자동으로 다시 지켜봅니다</h3>
              <div className="grid gap-2.5 mt-3.5" style={{ gridTemplateColumns: "repeat(auto-fit,minmax(170px,1fr))" }}>
                {[["배포 감지", "새 엔드포인트만 즉시 재검사"], ["매일 새벽", "전체 읽기전용 스윕"], ["주 1회", "쓰기·삭제 포함 심층"], ["이번 주", "3회 배포 · 새 API 5개"]].map(([t, v]) => (
                  <div key={t} className="bg-card border rounded-xl px-3.5 py-3" style={{ borderColor: "var(--gr-bdsoft)" }}>
                    <div className="text-xs font-mono" style={{ color: "var(--gr-faint)" }}>{t}</div>
                    <div className="text-[13.5px] mt-0.5">{v}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>
      )}

      {/* ============ FIX DIALOG ============ */}
      <FixDialog idx={fixIdx} onClose={() => setFixIdx(null)} />
    </div>
  );
}

function SectionHead({ title, meta }: { title: string; meta: string }) {
  return (
    <div className="flex items-baseline gap-3 mt-8 mb-3">
      <h2 className="font-black text-[22px]">{title}</h2>
      <span className="font-mono text-xs ml-auto" style={{ color: "var(--gr-faint)" }}>{meta}</span>
    </div>
  );
}
function CompactRow({ icon, route, desc, why, last }: { icon: React.ReactNode; route: React.ReactNode; desc: string; why: React.ReactNode; last?: boolean }) {
  return (
    <div className={`flex items-center gap-3 px-4 py-3 text-[13.5px] flex-wrap ${last ? "" : "border-b"}`} style={{ borderColor: "var(--gr-bdsoft)" }}>
      {icon}<span className="font-mono text-[13px]">{route}</span>
      <span className="text-muted-foreground">{desc}</span>
      <span className="text-xs ml-auto text-right" style={{ color: "var(--gr-faint)" }}>{why}</span>
    </div>
  );
}

function Donut() {
  const total = 57, conf = 6, need = 3, pass = 48;
  const r = 52, c = 2 * Math.PI * r;
  const seg = (n: number) => (n / total) * c;
  let off = 0;
  const arc = (n: number, color: string) => {
    const el = <circle key={color} cx="60" cy="60" r={r} fill="none" stroke={color} strokeWidth="14"
      strokeDasharray={`${seg(n)} ${c - seg(n)}`} strokeDashoffset={-off} transform="rotate(-90 60 60)" />;
    off += seg(n); return el;
  };
  return (
    <div className="relative w-[120px] h-[120px] shrink-0">
      <svg width="120" height="120" viewBox="0 0 120 120">
        <circle cx="60" cy="60" r={r} fill="none" stroke="var(--gr-bdsoft)" strokeWidth="14" />
        {arc(pass, "var(--gr-pass)")}{arc(conf, "var(--gr-crit)")}{arc(need, "var(--gr-warn)")}
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <b className="font-num font-bold text-[26px] leading-none">57</b>
        <span className="text-[11px] text-muted-foreground">엔드포인트</span>
      </div>
    </div>
  );
}

function FixDialog({ idx, onClose }: { idx: number | null; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  const [rv, setRv] = useState<"idle" | "run" | "ok">("idle");
  const reduce = useMemo(() => matchMedia("(prefers-reduced-motion: reduce)").matches, []);
  useEffect(() => { if (idx !== null) { setCopied(false); setRv("idle"); } }, [idx]);
  if (idx === null) return null;
  const c = CLUSTERS[idx];
  const copy = () => { navigator.clipboard?.writeText(c.fix).catch(() => {}); setCopied(true); setTimeout(() => setCopied(false), 1500); };
  const reverify = () => { setRv("run"); setTimeout(() => setRv("ok"), reduce ? 0 : 850); };
  return (
    <Dialog open={idx !== null} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-2xl p-0 gap-0 bg-card overflow-hidden">
        <div className="p-[16px_18px] border-b">
          <div className="flex items-center gap-2.5">
            <span className="font-mono font-bold text-xs px-2 py-[3px] rounded-md border" style={{ background: "var(--gr-critbg)", color: "var(--gr-crit)", borderColor: "var(--gr-critbd)" }}>5/5</span>
            <span className="font-mono text-sm font-medium"><span className="gr-accent font-bold">{c.method}</span> {c.route}</span>
          </div>
          <div className="font-bold text-[15px] mt-2.5">{c.title}</div>
        </div>
        <Tabs defaultValue="p" className="w-full">
          <TabsList className="mx-[18px] mt-3 bg-transparent gap-1 justify-start p-0 h-auto">
            <TabsTrigger value="p" className="data-[state=active]:bg-[color:var(--gr-code)] gap-1.5 text-[13px]"><Sparkles className="w-3.5 h-3.5" />AI 프롬프트</TabsTrigger>
            <TabsTrigger value="d" className="data-[state=active]:bg-[color:var(--gr-code)] gap-1.5 text-[13px]"><FileDiff className="w-3.5 h-3.5" />수정 코드</TabsTrigger>
            <TabsTrigger value="v" className="data-[state=active]:bg-[color:var(--gr-code)] gap-1.5 text-[13px]"><ShieldCheck className="w-3.5 h-3.5" />재검증</TabsTrigger>
          </TabsList>
          <TabsContent value="p" className="p-[15px_18px_20px] mt-0">
            <div className="flex items-center gap-2.5 mb-2.5">
              <Button variant="outline" onClick={copy} className="gap-1.5 h-9 text-[13px]">{copied ? <><Check className="w-[15px] h-[15px]" />복사됨</> : <><Copy className="w-[15px] h-[15px]" />프롬프트 복사</>}</Button>
              <span className="text-[12.5px] text-muted-foreground">Cursor·Claude Code 에 붙여넣으면 바로 고칩니다</span>
            </div>
            <pre className="m-0 border rounded-xl p-3.5 font-mono text-[12.5px] leading-[1.65] overflow-x-auto whitespace-pre-wrap break-words" style={{ background: "var(--gr-code)", borderColor: "var(--gr-bdsoft)", color: "#d4e0ef" }}>{c.fix}</pre>
          </TabsContent>
          <TabsContent value="d" className="p-[15px_18px_20px] mt-0">
            <pre className="m-0 border rounded-xl p-3.5 font-mono text-[12.5px] leading-[1.65] overflow-x-auto whitespace-pre-wrap break-words" style={{ background: "var(--gr-code)", borderColor: "var(--gr-bdsoft)" }}>
              {c.diff.map(([k, t], i) => (
                <div key={i} style={{ color: k === "add" ? "var(--gr-pass)" : k === "del" ? "var(--gr-crit)" : "var(--gr-faint)" }}>{t}</div>
              ))}
            </pre>
          </TabsContent>
          <TabsContent value="v" className="p-[15px_18px_20px] mt-0">
            <div className="flex items-center gap-3 flex-wrap">
              <Button onClick={reverify} className="gap-1.5 h-9 text-[13px]"><Play className="w-[15px] h-[15px]" />같은 공격 다시 실행</Button>
              <span className="font-mono text-[13px] px-3.5 py-2 rounded-xl border"
                    style={rv === "ok" ? { color: "var(--gr-pass)", borderColor: "var(--gr-passbd)", background: "var(--gr-passbg)" } : { color: "hsl(var(--muted-foreground))" }}>
                {rv === "idle" ? "고친 뒤 눌러 확인하세요" : rv === "run" ? "공격 재실행 중…" : "이제 막힙니다 ✓  403 Forbidden"}
              </span>
            </div>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}
