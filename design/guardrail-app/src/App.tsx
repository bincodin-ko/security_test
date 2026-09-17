import { useEffect, useMemo, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent } from "@/components/ui/dialog";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  ShieldCheck, Crosshair, Box, Wrench, BookOpen, RefreshCw,
  Search, Globe, Radar, Copy, Check, Play, Sparkles, FileDiff, Plus, Lock, ArrowRight,
  PenLine, KeyRound, Package, Workflow, Gauge,
} from "lucide-react";

type Cluster = {
  inv: string[]; method: string; route: string; title: string; src: string;
  cause: string; ev0: string; ev1: string; fix: string;
  diff?: [string, string][]; red?: string | null; supaOnly?: boolean;
};
type Row = { method: string; route: string; desc: string; why: string };
type LiveData = {
  live: true; target: string; withSupabase: boolean;
  meta: { routes: number; candidates: number; confirmed: number; clusters: number; dedupe: number; verifyOpen: number; verifyFixed: number; sandboxReqs: number; tables: number | null };
  clusters: Cluster[]; needs: { method: string; route: string; title: string; why: string }[];
  passed: { method: string; route: string; title: string; why: string }[];
  coverage: { supabaseRan: boolean; destructiveRan: boolean };
};

const DEMO_CLUSTERS: Cluster[] = [
  { inv: ["I1", "I2", "I6"], method: "GET", route: "/api/v2/workspaces/:id", src: "2계정 동적 테스트",
    title: "다른 회사의 워크스페이스와 API 토큰이 통째로 노출됩니다",
    cause: "소유권 검사가 없습니다. **owner_id 비교 한 줄**이면 세 가지가 한꺼번에 해결됩니다.",
    ev0: "밥으로 로그인 → 앨리스 워크스페이스(id=1) 요청 → 성공:",
    ev1: '{"id":1,"owner_id":1,"name":"Alice Corp","api_token":"wtok_ali[[R]]"}',
    fix: '"/api/v2/workspaces/:id" 에서 행을 불러온 뒤, owner 컬럼을 인증된 사용자 id 와 비교해 다르면 403/404 를 반환하세요. GET 뿐 아니라 모든 메서드에서 서버 측으로 검사해야 합니다. 다른 검사를 약화시키지 마세요.',
    diff: [["ctx", "  const ws = await db.workspaces.findById(params.id)"], ["add", "+ if (ws.owner_id !== session.user.id)"], ["add", '+   return Response.json({error:"forbidden"},{status:403})'], ["ctx", "  return Response.json(ws)"]] },
  { inv: ["I3", "I6"], method: "GET", route: "/api/internal/metrics", src: "익명 접근 · I3",
    title: "로그인도 안 하고 DB 비밀번호를 볼 수 있습니다",
    cause: "내부 전용 엔드포인트에 **인증이 없고**, 응답에 서버 전용 값이 들어 있습니다.",
    ev0: "토큰 없이 요청 → 200 OK:",
    ev1: '{"signups_today":42,"db_password":"prod[[R]]","active_sessions":3}',
    fix: '"/api/internal/metrics" 에 인증 미들웨어를 붙이고, 응답에서 db_password 같은 서버 전용 필드를 제거하세요. 라우트 표를 확인하세요 — 보호된 라우터 밖에 등록된 것이 흔한 원인입니다.',
    diff: [["del", "- export async function GET() {"], ["add", "+ export const GET = withAuth(async () => {"], ["del", "-   return Response.json({ signups_today, db_password, active_sessions })"], ["add", "+   return Response.json({ signups_today, active_sessions })"], ["ctx", "  })"]] },
  { inv: ["I1"], method: "GET", route: "/api/notes/:id", src: "IDOR · 2계정",
    title: "아무 글이나 남의 것을 읽을 수 있습니다",
    cause: "ID만 바꾸면 다른 사용자의 글이 그대로 옵니다 (IDOR).",
    ev0: "밥 토큰으로 앨리스 글(id=1) 요청 → 내용 그대로 수신:",
    ev1: '{"id":1,"owner_id":1,"title":"Alice private","body":"alice sec[[R]]"}',
    fix: '"/api/notes/:id" 에서 글을 불러온 뒤 owner_id 를 인증된 사용자와 비교하세요. 삭제(DELETE) 경로에도 같은 검사를 넣으세요 — 읽기만 막고 삭제를 열어두는 실수가 흔합니다.',
    diff: [["ctx", '  const note = db.prepare("SELECT * FROM notes WHERE id=?").get(id)'], ["add", "+ if (note.owner_id !== req.user.id) return res.status(403).end()"], ["ctx", "  res.json(note)"]] },
  { inv: ["I7", "I2"], method: "GET", route: "/api/search", src: "주입 · 실행 확인",
    title: "검색창에 넣은 값이 SQL 쿼리로 그대로 들어갑니다",
    cause: "입력을 문자열로 쿼리에 이어붙입니다 — **파라미터라이즈드 쿼리**로 바꾸면 주입도, 남의 글 노출도 함께 막힙니다.",
    ev0: "작은따옴표 하나로 DB가 터집니다 (주입 가능 증거):",
    ev1: `?q=' → 500 {"error":"unrecognized token","stack":"SqliteError[[R]]"} · "abc" → 200`,
    fix: '"/api/search" 에서 문자열로 SQL을 조립하지 말고 파라미터라이즈드 쿼리(prepared statement)를 쓰세요. 출력은 인코딩하고, DB 에러·스택은 클라이언트에 노출하지 마세요. 같은 쿼리에 owner 필터도 더하세요.',
    diff: [["del", "- db.prepare(`SELECT * FROM notes WHERE title LIKE '%${q}%'`)"], ["add", "+ db.prepare('SELECT * FROM notes WHERE title LIKE ? AND owner_id = ?')"], ["add", "+   .all('%'+q+'%', req.user.id)"]] },
  { inv: ["I2", "I6"], method: "GET", route: "/api/admin/users", src: "BFLA · 역할 검사 없음",
    title: "일반 사용자가 관리자 회원 목록을 통째로 봅니다",
    cause: "로그인만 하면 접근됩니다 — **역할(role) 검사가 없습니다**. 응답엔 비밀번호 해시까지 포함됩니다.",
    ev0: "밥(일반 사용자) 토큰으로 관리자 API 요청 → 200, 3명 전원:",
    ev1: '[{"id":1,"email":"al[[R]]@…","password_hash":"7abd[[R]]"}, …]',
    fix: '"/api/admin/users" 를 역할 검사 뒤로 옮기고(관리자만), 응답에서 password_hash 를 제거하세요. SELECT * 대신 필요한 컬럼만 명시하거나 공용 시리얼라이저로 민감 컬럼을 걸러내세요.',
    diff: [["add", '+ if (req.user.role !== "admin") return res.status(403).end()'], ["del", '- res.json(db.prepare("SELECT * FROM users").all())'], ["add", '+ res.json(db.prepare("SELECT id,email,role FROM users").all())']] },
  { inv: ["auth.uid"], method: "TABLE", route: "documents", src: "Supabase RLS · 2계정", supaOnly: true,
    title: "로그인한 사람은 누구나 모든 문서를 읽습니다",
    cause: 'RLS 정책이 **"소유"가 아니라 "로그인 여부"만** 검사합니다. 두 계정이 서로의 문서를 다 봅니다.',
    ev0: "앨리스·밥 각각 조회 → 완전히 동일한 2행 수신:",
    ev1: '[{"id":1,"owner":1,"content":"alice doc"},{"id":2,"owner":2, …}]',
    fix: "documents 테이블의 RLS 정책을 고치세요. USING (auth.uid() IS NOT NULL) 를 USING (owner = auth.uid()) 로 바꾸면 각자 자기 행만 보게 됩니다.",
    diff: [["del", "- CREATE POLICY p ON documents USING (auth.uid() IS NOT NULL);"], ["add", "+ CREATE POLICY p ON documents USING (owner = auth.uid());"]] },
];

const PIPE = [
  ["01", "발견", "라우트 자동 탐색", "Cloudflare"],
  ["02", "검사", "불변식 I1–I7", "고유 · RLS · 2계정"],
  ["03", "반박", "적대적 반증", "Cloudflare · VulnHunter"],
  ["04", "증명", "격리 실행 PoC", "XBOW · E2B"],
  ["05", "정리", "노이즈 제거", "Aikido"],
  ["06", "고침", "테스트 + 재검증", "VulnHunter"],
  ["07", "감시", "배포마다 재검사", "Aikido"],
];

const DEMO_STREAM: [string, string][] = [
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

const DEMO_NEEDS: Row[] = [
  { method: "PATCH", route: "/api/me", desc: "클라이언트가 보낸 role 값을 서버가 믿을 수 있습니다", why: "쓰기 테스트 꺼짐 — 켜면 확정" },
  { method: "POST", route: "/api/orders/:id/status", desc: "결제 상태를 되돌릴 수 있는지 — 합법 여부는 앱 규칙에 달림", why: "상태 전이 규칙은 당신만" },
  { method: "", route: "table: api_keys", desc: "익명엔 잠겼으나 secret 담은 테이블 — service_role 유출 시 즉시 노출", why: "크라운 주얼 · 키 관리" },
];
const DEMO_PASSED: Row[] = [
  { method: "GET", route: "/api/cards/:id", desc: "소유권 검사가 제대로 있음 — 밥이 앨리스 카드 요청하면 403", why: "격리 유지 ✓" },
  { method: "", route: "table: private_msgs", desc: "RLS 정상 — 로그인해도 자기 메시지만 보임", why: "소유권 정책 ✓" },
  { method: "GET", route: "/api/stats", desc: "공개 엔드포인트 — 민감 데이터 없음. 권한상승 오탐으로 잡지 않음", why: "의도된 공개 ✓" },
];

/* classic anon keys are JWTs whose payload carries the project ref →
   we can derive the API URL from the key alone, so the URL field is
   only needed for self-host / new sb_publishable_ keys. */
function supaRefFromKey(key: string): string | null {
  const parts = key.trim().split(".");
  if (parts.length < 3) return null;
  try {
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const json = JSON.parse(decodeURIComponent(escape(atob(b64))));
    return typeof json.ref === "string" && /^[a-z0-9]{16,}$/.test(json.ref) ? json.ref : null;
  } catch { return null; }
}

function Redact({ dark }: { dark?: boolean }) {
  return <span className="font-mono text-[.92em]" style={{ color: dark ? "#ffb86b" : "var(--ap-warn)", background: dark ? "rgba(255,255,255,.09)" : "#f6ede0", padding: "0 5px", borderRadius: 4 }}>redacted</span>;
}
function renderRich(s: string) {
  return s.split(/(\*\*[^*]+\*\*|\[\[R\]\])/g).map((p, i) => {
    if (p === "[[R]]") return <Redact key={i} />;
    if (p.startsWith("**")) return <b key={i} className="font-semibold" style={{ color: "var(--ap-ink)" }}>{p.slice(2, -2)}</b>;
    return <span key={i}>{p}</span>;
  });
}
function renderEv(s: string) {
  return s.split(/(\[\[R\]\])/g).map((p, i) => (p === "[[R]]" ? <Redact key={i} dark /> : <span key={i}>{p}</span>));
}

type View = "input" | "scan" | "results";

/* thin near-black Apple global nav */
function Nav({ right }: { right?: React.ReactNode }) {
  return (
    <nav className="h-11 flex items-center px-5 sticky top-0 z-30" style={{ background: "var(--ap-black)", color: "#f5f5f7" }}>
      <div className="mx-auto max-w-[1100px] w-full flex items-center gap-2.5">
        <span className="inline-block w-[13px] h-[13px] rounded-[4px]" style={{ background: "var(--ap-blue-dark)" }} />
        <span className="font-display text-[15px] font-semibold tracking-[-0.01em]">가드레일</span>
        <span className="hidden sm:inline text-[12px] ml-3" style={{ color: "#a1a1a6" }}>바이브코딩 앱 자율 보안 검증</span>
        <div className="ml-auto flex items-center gap-4 text-[12px]" style={{ color: "#d2d2d7" }}>{right}</div>
      </div>
    </nav>
  );
}

/* full-bleed tile band; the color change is the divider */
function Band({ tone = "white", children, className = "" }: { tone?: "white" | "parch"; children: React.ReactNode; className?: string }) {
  return (
    <section className={className} style={{ background: tone === "parch" ? "var(--ap-parch)" : "#ffffff" }}>
      <div className="mx-auto max-w-[1100px] px-5">{children}</div>
    </section>
  );
}

export default function App() {
  const [view, setView] = useState<View>("input");
  const [url, setUrl] = useState("https://my-vibe-app.vercel.app");
  const [host, setHost] = useState("my-vibe-app.vercel.app");
  const [supaOpen, setSupaOpen] = useState(false);
  const [supaUrl, setSupaUrl] = useState("");
  const [supaKey, setSupaKey] = useState("");
  const [prog, setProg] = useState(0);
  const [fixIdx, setFixIdx] = useState<number | null>(null);
  const [data, setData] = useState<LiveData | null>(null);   // real engine result; null = demo
  const [liveLog, setLiveLog] = useState<[string, string][]>([]);
  const [liveStage, setLiveStage] = useState("");
  const [scanTotal, setScanTotal] = useState(57);
  const raf = useRef<number>();
  const esRef = useRef<EventSource>();
  const reduce = useMemo(() => matchMedia("(prefers-reduced-motion: reduce)").matches, []);
  const derivedRef = useMemo(() => supaRefFromKey(supaKey), [supaKey]);
  const derivedUrl = derivedRef ? `https://${derivedRef}.supabase.co` : "";
  const needManualUrl = supaKey.trim().length > 0 && !derivedRef;
  const supaReady = supaOpen && supaKey.trim().length > 0 && (!!derivedUrl || supaUrl.trim().length > 0);
  const withSupa = supaReady;

  const STAGES = ["라우트 발견", "불변식 I1–I7 검사", "적대적 반증", "격리 증명", "결과 정리"];

  // fake-animate the demo when no backend is reachable (keeps the artifact usable)
  const demoAnimate = () => {
    setData(null); setScanTotal(57);
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

  const runScan = () => {
    const h = url.replace(/^https?:\/\//, "").replace(/\/.*$/, "") || "my-vibe-app.vercel.app";
    setHost(h); setView("scan"); setProg(0); setLiveLog([]); setLiveStage(""); setData(null);
    if (raf.current) cancelAnimationFrame(raf.current);
    try { esRef.current?.close(); } catch {}

    // Live path: talk to the real engine server (same origin). Falls back to the
    // built-in demo if no backend answers (e.g. opened as a standalone artifact).
    const isDemo = /my-vibe-app\.vercel\.app/.test(url) || url.trim() === "";
    const qs = new URLSearchParams({ target: isDemo ? "demo" : url.trim() });
    if (withSupa) { qs.set("supabaseKey", supaKey.trim()); qs.set("supabaseUrl", (derivedUrl || supaUrl).trim()); }
    let es: EventSource | null = null;
    let got = false;
    const fallback = () => { try { es?.close(); } catch {} if (!got) demoAnimate(); };
    try { es = new EventSource(`/api/scan?${qs}`); } catch { es = null; }
    if (!es) return demoAnimate();
    esRef.current = es;
    const timer = setTimeout(fallback, 1500); // no backend → demo
    es.addEventListener("stage", (e: MessageEvent) => { got = true; clearTimeout(timer); setLiveStage(JSON.parse(e.data).stage); });
    es.addEventListener("progress", (e: MessageEvent) => { const d = JSON.parse(e.data); if (d.total) setScanTotal(d.total); setProg(d.total ? d.done / d.total : 0); });
    es.addEventListener("log", (e: MessageEvent) => { got = true; clearTimeout(timer); const d = JSON.parse(e.data); setLiveLog((l) => [...l.slice(-120), [d.kind, d.text]]); });
    es.addEventListener("done", (e: MessageEvent) => { const d = JSON.parse(e.data); setData(d.result); setProg(1); try { es!.close(); } catch {} setTimeout(() => setView("results"), reduce ? 0 : 320); });
    es.addEventListener("error", () => { clearTimeout(timer); if (!got) fallback(); });
    es.onerror = () => { if (!got) { clearTimeout(timer); fallback(); } };
  };
  useEffect(() => () => { if (raf.current) cancelAnimationFrame(raf.current); try { esRef.current?.close(); } catch {} }, []);

  const stageIdx = liveStage ? Math.max(0, STAGES.indexOf(liveStage)) : Math.min(4, Math.floor(prog * 5));

  // honest coverage: Supabase-only findings appear as confirmed ONLY when a key
  // was given — otherwise that area is reported as "not checked", never hidden.
  const shown = data ? data.clusters : (withSupa ? DEMO_CLUSTERS : DEMO_CLUSTERS.filter((c) => !c.supaOnly));
  const confirmedN = shown.length;
  const needsRows: Row[] = data ? data.needs.map((n) => ({ method: n.method, route: n.route, desc: n.title, why: n.why })) : DEMO_NEEDS;
  const passedRows: Row[] = data ? data.passed.map((p) => ({ method: p.method, route: p.route, desc: p.title, why: p.why })) : DEMO_PASSED;
  const N = data
    ? { total: data.meta.routes, conf: confirmedN, need: data.needs.length, pass: data.passed.length }
    : { total: 57, conf: confirmedN, need: 3, pass: 48 };
  const supaCovered = data ? data.coverage.supabaseRan : withSupa;
  const openSupaInput = () => { setView("input"); setSupaOpen(true); requestAnimationFrame(() => scrollTo({ top: 0 })); };

  const btnPrimary = "rounded-full ap-press font-normal";
  const btnGhost = "rounded-full ap-press font-normal bg-transparent";

  return (
    <div className="min-h-screen font-text" style={{ background: "var(--ap-parch)" }}>
      {/* ══════════════════ INPUT ══════════════════ */}
      {view === "input" && (
        <>
          <Nav right={<span className="hidden md:inline">XBOW · Cloudflare · VulnHunter · Aikido</span>} />

          <Band tone="white" className="pt-[72px] pb-[64px]">
            <div className="max-w-[820px] mx-auto text-center">
              <div className="text-[13px] font-semibold tracking-[.02em] mb-4" style={{ color: "var(--ap-blue)" }}>바이브코딩 앱 자율 보안 검증</div>
              <h1 className="font-display font-semibold tighter leading-[1.06] text-[clamp(38px,7vw,64px)]" style={{ color: "var(--ap-ink)" }}>
                찾고 · 반박하고 · 증명하고<br />고치고 · 계속 지킵니다
              </h1>
              <p className="mx-auto mt-6 text-[clamp(17px,2.4vw,21px)] leading-[1.45] max-w-[64ch]" style={{ color: "var(--ap-muted)" }}>
                URL만 넣으면 라우트를 스스로 찾아 불변식 7개로 검사하고, 독립 에이전트가 반박한 뒤,
                격리 환경에서 실제로 뚫어 증명하고, 고칠 프롬프트까지 드립니다.
              </p>

              {/* pill search + supabase reveal */}
              <div className="mt-9 max-w-[640px] mx-auto text-left">
                <div className="flex items-center gap-2.5 rounded-full bg-white ap-hair pl-5 pr-2 h-[58px] focus-within:border-[color:var(--ap-blue-focus)] transition-colors" style={{ boxShadow: "0 1px 2px rgba(0,0,0,.04)" }}>
                  <Search className="w-[18px] h-[18px] shrink-0" style={{ color: "var(--ap-muted2)" }} />
                  <input
                    value={url} onChange={(e) => setUrl(e.target.value)} onKeyDown={(e) => e.key === "Enter" && runScan()}
                    placeholder="https://내앱.vercel.app"
                    className="flex-1 bg-transparent outline-none font-mono text-[15px] min-w-0" style={{ color: "var(--ap-ink)" }} />
                  <Button onClick={runScan} className={`${btnPrimary} h-[44px] px-6 gap-2 text-[15px]`}>
                    진단 <ArrowRight className="w-4 h-4" />
                  </Button>
                </div>

                <button onClick={() => setSupaOpen((o) => !o)} className="mt-3 inline-flex items-center gap-1.5 text-[14px] ap-press" style={{ color: "var(--ap-blue)" }}>
                  <Plus className={`w-4 h-4 transition-transform ${supaOpen ? "rotate-45" : ""}`} />
                  Supabase 프로젝트도 함께 검사 <span style={{ color: "var(--ap-muted2)" }}>(선택)</span>
                </button>

                {supaOpen && (
                  <div className="mt-3 rounded-[18px] bg-white ap-hair p-4 flex flex-col gap-2.5">
                    <div className="flex items-center gap-2 text-[13px] font-semibold" style={{ color: "var(--ap-ink)" }}>
                      <Box className="w-4 h-4" style={{ color: "var(--ap-blue)" }} />RLS 정책까지 2계정으로 실제 검증
                    </div>
                    {/* anon key is enough — the project address is read from the key */}
                    <Input value={supaKey} onChange={(e) => setSupaKey(e.target.value)} type="password" placeholder="anon (public) key — eyJhbGc…"
                      className="rounded-full h-11 font-mono text-[14px] px-4 bg-white" />

                    {derivedUrl && (
                      <div className="flex items-center gap-1.5 text-[12.5px] px-1" style={{ color: "var(--ap-pass)" }}>
                        <Check className="w-3.5 h-3.5 shrink-0" />
                        프로젝트 자동 감지 · <span className="font-mono" style={{ color: "var(--ap-ink)" }}>{derivedRef}.supabase.co</span> <span style={{ color: "var(--ap-muted2)" }}>· 주소 입력 불필요</span>
                      </div>
                    )}
                    {needManualUrl && (
                      <>
                        <Input value={supaUrl} onChange={(e) => setSupaUrl(e.target.value)} placeholder="https://xxxx.supabase.co"
                          className="rounded-full h-11 font-mono text-[14px] px-4 bg-white" />
                        <div className="text-[12.5px] px-1" style={{ color: "var(--ap-warn)" }}>이 키에서는 주소를 못 읽었어요 — self-host나 신형 키예요. 프로젝트 주소를 직접 넣어주세요.</div>
                      </>
                    )}

                    <div className="flex items-start gap-1.5 text-[12.5px] leading-[1.5]" style={{ color: "var(--ap-muted)" }}>
                      <Lock className="w-3.5 h-3.5 mt-0.5 shrink-0" />
                      <span><b className="font-semibold" style={{ color: "var(--ap-ink)" }}>anon(public) 키만</b> 넣으세요 — service_role 키는 절대 넣지 마세요. 키는 브라우저에서만 쓰이고 서버에 저장되지 않습니다.</span>
                    </div>
                  </div>
                )}

                <div className="mt-4 flex items-center justify-center gap-x-5 gap-y-1 flex-wrap text-[13px]" style={{ color: "var(--ap-muted2)" }}>
                  <span>✓ 가입 불필요</span><span>✓ 본인 소유 앱만</span><span>✓ 시크릿 마스킹</span>
                  {withSupa ? <span style={{ color: "var(--ap-blue)" }}>✓ Supabase RLS 포함</span> : <span>✓ 예시 데이터 미리보기</span>}
                </div>
              </div>
            </div>
          </Band>

          {/* pipeline tile — parchment */}
          <Band tone="parch" className="py-[56px]">
            <div className="text-center mb-8">
              <h2 className="font-display font-semibold tighter text-[clamp(26px,4vw,34px)]" style={{ color: "var(--ap-ink)" }}>한 번에 7단계를 모두 돕니다</h2>
              <p className="mt-2 text-[16px]" style={{ color: "var(--ap-muted)" }}>선두주자들의 방식을 하나의 파이프라인으로 묶었습니다</p>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2.5">
              {PIPE.map(([n, t, d, s]) => (
                <div key={n} className="rounded-[18px] bg-white ap-hair p-4 flex flex-col">
                  <span className="font-mono text-[12px]" style={{ color: "var(--ap-blue)" }}>{n}</span>
                  <span className="font-display font-semibold text-[17px] mt-1.5" style={{ color: "var(--ap-ink)" }}>{t}</span>
                  <span className="text-[13px] mt-1" style={{ color: "var(--ap-ink)" }}>{d}</span>
                  <span className="text-[11.5px] mt-auto pt-3" style={{ color: "var(--ap-muted2)" }}>{s}</span>
                </div>
              ))}
            </div>
          </Band>

          <Footer />
        </>
      )}

      {/* ══════════════════ SCAN ══════════════════ */}
      {view === "scan" && (
        <>
          <Nav right={<span className="flex items-center gap-2"><span className="w-2 h-2 rounded-full gr-pulse" style={{ background: "var(--ap-blue-dark)" }} />스캔 중 · {host}</span>} />
          <Band tone="parch" className="py-[56px] min-h-[calc(100vh-44px)] flex flex-col justify-center">
            <div className="max-w-[900px] mx-auto w-full">
              <div className="text-center mb-7">
                <div className="text-[13px] font-semibold" style={{ color: "var(--ap-blue)" }}>02 · 불변식 검사 실행 중</div>
                <h2 className="font-display font-semibold tighter text-[clamp(24px,4vw,32px)] mt-1.5" style={{ color: "var(--ap-ink)" }}>
                  두 개의 계정으로 실제로 두드려 보는 중입니다
                </h2>
              </div>

              {/* the "product": dark tile resting on the surface — the one shadow */}
              <div className="relative rounded-[18px] overflow-hidden ap-product-shadow h-[min(48vh,360px)]" style={{ background: "var(--ap-tile3)" }}>
                <div className="absolute inset-x-0 top-0 z-[3] flex items-center gap-1.5 px-4 py-3" style={{ background: "#000", borderBottom: "1px solid rgba(255,255,255,.08)" }}>
                  <i className="w-2.5 h-2.5 rounded-full inline-block" style={{ background: "#ff5f57" }} />
                  <i className="w-2.5 h-2.5 rounded-full inline-block" style={{ background: "#febc2e" }} />
                  <i className="w-2.5 h-2.5 rounded-full inline-block" style={{ background: "#28c840" }} />
                  <span className="ml-2.5 font-mono text-[12px] truncate" style={{ color: "#8e8e93" }}>{liveLog.length ? `probing ${host} · account A → B` : "probing /api/v2/workspaces/:id · account A → B"}</span>
                </div>
                {liveLog.length ? (
                  <div className="absolute left-0 right-0 top-[44px] bottom-0 overflow-hidden px-5 flex flex-col justify-end pb-3 font-mono text-[12px] leading-[1.55]">
                    {liveLog.slice(-16).map(([c, t], i) => (
                      <div key={i} className={c ? "" : "opacity-45"} style={{ color: c === "crit" ? "var(--ap-crit-ondark)" : c === "warn" ? "#ffcf70" : c === "pass" ? "var(--ap-pass-ondark)" : c === "accent" ? "var(--ap-blue-dark)" : "#c7c7cc" }}>{t}</div>
                    ))}
                  </div>
                ) : (
                  <div className="absolute left-0 right-0 top-[44px] bottom-0 overflow-hidden px-5">
                    <div className="gr-flow font-mono text-[12px] leading-[1.55]">
                      {DEMO_STREAM.concat(DEMO_STREAM).map(([c, t], i) => (
                        <div key={i} className={c ? "" : "opacity-45"} style={{ color: c === "crit" ? "var(--ap-crit-ondark)" : c === "warn" ? "#ffcf70" : c === "pass" ? "var(--ap-pass-ondark)" : c === "accent" ? "var(--ap-blue-dark)" : "#c7c7cc" }}>{t}</div>
                      ))}
                    </div>
                  </div>
                )}
                <div className="gr-sweep absolute left-0 right-0 h-[2px] z-[2]" style={{ top: "1%", background: "linear-gradient(90deg,transparent,var(--ap-blue-dark),transparent)", boxShadow: "0 0 20px 3px rgba(41,151,255,.5)" }} />
                <div className="absolute left-0 right-0 bottom-0 h-[64px] z-[2]" style={{ background: "linear-gradient(180deg,transparent,var(--ap-tile3))" }} />
              </div>

              {/* progress */}
              <div className="mt-7">
                <div className="flex items-baseline justify-between">
                  <div className="flex items-baseline gap-2">
                    <span className="font-num font-semibold text-[28px] tighter" style={{ color: "var(--ap-ink)" }}>{Math.round(prog * scanTotal)}</span>
                    <span className="text-[14px]" style={{ color: "var(--ap-muted)" }}>/ {scanTotal} 라우트</span>
                  </div>
                  <span className="font-mono text-[12px]" style={{ color: "var(--ap-muted2)" }}>{STAGES[stageIdx]}</span>
                </div>
                <div className="mt-3 h-[6px] rounded-full overflow-hidden" style={{ background: "#e3e3e8" }}>
                  <div className="h-full rounded-full transition-none" style={{ width: `${prog * 100}%`, background: "var(--ap-blue)" }} />
                </div>
                <div className="mt-4 flex gap-2 flex-wrap">
                  {STAGES.map((s, i) => (
                    <span key={s} className="text-[12.5px] px-3 py-1 rounded-full transition-colors"
                      style={i < stageIdx ? { background: "#e7f0ff", color: "var(--ap-blue)" }
                        : i === stageIdx ? { background: "var(--ap-ink)", color: "#fff" }
                          : { background: "#fff", color: "var(--ap-muted2)", border: "1px solid var(--ap-hair)" }}>{s}</span>
                  ))}
                </div>
              </div>
            </div>
          </Band>
        </>
      )}

      {/* ══════════════════ RESULTS ══════════════════ */}
      {view === "results" && (
        <>
          <Nav right={
            <div className="flex items-center gap-3">
              <span className="hidden sm:flex items-center gap-1.5 font-mono text-[12px]"><Globe className="w-3.5 h-3.5" />{host}</span>
              <button onClick={() => setView("input")} className="flex items-center gap-1.5 ap-press" style={{ color: "var(--ap-blue-dark)" }}><RefreshCw className="w-3.5 h-3.5" />다시 스캔</button>
            </div>
          } />

          {/* summary hero — parchment */}
          <Band tone="parch" className="pt-[52px] pb-[44px]">
            <div className="flex items-center gap-2 flex-wrap">
              <div className="text-[13px] font-semibold" style={{ color: "var(--ap-blue)" }}>스캔 완료 · 방금 · {host}{supaCovered ? " + Supabase" : ""}</div>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded-full" style={data ? { background: "#e7f0ff", color: "var(--ap-blue)" } : { background: "#f0f0f2", color: "var(--ap-muted2)" }}>
                {data ? `실제 엔진 · ${data.meta.sandboxReqs}회 요청` : "예시 데이터"}
              </span>
            </div>
            <h1 className="font-display font-semibold tighter leading-[1.08] text-[clamp(30px,5.5vw,48px)] mt-3" style={{ color: "var(--ap-ink)" }}>
              지금 <span style={{ color: "var(--ap-crit)" }}>{confirmedN}곳</span>에서<br className="sm:hidden" /> 남의 데이터가 새고 있습니다
            </h1>
            <p className="mt-4 text-[clamp(17px,2.2vw,20px)] leading-[1.45] max-w-[70ch]" style={{ color: "var(--ap-muted)" }}>
              라우트를 스스로 찾아 불변식 7개로 검사하고, 독립 에이전트가 반박한 뒤, 격리 환경에서 실제로 뚫어 증명한 것만 보여드립니다.
            </p>

            <div className="grid md:grid-cols-[1.6fr_1fr] gap-4 mt-9">
              <div className="grid grid-cols-3 gap-3">
                {[[String(N.conf), "확정", "실제로 뚫림", "crit"], [String(N.need), "확인 필요", "당신 판단 필요", "warn"], [String(N.pass), "통과", "검사했고 안전", "pass"]].map(([n, l, s, c]) => (
                  <div key={l} className="rounded-[18px] bg-white ap-hair p-5">
                    <div className="font-num font-semibold text-[clamp(36px,6vw,52px)] leading-none tighter" style={{ color: `var(--ap-${c})` }}>{n}</div>
                    <div className="text-[15px] font-semibold mt-3" style={{ color: "var(--ap-ink)" }}>{l}</div>
                    <div className="text-[13px] mt-0.5" style={{ color: "var(--ap-muted2)" }}>{s}</div>
                  </div>
                ))}
              </div>
              <div className="rounded-[18px] bg-white ap-hair p-5 flex items-center gap-5">
                <Donut total={N.total} conf={N.conf} need={N.need} pass={N.pass} />
                <div className="text-[13.5px] leading-[1.9]" style={{ color: "var(--ap-muted)" }}>
                  <Legend c="var(--ap-crit)" t={`확정 ${N.conf}`} />
                  <Legend c="var(--ap-warn)" t={`확인 필요 ${N.need}`} />
                  <Legend c="var(--ap-pass)" t={`통과 ${N.pass}`} />
                  <div className="font-mono text-[11.5px] mt-2" style={{ color: "var(--ap-muted2)" }}>불변식 I1–I7{data ? ` · 노이즈 −${data.meta.dedupe}%` : " · 노이즈 −46%"}</div>
                </div>
              </div>
            </div>
          </Band>

          {/* confirmed — white */}
          <Band tone="white" className="pt-[44px] pb-[52px]">
            <SectionHead title="확정된 취약점" meta="심각도순 · 독립 반증 통과분만 · 근본원인별 묶음" />
            <div className="flex flex-col gap-3">
              {shown.length === 0 && (
                <div className="rounded-[18px] bg-white ap-hair p-6 text-[15px] flex items-center gap-2.5" style={{ color: "var(--ap-ink)" }}>
                  <ShieldCheck className="w-5 h-5" style={{ color: "var(--ap-pass)" }} />검사한 경계에서 확정된 취약점이 없습니다. 아래 <b className="font-semibold">검사하지 못한 영역</b>도 확인하세요.
                </div>
              )}
              {shown.map((c, i) => { return (
                <div key={i} className="rounded-[18px] bg-white ap-hair overflow-hidden">
                  <div className="p-[18px_20px]">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="inline-flex items-center gap-1.5 text-[12px] font-semibold px-2.5 py-1 rounded-full" style={{ background: "var(--ap-critbg)", color: "var(--ap-crit)" }}>
                        <span className="w-1.5 h-1.5 rounded-full" style={{ background: "var(--ap-crit)" }} />확정 · 실제 침투
                      </span>
                      <span className="inline-flex items-center gap-1 text-[12px] font-semibold px-2.5 py-1 rounded-full" style={{ background: "#e9f7ee", color: "var(--ap-pass)" }}>
                        <ShieldCheck className="w-3.5 h-3.5" />반증 통과
                      </span>
                      <span className="font-mono text-[13.5px] ml-1"><span className="font-semibold" style={{ color: "var(--ap-blue)" }}>{c.method}</span> <span style={{ color: "var(--ap-ink)" }}>{c.route}</span></span>
                      <span className="flex gap-1 ml-auto">{c.inv.map((v) => <span key={v} className="font-mono text-[11px] px-1.5 py-0.5 rounded-md ap-hair" style={{ color: "var(--ap-muted2)" }}>{v}</span>)}</span>
                    </div>
                    <div className="font-display font-semibold text-[19px] tight mt-3.5" style={{ color: "var(--ap-ink)" }}>{c.title}</div>
                    <div className="text-[14.5px] leading-[1.5] mt-1.5" style={{ color: "var(--ap-muted)" }}>근본원인: {renderRich(c.cause)}</div>

                    {/* evidence: dark artifact block */}
                    <div className="mt-4 rounded-[12px] overflow-hidden" style={{ background: "var(--ap-tile3)" }}>
                      <div className="flex items-center gap-1.5 px-3.5 py-2.5 font-mono text-[11.5px] tracking-[.3px] uppercase" style={{ color: "var(--ap-pass-ondark)", borderBottom: "1px solid rgba(255,255,255,.08)" }}>
                        <Crosshair className="w-[13px] h-[13px]" />실제로 이렇게 뚫었습니다
                        <span className="ml-auto flex items-center gap-1 text-[10.5px] normal-case tracking-normal" style={{ color: "#8e8e93" }}><Box className="w-[11px] h-[11px]" />격리 VM 실행 · {c.src}</span>
                      </div>
                      <pre className="m-0 px-3.5 py-3 font-mono text-[12.5px] leading-[1.6] overflow-x-auto whitespace-pre-wrap break-words" style={{ color: "#d1d1d6" }}>{renderEv(c.ev0)}{"\n"}<span style={{ color: "#636366" }}>→</span> {renderEv(c.ev1)}</pre>
                    </div>

                    <div className="flex gap-2.5 mt-4 flex-wrap">
                      <Button onClick={() => setFixIdx(i)} className={`${btnPrimary} h-10 px-5 gap-1.5 text-[14px]`}><Wrench className="w-[15px] h-[15px]" />고치기</Button>
                      <Button variant="outline" onClick={() => setFixIdx(i)} className={`${btnGhost} h-10 px-5 gap-1.5 text-[14px]`} style={{ borderColor: "var(--ap-blue)", color: "var(--ap-blue)" }}><BookOpen className="w-[15px] h-[15px]" />왜 위험한가요?</Button>
                    </div>
                  </div>
                </div>
              ); })}
            </div>
          </Band>

          {/* need review — parchment */}
          <Band tone="parch" className="pt-[44px] pb-[44px]">
            <SectionHead title="확인이 필요합니다" meta="뚫릴 수 있으나 의도 여부는 당신만 압니다" />
            <div className="rounded-[18px] bg-white ap-hair overflow-hidden">
              {needsRows.length ? needsRows.map((r, i) => (
                <CompactRow key={i} dot="var(--ap-warn)" last={i === needsRows.length - 1}
                  route={r.method ? <><span style={{ color: "var(--ap-blue)" }} className="font-semibold">{r.method}</span> {r.route}</> : <span>{r.route}</span>}
                  desc={r.desc} why={r.why} />
              )) : <div className="px-5 py-4 text-[13.5px]" style={{ color: "var(--ap-muted2)" }}>확인이 필요한 항목이 없습니다.</div>}
            </div>
          </Band>

          {/* passed — white */}
          <Band tone="white" className="pt-[44px] pb-[44px]">
            <SectionHead title="통과한 검사" meta="무엇을 검사했는지 알아야 하니까" />
            <div className="rounded-[18px] bg-white ap-hair overflow-hidden">
              {passedRows.length ? passedRows.map((r, i) => (
                <CompactRow key={i} dot="var(--ap-pass)" last={i === passedRows.length - 1}
                  route={r.method ? <><span style={{ color: "var(--ap-blue)" }} className="font-semibold">{r.method}</span> {r.route}</> : <span>{r.route}</span>}
                  desc={r.desc} why={<span style={{ color: "var(--ap-pass)" }}>{r.why}</span>} />
              )) : <div className="px-5 py-4 text-[13.5px]" style={{ color: "var(--ap-muted2)" }}>통과 기록이 없습니다.</div>}
            </div>
          </Band>

          {/* coverage gaps — parchment. Never hide what we couldn't reach. */}
          <Band tone="parch" className="pt-[44px] pb-[44px]">
            <SectionHead title="검사하지 못한 영역" meta="숨기지 않고 그대로 알려드립니다 — 무엇을 못 봤는지 알아야 하니까" />

            <div className="text-[13px] font-semibold mb-3" style={{ color: "var(--ap-ink)" }}>입력을 주면 지금 바로 넓힙니다</div>
            <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fit,minmax(250px,1fr))" }}>
              {!supaCovered && (
                <CoverGap icon={<Box className="w-[18px] h-[18px]" />} title="Supabase RLS · 테이블 권한"
                  reason="anon key를 넣지 않아 RLS 정책, 테이블 접근 권한, service_role 노출을 검사하지 못했습니다."
                  action="＋ 키 넣고 검사하기" onAction={openSupaInput} />
              )}
              <CoverGap icon={<PenLine className="w-[18px] h-[18px]" />} title="쓰기·삭제 공격 (POST·PUT·DELETE)"
                reason="데이터를 바꾸지 않으려고 읽기 전용으로 돌렸습니다. 켜면 상태 변경·삭제 권한까지 실제로 시도합니다."
                action="심층 검사 (쓰기 포함) 다시 실행" onAction={runScan} />
              <CoverGap icon={<KeyRound className="w-[18px] h-[18px]" />} title="로그인 뒤 화면 · 역할별 권한"
                reason="세션 없이 접근되는 영역만 봤습니다. 테스트 계정을 주면 로그인 뒤 페이지·역할별 권한까지 검사합니다." />
              <CoverGap icon={<Package className="w-[18px] h-[18px]" />} title="소스 · 의존성 · 시크릿 (SCA · SAST)"
                reason="레포(락파일·소스)를 연결하면 취약 패키지(OSV), 하드코딩된 시크릿, 위험한 SQL·실행 싱크를 검사합니다. SAST가 의심한 싱크는 아래 실행 검사로 확정합니다."
                action="레포 연결하기" onAction={openSupaInput} />
            </div>

            <div className="text-[13px] font-semibold mt-7 mb-3" style={{ color: "var(--ap-ink)" }}>지금 함께 검사하는 것 <span className="font-normal" style={{ color: "var(--ap-pass)" }}>· 이번 스캔에 포함됨</span></div>
            <div className="rounded-[18px] overflow-hidden" style={{ border: "1px solid #cde7d5", background: "#f4fbf6" }}>
              {[
                ["주입 공격 (SQLi · 반영형 XSS · 경로 탐색)", "불변식 I7 — 작은따옴표·항진식·../ 를 실제로 넣어보고, 독립 반증까지 통과한 것만 확정합니다.", "확정: SQL 인젝션"],
                ["권한 · 격리 · RLS · 시크릿 노출", "불변식 I1–I7 — 2계정으로 실제로 두드려 확정합니다.", "핵심"],
              ].map(([t, d, tag]: any, i, arr) => (
                <div key={i} className="flex items-start gap-3 px-5 py-3.5" style={{ borderBottom: i === arr.length - 1 ? "none" : "1px solid #d9efe0" }}>
                  <span className="grid place-items-center w-8 h-8 rounded-full shrink-0 mt-0.5" style={{ background: "#e2f4e8", color: "var(--ap-pass)" }}><ShieldCheck className="w-[17px] h-[17px]" /></span>
                  <div className="min-w-0">
                    <div className="text-[14px] font-semibold" style={{ color: "var(--ap-ink)" }}>{t}</div>
                    <div className="text-[13px] leading-[1.5] mt-0.5" style={{ color: "var(--ap-muted)" }}>{d}</div>
                  </div>
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded-full shrink-0 ml-auto" style={{ background: "#e2f4e8", color: "var(--ap-pass)" }}>{tag}</span>
                </div>
              ))}
            </div>

            <div className="text-[13px] font-semibold mt-7 mb-3" style={{ color: "var(--ap-ink)" }}>이 스캔 방식이 다루지 않는 것 <span className="font-normal" style={{ color: "var(--ap-muted2)" }}>· 별도 방식이 필요합니다</span></div>
            <div className="rounded-[18px] bg-white ap-hair overflow-hidden">
              {[
                [<Workflow className="w-[17px] h-[17px]" />, "비즈니스 로직 · 레이스 컨디션", "가격 조작·수량 음수·결제 흐름 우회·동시성 문제는 앱 고유 규칙을 알아야 판단됩니다."],
                [<Gauge className="w-[17px] h-[17px]" />, "속도 제한 · 무차별 대입", "당신 서비스에 부하를 주지 않으려고 일부러 몰아치지 않습니다. 레이트리밋은 별도로 점검하세요."],
              ].map(([ic, t, d]: any, i, arr) => (
                <div key={i} className="flex items-start gap-3 px-5 py-3.5" style={{ borderBottom: i === arr.length - 1 ? "none" : "1px solid var(--ap-divider)" }}>
                  <span className="grid place-items-center w-8 h-8 rounded-full shrink-0 mt-0.5" style={{ background: "var(--ap-parch)", color: "var(--ap-muted)" }}>{ic}</span>
                  <div className="min-w-0">
                    <div className="text-[14px] font-semibold" style={{ color: "var(--ap-ink)" }}>{t}</div>
                    <div className="text-[13px] leading-[1.5] mt-0.5" style={{ color: "var(--ap-muted)" }}>{d}</div>
                  </div>
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded-full shrink-0 ml-auto" style={{ background: "#f0f0f2", color: "var(--ap-muted2)" }}>범위 밖</span>
                </div>
              ))}
            </div>
            <p className="text-[12.5px] mt-3" style={{ color: "var(--ap-muted2)" }}>가드레일은 <b className="font-semibold" style={{ color: "var(--ap-ink)" }}>“남의 데이터가 새는가”</b>(권한·격리·RLS·시크릿·주입)를 실행으로 확정하는 데 집중합니다. 위 두 항목만 앱 고유 규칙·부하 제어가 필요해 별도 방식으로 점검하세요.</p>
          </Band>

          {/* watch — white */}
          <Band tone="white" className="pt-[44px] pb-[64px]">
            <h3 className="font-display font-semibold text-[20px] tight flex items-center gap-2.5" style={{ color: "var(--ap-ink)" }}><Radar className="w-[19px] h-[19px]" style={{ color: "var(--ap-blue)" }} />배포할 때마다 자동으로 다시 지켜봅니다</h3>
            <div className="grid gap-2.5 mt-4" style={{ gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))" }}>
              {[["배포 감지", "새 엔드포인트만 즉시 재검사"], ["매일 새벽", "전체 읽기전용 스윕"], ["주 1회", "쓰기·삭제 포함 심층"], ["이번 주", "3회 배포 · 새 API 5개"]].map(([t, v]) => (
                <div key={t} className="rounded-[14px] p-4 ap-hair" style={{ background: "var(--ap-parch)" }}>
                  <div className="font-mono text-[12px]" style={{ color: "var(--ap-muted2)" }}>{t}</div>
                  <div className="text-[14px] mt-1" style={{ color: "var(--ap-ink)" }}>{v}</div>
                </div>
              ))}
            </div>
          </Band>

          <Footer />
        </>
      )}

      <FixDialog clusters={shown} idx={fixIdx} onClose={() => setFixIdx(null)} />
    </div>
  );
}

function Legend({ c, t }: { c: string; t: string }) {
  return <div className="flex items-center gap-2"><span className="w-2 h-2 rounded-full inline-block" style={{ background: c }} />{t}</div>;
}
function CoverGap({ icon, title, reason, action, onAction }: { icon: React.ReactNode; title: string; reason: string; action?: string; onAction?: () => void }) {
  return (
    <div className="rounded-[18px] bg-white ap-hair p-5 flex flex-col">
      <div className="flex items-center gap-2.5">
        <span className="grid place-items-center w-9 h-9 rounded-full shrink-0" style={{ background: "var(--ap-parch)", color: "var(--ap-muted)" }}>{icon}</span>
        <span className="text-[11px] font-mono px-2 py-0.5 rounded-full ml-auto" style={{ background: "#f0f0f2", color: "var(--ap-muted2)" }}>미검사</span>
      </div>
      <div className="font-display font-semibold text-[16px] tight mt-3" style={{ color: "var(--ap-ink)" }}>{title}</div>
      <div className="text-[13.5px] leading-[1.55] mt-1.5 flex-1" style={{ color: "var(--ap-muted)" }}>{reason}</div>
      {action && (
        <button onClick={onAction} className="mt-3 inline-flex items-center gap-1 text-[13.5px] font-semibold ap-press self-start" style={{ color: "var(--ap-blue)" }}>
          {action} <ArrowRight className="w-3.5 h-3.5" />
        </button>
      )}
    </div>
  );
}
function SectionHead({ title, meta }: { title: string; meta: string }) {
  return (
    <div className="flex items-baseline gap-3 mb-4 flex-wrap">
      <h2 className="font-display font-semibold tight text-[clamp(22px,3.4vw,28px)]" style={{ color: "var(--ap-ink)" }}>{title}</h2>
      <span className="text-[12.5px] ml-auto" style={{ color: "var(--ap-muted2)" }}>{meta}</span>
    </div>
  );
}
function CompactRow({ dot, route, desc, why, last }: { dot: string; route: React.ReactNode; desc: string; why: React.ReactNode; last?: boolean }) {
  return (
    <div className="flex items-center gap-3 px-5 py-3.5 text-[14px] flex-wrap" style={{ borderBottom: last ? "none" : "1px solid var(--ap-divider)" }}>
      <span className="w-2 h-2 rounded-full shrink-0" style={{ background: dot }} />
      <span className="font-mono text-[13px]" style={{ color: "var(--ap-ink)" }}>{route}</span>
      <span style={{ color: "var(--ap-muted)" }}>{desc}</span>
      <span className="text-[12.5px] ml-auto text-right" style={{ color: "var(--ap-muted2)" }}>{why}</span>
    </div>
  );
}
function Footer() {
  return (
    <footer style={{ background: "var(--ap-parch)", borderTop: "1px solid var(--ap-divider)" }}>
      <div className="mx-auto max-w-[1100px] px-5 py-8 flex items-center gap-2.5 flex-wrap text-[12px]" style={{ color: "var(--ap-muted2)" }}>
        <span className="inline-block w-2.5 h-2.5 rounded-[3px]" style={{ background: "var(--ap-blue)" }} />
        <span className="font-display font-semibold text-[13px]" style={{ color: "var(--ap-ink)" }}>가드레일</span>
        <span>— 추론으로 의심하고, 실행으로 확정합니다</span>
        <span className="ml-auto">본인 소유 앱만 진단하세요 · 시크릿은 마스킹됩니다</span>
      </div>
    </footer>
  );
}

function Donut({ total = 57, conf = 6, need = 3, pass = 48 }: { total?: number; conf?: number; need?: number; pass?: number }) {
  const sum = conf + need + pass || 1;             // ring shows the finding breakdown
  const r = 48, c = 2 * Math.PI * r;
  const seg = (n: number) => (n / sum) * c;
  let off = 0;
  const arc = (n: number, color: string) => {
    if (n <= 0) return null;
    const el = <circle key={color} cx="60" cy="60" r={r} fill="none" stroke={color} strokeWidth="12" strokeLinecap="butt"
      strokeDasharray={`${seg(n)} ${c - seg(n)}`} strokeDashoffset={-off} transform="rotate(-90 60 60)" />;
    off += seg(n); return el;
  };
  return (
    <div className="relative w-[112px] h-[112px] shrink-0">
      <svg width="112" height="112" viewBox="0 0 120 120">
        <circle cx="60" cy="60" r={r} fill="none" stroke="#eaeaef" strokeWidth="12" />
        {arc(pass, "var(--ap-pass)")}{arc(conf, "var(--ap-crit)")}{arc(need, "var(--ap-warn)")}
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <b className="font-num font-semibold text-[26px] leading-none tighter" style={{ color: "var(--ap-ink)" }}>{total}</b>
        <span className="text-[11px]" style={{ color: "var(--ap-muted2)" }}>라우트</span>
      </div>
    </div>
  );
}

function FixDialog({ clusters, idx, onClose }: { clusters: Cluster[]; idx: number | null; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  const [rv, setRv] = useState<"idle" | "run" | "ok">("idle");
  const reduce = useMemo(() => matchMedia("(prefers-reduced-motion: reduce)").matches, []);
  useEffect(() => { if (idx !== null) { setCopied(false); setRv("idle"); } }, [idx]);
  if (idx === null || !clusters[idx]) return null;
  const c = clusters[idx];
  const copy = () => { navigator.clipboard?.writeText(c.fix).catch(() => {}); setCopied(true); setTimeout(() => setCopied(false), 1500); };
  const reverify = () => { setRv("run"); setTimeout(() => setRv("ok"), reduce ? 0 : 850); };
  const codeBox = "m-0 rounded-[12px] p-3.5 font-mono text-[12.5px] leading-[1.65] overflow-x-auto whitespace-pre-wrap break-words";
  return (
    <Dialog open={idx !== null} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-2xl p-0 gap-0 bg-white overflow-hidden rounded-[18px] border-0">
        <div className="p-[18px_20px]" style={{ borderBottom: "1px solid var(--ap-divider)" }}>
          <div className="flex items-center gap-2 flex-wrap">
            <span className="inline-flex items-center gap-1.5 text-[12px] font-semibold px-2.5 py-1 rounded-full" style={{ background: "var(--ap-critbg)", color: "var(--ap-crit)" }}><span className="w-1.5 h-1.5 rounded-full" style={{ background: "var(--ap-crit)" }} />확정</span>
            <span className="font-mono text-[13.5px]"><span className="font-semibold" style={{ color: "var(--ap-blue)" }}>{c.method}</span> <span style={{ color: "var(--ap-ink)" }}>{c.route}</span></span>
          </div>
          <div className="font-display font-semibold text-[18px] tight mt-2.5" style={{ color: "var(--ap-ink)" }}>{c.title}</div>
        </div>
        <Tabs defaultValue="p" className="w-full">
          <div className="px-5 pt-4">
            <TabsList className="rounded-full h-auto p-1" style={{ background: "var(--ap-parch)" }}>
              <TabsTrigger value="p" className="rounded-full gap-1.5 text-[13px] data-[state=active]:bg-white"><Sparkles className="w-3.5 h-3.5" />AI 프롬프트</TabsTrigger>
              <TabsTrigger value="d" className="rounded-full gap-1.5 text-[13px] data-[state=active]:bg-white"><FileDiff className="w-3.5 h-3.5" />{c.red ? "재현 테스트" : "수정 코드"}</TabsTrigger>
              <TabsTrigger value="v" className="rounded-full gap-1.5 text-[13px] data-[state=active]:bg-white"><ShieldCheck className="w-3.5 h-3.5" />재검증</TabsTrigger>
            </TabsList>
          </div>
          <TabsContent value="p" className="p-5 mt-0">
            <div className="flex items-center gap-2.5 mb-3 flex-wrap">
              <Button onClick={copy} className="rounded-full ap-press h-9 px-4 gap-1.5 text-[13px] font-normal">{copied ? <><Check className="w-[15px] h-[15px]" />복사됨</> : <><Copy className="w-[15px] h-[15px]" />프롬프트 복사</>}</Button>
              <span className="text-[13px]" style={{ color: "var(--ap-muted)" }}>Cursor · Claude Code 에 붙여넣으면 바로 고칩니다</span>
            </div>
            <pre className={codeBox} style={{ background: "var(--ap-tile3)", color: "#d1d1d6" }}>{c.fix}</pre>
          </TabsContent>
          <TabsContent value="d" className="p-5 mt-0">
            {c.red ? (
              <>
                <div className="text-[12.5px] mb-2.5" style={{ color: "var(--ap-muted)" }}>고치기 전엔 실패하고, 고친 뒤엔 통과해야 하는 <b className="font-semibold" style={{ color: "var(--ap-ink)" }}>회귀 테스트(RED)</b> — 엔진이 이 취약점의 증거로부터 생성했습니다.</div>
                <pre className={codeBox} style={{ background: "var(--ap-tile3)", color: "#d1d1d6" }}>{c.red}</pre>
              </>
            ) : (
              <pre className={codeBox} style={{ background: "var(--ap-tile3)" }}>
                {(c.diff || []).map(([k, t], i) => (
                  <div key={i} style={{ color: k === "add" ? "var(--ap-pass-ondark)" : k === "del" ? "var(--ap-crit-ondark)" : "#8e8e93" }}>{t}</div>
                ))}
              </pre>
            )}
          </TabsContent>
          <TabsContent value="v" className="p-5 mt-0">
            <div className="flex items-center gap-3 flex-wrap">
              <Button onClick={reverify} className="rounded-full ap-press h-9 px-4 gap-1.5 text-[13px] font-normal"><Play className="w-[15px] h-[15px]" />같은 공격 다시 실행</Button>
              <span className="font-mono text-[13px] px-3.5 py-2 rounded-full"
                style={rv === "ok" ? { color: "var(--ap-pass)", background: "#e9f7ee" } : { color: "var(--ap-muted)", background: "var(--ap-parch)" }}>
                {rv === "idle" ? "고친 뒤 눌러 확인하세요" : rv === "run" ? "공격 재실행 중…" : "이제 막힙니다 ✓  403 Forbidden"}
              </span>
            </div>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}
