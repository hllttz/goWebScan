import React, { useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  AlertTriangle,
  Ban,
  Braces,
  Clock3,
  Crosshair,
  Gauge,
  Play,
  Radar,
  Server,
  ShieldCheck,
  SquareTerminal,
  Zap,
} from "lucide-react";
import "./styles.css";

type PortState = "open" | "closed" | "filtered" | "unreachable" | "unknown";
type RunStatus = "pending" | "running" | "completed" | "canceled" | "failed";

type ScanReport = { targets: HostResult[] };
type HostResult = {
  target: { input: string; hostname?: string; addresses: string[] };
  status: "up" | "down" | "unknown";
  reason?: string;
  ports: PortResult[];
  error?: string;
};
type PortResult = {
  port: { port: number; protocol: string };
  state: PortState;
  reason?: string;
  latency: number;
  error?: string;
  service?: { name?: string; product?: string; version?: string; confidence?: number; banner?: string };
};
type ScanRun = {
  id: string;
  status: RunStatus;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
  error?: string;
  summary: Summary;
  report: ScanReport;
};
type Summary = {
  hosts: number;
  ports: number;
  open: number;
  closed: number;
  filtered: number;
  unreachable: number;
  unknown: number;
};
type ScanEvent = { seq: number; type: string; host?: HostResult; data?: unknown };
type ScanRequest = {
  targets: string;
  ports: string;
  timeoutMs: number;
  hostWorkers: number;
  portWorkers: number;
  skipDiscovery: boolean;
  serviceVersion: boolean;
};

const defaultRequest: ScanRequest = {
  targets: "127.0.0.1",
  ports: "22,80,443,8080",
  timeoutMs: 500,
  hostWorkers: 8,
  portWorkers: 80,
  skipDiscovery: true,
  serviceVersion: false,
};

function App() {
  const [request, setRequest] = useState<ScanRequest>(defaultRequest);
  const [run, setRun] = useState<ScanRun | null>(null);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [rawJSON, setRawJSON] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const eventSourceRef = useRef<EventSource | null>(null);

  const summary = useMemo(() => summarize(report, run?.summary), [report, run]);
  const active = run?.status === "pending" || run?.status === "running";

  async function runScan() {
    closeStream();
    setLoading(true);
    setError("");
    setEvents([]);
    setReport({ targets: [] });
    try {
      const response = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(request),
      });
      const payload: ScanRun | { error?: string } = await response.json();
      if (!response.ok) {
        throw new Error("error" in payload ? payload.error || "扫描创建失败" : "扫描创建失败");
      }
      const created = payload as ScanRun;
      setRun(created);
      setReport(created.report);
      openStream(created.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "扫描创建失败");
      setLoading(false);
    }
  }

  async function cancelScan() {
    if (!run) return;
    try {
      await fetch(`/api/scans/${run.id}/cancel`, { method: "POST" });
      setRun({ ...run, status: "canceled" });
      addEvent({ seq: Date.now(), type: "cancel_requested" });
    } catch (err) {
      setError(err instanceof Error ? err.message : "取消失败");
    }
  }

  function openStream(id: string) {
    const source = new EventSource(`/api/scans/${id}/events`);
    eventSourceRef.current = source;

    source.onmessage = (message) => handleEventMessage(message.data, id);
    for (const eventName of ["created", "started", "host_result", "completed", "canceled", "failed", "cancel_requested"]) {
      source.addEventListener(eventName, (message) => handleEventMessage((message as MessageEvent).data, id));
    }
    source.onerror = () => {
      void refreshRun(id);
    };
  }

  function handleEventMessage(raw: string, id: string) {
    const event = JSON.parse(raw) as ScanEvent;
    addEvent(event);
    if (event.type === "host_result" && event.host) {
      setReport((current) => ({ targets: [...(current?.targets || []), event.host!] }));
    }
    if (["completed", "canceled", "failed"].includes(event.type)) {
      closeStream();
      setLoading(false);
      void refreshRun(id);
    }
    if (event.type === "started") {
      setRun((current) => (current ? { ...current, status: "running" } : current));
    }
  }

  async function refreshRun(id: string) {
    const response = await fetch(`/api/scans/${id}`);
    if (!response.ok) return;
    const latest = (await response.json()) as ScanRun;
    setRun(latest);
    setReport(latest.report);
    if (!["pending", "running"].includes(latest.status)) {
      setLoading(false);
      closeStream();
    }
  }

  function addEvent(event: ScanEvent) {
    setEvents((current) => [...current.slice(-199), event]);
  }

  function closeStream() {
    eventSourceRef.current?.close();
    eventSourceRef.current = null;
  }

  return (
    <main className="shell">
      <header className="hero-bar" aria-label="应用头部">
        <div className="hero-copy">
          <div className="brand">
            <Radar size={30} strokeWidth={1.8} />
            <span>GoScan 扫描控制台</span>
          </div>
          <p>基于任务队列、SSE 实时事件和 TCP Connect 的网络资产探测界面。</p>
        </div>
        <div className="hero-actions">
          <Badge icon={<ShieldCheck size={16} />} label="仅限授权扫描" />
          <Badge icon={<SquareTerminal size={16} />} label="API 127.0.0.1:8088" />
          <span className={`run-status ${run?.status || "idle"}`}>{statusText(run?.status)}</span>
        </div>
      </header>

      <section className="summary-grid" aria-label="扫描摘要">
        <Metric icon={<Server size={18} />} label="主机数" value={summary.hosts} />
        <Metric icon={<Gauge size={18} />} label="开放端口" value={summary.open} tone="good" />
        <Metric icon={<Clock3 size={18} />} label="过滤/不可达" value={summary.filtered + summary.unreachable} tone="warn" />
        <Metric icon={<Braces size={18} />} label="端口结果" value={summary.ports} />
      </section>

      <section className="workspace">
        <aside className="control-panel" aria-label="扫描参数">
          <div className="panel-heading">
            <div>
              <span className="eyebrow">扫描配置</span>
              <h1>任务参数</h1>
            </div>
            <Crosshair size={20} />
          </div>

          <label className="field">
            <span>目标地址</span>
            <textarea
              value={request.targets}
              rows={5}
              spellCheck={false}
              disabled={active}
              placeholder="支持 IP、域名、CIDR；多个目标可换行或逗号分隔"
              onChange={(event) => setRequest({ ...request, targets: event.target.value })}
            />
          </label>

          <label className="field">
            <span>端口范围</span>
            <input
              value={request.ports}
              spellCheck={false}
              disabled={active}
              placeholder="例如 22,80,443 或 1-1024"
              onChange={(event) => setRequest({ ...request, ports: event.target.value })}
            />
          </label>

          <div className="grid-two">
            <NumberField label="超时毫秒" value={request.timeoutMs} min={50} disabled={active} onChange={(value) => setRequest({ ...request, timeoutMs: value })} />
            <NumberField label="主机并发" value={request.hostWorkers} min={1} disabled={active} onChange={(value) => setRequest({ ...request, hostWorkers: value })} />
            <NumberField label="端口并发" value={request.portWorkers} min={1} disabled={active} onChange={(value) => setRequest({ ...request, portWorkers: value })} />
          </div>

          <div className="toggles">
            <Toggle checked={request.skipDiscovery} label="-Pn" description="跳过主机发现，直接扫描端口" disabled={active} onChange={(checked) => setRequest({ ...request, skipDiscovery: checked })} />
            <Toggle checked={request.serviceVersion} label="-sV" description="开启主动服务识别" disabled={active} onChange={(checked) => setRequest({ ...request, serviceVersion: checked })} />
          </div>

          <div className="button-row">
            <button className="run-button" disabled={active} onClick={runScan}>
              {loading ? <Activity size={18} className="spin" /> : <Play size={18} />}
              <span>{active ? "扫描中" : "开始扫描"}</span>
            </button>
            <button className="cancel-button" disabled={!active} onClick={cancelScan}>
              <Ban size={18} />
              <span>取消</span>
            </button>
          </div>

          {run && (
            <div className="run-card">
              <span>任务编号</span>
              <strong>{run.id}</strong>
              <small>创建时间：{formatTime(run.createdAt)}</small>
              {run.error && <small className="danger">{run.error}</small>}
            </div>
          )}

          {error && (
            <div className="error-box">
              <AlertTriangle size={18} />
              <span>{error}</span>
            </div>
          )}
        </aside>

        <section className="results" aria-label="扫描结果">
          <div className="result-toolbar">
            <div>
              <span className="eyebrow">实时结果</span>
              <h2>端口状态表</h2>
            </div>
            <button className="ghost-button" onClick={() => setRawJSON(!rawJSON)}>
              <Braces size={16} />
              <span>{rawJSON ? "表格视图" : "JSON 视图"}</span>
            </button>
          </div>

          {!report && !loading && <EmptyState />}
          {loading && (!report || report.targets.length === 0) && <LoadingState />}
          {report && rawJSON && <pre className="json-view">{JSON.stringify({ run, report }, null, 2)}</pre>}
          {report && !rawJSON && <ResultTable report={report} />}

          <EventLog events={events} />
        </section>
      </section>
    </main>
  );
}

function ResultTable({ report }: { report: ScanReport }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>主机</th>
            <th>端口</th>
            <th>状态</th>
            <th>依据</th>
            <th>服务</th>
            <th>延迟</th>
          </tr>
        </thead>
        <tbody>
          {report.targets.flatMap((host) =>
            host.ports.length === 0
              ? [
                  <tr key={`${host.target.input}-empty`}>
                    <td>{hostLabel(host)}</td>
                    <td>-</td>
                    <td>
                      <StatePill state="unknown" label={hostStatusText(host.status)} />
                    </td>
                    <td>{reasonText(host.reason)}</td>
                    <td>-</td>
                    <td>-</td>
                  </tr>,
                ]
              : host.ports.map((port) => (
                  <tr key={`${host.target.input}-${port.port.port}`}>
                    <td>{hostLabel(host)}</td>
                    <td>
                      {port.port.port}/{port.port.protocol}
                    </td>
                    <td>
                      <StatePill state={port.state} />
                    </td>
                    <td>{reasonText(port.reason)}</td>
                    <td>{serviceLabel(port)}</td>
                    <td>{formatLatency(port.latency)}</td>
                  </tr>
                )),
          )}
        </tbody>
      </table>
    </div>
  );
}

function EventLog({ events }: { events: ScanEvent[] }) {
  return (
    <section className="event-log">
      <div className="result-toolbar compact">
        <div>
          <span className="eyebrow">事件流</span>
          <h2>SSE 日志</h2>
        </div>
        <span className="event-count">{events.length} 条</span>
      </div>
      <div className="event-list">
        {events.length === 0 && <p>暂无事件。开始扫描后会实时显示任务状态、主机结果和结束事件。</p>}
        {events.map((event) => (
          <div className="event-row" key={`${event.seq}-${event.type}`}>
            <span>#{event.seq}</span>
            <strong>{eventText(event.type)}</strong>
            <code>{event.host ? hostLabel(event.host) : event.data ? JSON.stringify(event.data) : "系统事件"}</code>
          </div>
        ))}
      </div>
    </section>
  );
}

function NumberField({ label, value, min, disabled, onChange }: { label: string; value: number; min: number; disabled?: boolean; onChange: (value: number) => void }) {
  return (
    <label className="field">
      <span>{label}</span>
      <input type="number" min={min} value={value} disabled={disabled} onChange={(event) => onChange(Math.max(min, Number(event.target.value)))} />
    </label>
  );
}

function Toggle({ checked, label, description, disabled, onChange }: { checked: boolean; label: string; description: string; disabled?: boolean; onChange: (checked: boolean) => void }) {
  return (
    <label className={`toggle ${disabled ? "disabled" : ""}`}>
      <input type="checkbox" checked={checked} disabled={disabled} onChange={(event) => onChange(event.target.checked)} />
      <span className="switch" />
      <span>
        <strong>{label}</strong>
        <small>{description}</small>
      </span>
    </label>
  );
}

function Badge({ icon, label }: { icon: React.ReactNode; label: string }) {
  return (
    <span className="badge">
      {icon}
      {label}
    </span>
  );
}

function Metric({ icon, label, value, tone }: { icon: React.ReactNode; label: string; value: number; tone?: "good" | "warn" }) {
  return (
    <div className={`metric ${tone || ""}`}>
      <div className="metric-icon">{icon}</div>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function StatePill({ state, label }: { state: PortState; label?: string }) {
  return <span className={`state ${state}`}>{label || portStateText(state)}</span>;
}

function EmptyState() {
  return (
    <div className="empty">
      <Radar size={44} strokeWidth={1.4} />
      <h3>等待扫描任务</h3>
      <p>配置目标和端口后，点击“开始扫描”创建任务。</p>
    </div>
  );
}

function LoadingState() {
  return (
    <div className="empty">
      <Activity size={44} className="spin" />
      <h3>正在扫描</h3>
      <p>工作线程正在探测端口，结果会通过事件流实时到达。</p>
    </div>
  );
}

function summarize(report: ScanReport | null, serverSummary?: Summary) {
  if (serverSummary && (!report || report.targets.length === 0)) return serverSummary;
  const empty = { hosts: 0, ports: 0, open: 0, closed: 0, filtered: 0, unreachable: 0, unknown: 0 };
  if (!report) return empty;
  return report.targets.reduce((summary, host) => {
    summary.hosts += 1;
    for (const port of host.ports) {
      summary.ports += 1;
      summary[port.state] += 1;
    }
    return summary;
  }, empty);
}

function hostLabel(host: HostResult) {
  const address = host.target.addresses?.[0];
  return address ? `${host.target.input} (${address})` : host.target.input;
}

function serviceLabel(port: PortResult) {
  if (!port.service) return "-";
  return [port.service.name, port.service.product, port.service.version].filter(Boolean).join(" ") || "-";
}

function formatLatency(ns: number) {
  if (!Number.isFinite(ns)) return "-";
  if (ns < 1_000_000) return `${Math.round(ns / 1_000)} 微秒`;
  return `${(ns / 1_000_000).toFixed(1)} 毫秒`;
}

function formatTime(raw: string) {
  return new Date(raw).toLocaleString("zh-CN", { hour12: false });
}

function statusText(status?: RunStatus) {
  const map: Record<string, string> = {
    idle: "空闲",
    pending: "等待中",
    running: "扫描中",
    completed: "已完成",
    canceled: "已取消",
    failed: "失败",
  };
  return map[status || "idle"] || status || "空闲";
}

function hostStatusText(status: HostResult["status"]) {
  return { up: "在线", down: "离线", unknown: "未知" }[status];
}

function portStateText(state: PortState) {
  return { open: "开放", closed: "关闭", filtered: "过滤", unreachable: "不可达", unknown: "未知" }[state];
}

function reasonText(reason?: string) {
  if (!reason) return "-";
  const map: Record<string, string> = {
    connect_succeeded: "连接成功",
    connection_refused: "连接被拒绝",
    timeout: "连接超时",
    network_unreachable: "网络不可达",
    permission_denied: "权限不足",
    unclassified_error: "未分类错误",
    discovery_skipped: "已跳过发现",
    tcp_probe_connect_succeeded: "TCP 探测成功",
    tcp_probe_connection_refused: "TCP 探测被拒绝",
    tcp_probes_inconclusive: "TCP 探测无结论",
    tcp_probes_failed: "TCP 探测失败",
    no_address: "无可用地址",
  };
  return map[reason] || reason;
}

function eventText(type: string) {
  const map: Record<string, string> = {
    created: "任务创建",
    started: "任务开始",
    host_result: "主机结果",
    completed: "任务完成",
    canceled: "任务取消",
    failed: "任务失败",
    cancel_requested: "请求取消",
  };
  return map[type] || type;
}

createRoot(document.getElementById("root")!).render(<App />);
