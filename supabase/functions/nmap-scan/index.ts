import "jsr:@supabase/functions-js/edge-runtime.d.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

interface ScanRequest {
  target: string;
  ports?: number[];
  timeout?: number;
}

interface PortResult {
  port: number;
  state: "open" | "closed" | "filtered";
  service: string;
  latency_ms?: number;
}

// Common service names by port
const SERVICES: Record<number, string> = {
  21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
  80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
  139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
  993: "imaps", 995: "pop3s", 1433: "ms-sql-s", 1521: "oracle",
  3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql",
  5900: "vnc", 6379: "redis", 8080: "http-proxy", 8443: "https-alt",
  8888: "sun-answerbook", 9090: "zeus-admin", 27017: "mongodb",
};

const DEFAULT_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
  993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379,
  8080, 8443, 8888, 9090, 27017,
];

async function scanPort(
  hostname: string,
  port: number,
  timeoutMs: number
): Promise<PortResult> {
  const service = SERVICES[port] || "unknown";
  const start = performance.now();

  try {
    const conn = await Promise.race([
      Deno.connect({ hostname, port }),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("timeout")), timeoutMs)
      ),
    ]);

    const latency = Math.round(performance.now() - start);
    (conn as Deno.Conn).close();
    return { port, state: "open", service, latency_ms: latency };
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "";
    if (msg.includes("timeout")) {
      return { port, state: "filtered", service };
    }
    return { port, state: "closed", service };
  }
}

// Resolve hostname to IP
async function resolveHost(target: string): Promise<string> {
  // If it's already an IP, return it
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(target)) return target;

  // Strip protocol/path
  let hostname = target.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
  
  try {
    const addrs = await Deno.resolveDns(hostname, "A");
    if (addrs.length > 0) return addrs[0];
  } catch {
    // Fall through
  }
  return hostname;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const body: ScanRequest = await req.json();
    const { target, ports = DEFAULT_PORTS, timeout = 3000 } = body;

    if (!target) {
      return new Response(
        JSON.stringify({ error: "Target is required" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const ip = await resolveHost(target);
    const scanTimeout = Math.min(timeout, 5000); // Cap at 5s per port

    // Scan in batches of 10 to avoid overwhelming
    const results: PortResult[] = [];
    const batchSize = 10;

    for (let i = 0; i < ports.length; i += batchSize) {
      const batch = ports.slice(i, i + batchSize);
      const batchResults = await Promise.all(
        batch.map((port) => scanPort(ip, port, scanTimeout))
      );
      results.push(...batchResults);
    }

    const openPorts = results.filter((r) => r.state === "open");
    const closedPorts = results.filter((r) => r.state === "closed");
    const filteredPorts = results.filter((r) => r.state === "filtered");

    const response = {
      target,
      ip,
      scan_time: new Date().toISOString(),
      total_ports_scanned: ports.length,
      summary: {
        open: openPorts.length,
        closed: closedPorts.length,
        filtered: filteredPorts.length,
      },
      results: results.sort((a, b) => a.port - b.port),
    };

    return new Response(JSON.stringify(response), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "Unknown error";
    return new Response(
      JSON.stringify({ error: msg }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
