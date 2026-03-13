import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const { reportType, scanId, target, date, vulnerabilities, summary } = await req.json();

    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    if (!LOVABLE_API_KEY) throw new Error("LOVABLE_API_KEY is not configured");

    // Build the vulnerability table rows
    const vulnRows = (vulnerabilities || [])
      .map(
        (v: any, i: number) =>
          `| ${i + 1} | ${v.name || "N/A"} | ${(v.severity || "info").toUpperCase()} | ${v.confidence || "N/A"} | ${v.asset || v.url || "N/A"} | ${v.description?.slice(0, 80) || "N/A"} |`
      )
      .join("\n");

    const summaryText = summary
      ? `Critical: ${summary.critical || 0}, High: ${summary.high || 0}, Medium: ${summary.medium || 0}, Low: ${summary.low || 0}, Info: ${summary.info || 0}`
      : "No summary available";

    const prompt = `Generate a professional cybersecurity ${reportType} in structured format for a vulnerability scan.

Scan Details:
- Scan ID: ${scanId}
- Target: ${target}
- Date: ${date}
- Summary: ${summaryText}

Vulnerabilities:
| # | Name | Severity | Confidence | Asset | Description |
|---|------|----------|------------|-------|-------------|
${vulnRows || "| - | No vulnerabilities found | - | - | - | - |"}

Generate the report as a ${reportType}:
${reportType === "Executive Summary" ? "Focus on business risk, overall posture, and high-level recommendations for executives. Keep it concise (1-2 pages worth)." : ""}
${reportType === "Developer Report" ? "Focus on technical details, code-level fixes, affected components, and remediation steps for developers." : ""}
${reportType === "Comprehensive Report" ? "Include executive summary, detailed findings, risk assessment, remediation steps, methodology, and appendix. Be thorough." : ""}

Return the report as clean, well-structured markdown that can be converted to PDF.`;

    const aiResponse = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-3-flash-preview",
        messages: [
          {
            role: "system",
            content:
              "You are a senior cybersecurity report writer. Generate professional, well-structured vulnerability assessment reports in markdown. Use proper headings, tables, and formatting. Be precise and actionable.",
          },
          { role: "user", content: prompt },
        ],
      }),
    });

    if (!aiResponse.ok) {
      if (aiResponse.status === 429) {
        return new Response(JSON.stringify({ error: "Rate limit exceeded." }), {
          status: 429,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      if (aiResponse.status === 402) {
        return new Response(JSON.stringify({ error: "AI credits exhausted." }), {
          status: 402,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      const t = await aiResponse.text();
      console.error("AI error:", aiResponse.status, t);
      throw new Error("AI report generation failed");
    }

    const aiData = await aiResponse.json();
    const reportMarkdown = aiData.choices?.[0]?.message?.content || "Report generation failed.";

    return new Response(JSON.stringify({ markdown: reportMarkdown }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    console.error("Report generation error:", e);
    return new Response(
      JSON.stringify({ error: e instanceof Error ? e.message : "Unknown error" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
