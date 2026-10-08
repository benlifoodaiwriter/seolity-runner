# SEOlity – Subscription AI runner

This private repository was created by the **SEOlity** WordPress plugin. It lets SEOlity use the AI
subscription you already pay for instead of a pay-per-token API key:

- **Claude Pro/Max** through the official Claude Code CLI (`CLAUDE_CODE_OAUTH_TOKEN`, created with `claude setup-token`)
- **ChatGPT Plus/Pro** through the official OpenAI Codex CLI (`CODEX_AUTH_JSON`, the `~/.codex/auth.json` file after `codex login`)

How it works: SEOlity writes encrypted requests to `jobs/` on the `seolity-jobs` branch and starts the
"SEOlity AI" workflow. The runner answers them, writes encrypted results to `results/`, and also sends
them directly to your site when it is reachable. Requests and results are AES-256-GCM encrypted with
`SEOLITY_SHARED_SECRET`, so the repository never contains readable content.

Keep this repository **private**, do not share its secrets, and do not edit these files by hand —
SEOlity updates them automatically. Usage counts against your subscription's normal limits.
