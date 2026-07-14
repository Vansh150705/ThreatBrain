import { type ReactNode } from "react";
import { Link } from "react-router-dom";
import { ArrowLeft, ShieldAlert, Info, TriangleAlert } from "lucide-react";

import { LogoMark } from "@/components/Logo";

const BASE_URL = "https://vansh150705-threatbrain-backend.hf.space/api/v1";

/* ---- small building blocks ---- */
function Code({ children }: { children: ReactNode }) {
  return (
    <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-[0.85em] text-foreground">
      {children}
    </code>
  );
}

function Pre({ children }: { children: string }) {
  return (
    <pre className="my-3 overflow-x-auto rounded-lg bg-[#0f172a] p-4 font-mono text-[12.5px] leading-relaxed text-slate-100">
      {children}
    </pre>
  );
}

function Note({ children, tone = "info" }: { children: ReactNode; tone?: "info" | "warn" }) {
  const warn = tone === "warn";
  return (
    <div
      className={
        "my-4 flex gap-3 rounded-lg border p-3.5 text-[13.5px] leading-relaxed " +
        (warn
          ? "border-severity-high/30 bg-severity-high/[0.06]"
          : "border-severity-info/30 bg-severity-info/[0.06]")
      }
    >
      {warn ? (
        <TriangleAlert className="mt-0.5 h-4 w-4 flex-shrink-0 text-severity-high" />
      ) : (
        <Info className="mt-0.5 h-4 w-4 flex-shrink-0 text-severity-info" />
      )}
      <div>{children}</div>
    </div>
  );
}

function Section({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <section id={id} className="mb-14 scroll-mt-24">
      <h2 className="mb-4 font-serif text-2xl font-semibold text-foreground">{title}</h2>
      <div className="space-y-2 text-[14.5px] leading-relaxed text-foreground/85">{children}</div>
    </section>
  );
}

function Step({ n, title, children }: { n: string; title: string; children: ReactNode }) {
  return (
    <div className="mb-5">
      <div className="mb-1 flex items-center gap-2.5">
        <span className="flex h-6 w-6 flex-shrink-0 items-center justify-center rounded-full bg-foreground text-[12px] font-semibold text-background">
          {n}
        </span>
        <h4 className="text-[15px] font-semibold text-foreground">{title}</h4>
      </div>
      <div className="ml-[34px] space-y-2 text-[14px] leading-relaxed text-foreground/85">
        {children}
      </div>
    </div>
  );
}

const TOC = [
  ["what-you-need", "1. What you need"],
  ["how-it-works", "2. How it works (30 seconds)"],
  ["setup-windows", "3. Set up on Windows"],
  ["setup-linux", "4. Set up on Linux"],
  ["setup-web", "5. Optional: watch a website"],
  ["attacks", "6. The attacks & how to run them"],
  ["approve", "7. How to approve an action"],
  ["actions", "8. What actions ThreatBrain can take"],
  ["config", "9. Config reference"],
  ["safety", "10. Safety checklist"],
];

export default function GuidePage() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* top bar */}
      <header className="sticky top-0 z-20 border-b border-border/70 bg-background/85 backdrop-blur">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-5 py-3">
          <Link to="/" className="flex items-center gap-2">
            <LogoMark className="h-6 w-6" />
            <span className="font-serif text-lg font-semibold">ThreatBrain</span>
          </Link>
          <Link
            to="/"
            className="flex items-center gap-1.5 text-[13px] text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="h-3.5 w-3.5" /> Back to app
          </Link>
        </div>
      </header>

      <main className="mx-auto max-w-3xl px-5 py-10">
        {/* hero */}
        <div className="mb-10">
          <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-border bg-muted/50 px-3 py-1 text-[12px] font-medium text-muted-foreground">
            <ShieldAlert className="h-3.5 w-3.5" /> Hands-on setup &amp; attack guide
          </div>
          <h1 className="font-serif text-4xl font-semibold leading-tight text-foreground">
            Run ThreatBrain, then attack it
          </h1>
          <p className="mt-3 text-[15px] leading-relaxed text-muted-foreground">
            A complete, no-step-skipped walkthrough: install ThreatBrain's watcher on a Windows or
            Linux machine, launch real attacks from a second computer, and watch it detect,
            escalate, and (on your approval) block them. Written for people new to security — every
            term is explained.
          </p>
        </div>

        {/* table of contents */}
        <nav className="mb-12 rounded-xl border border-border bg-muted/30 p-5">
          <div className="mb-2 text-[12px] font-semibold uppercase tracking-wide text-muted-foreground">
            On this page
          </div>
          <ol className="grid gap-1.5 sm:grid-cols-2">
            {TOC.map(([id, label]) => (
              <li key={id}>
                <a href={"#" + id} className="text-[14px] text-foreground/80 hover:text-foreground hover:underline">
                  {label}
                </a>
              </li>
            ))}
          </ol>
        </nav>

        {/* 1 */}
        <Section id="what-you-need" title="1. What you need">
          <ul className="ml-5 list-disc space-y-1.5">
            <li>
              <strong>Two computers on the same network</strong> — one to <em>protect</em> (the
              "target"), one to <em>attack from</em> (the "attacker"). They can be any mix of Windows
              and Linux.
            </li>
            <li>
              <strong>A ThreatBrain account</strong> — sign up at{" "}
              <a href="/signup" className="text-signal underline">
                /signup
              </a>
              . You'll put this email &amp; password into the watcher's config, and log in with it
              on this site to see what it finds.
            </li>
            <li>
              <strong>Python 3</strong> installed on the target machine (that's all the watcher
              needs).
            </li>
            <li>
              <strong>Administrator / sudo</strong> on the target — blocking an attacker changes the
              firewall, which needs admin rights.
            </li>
          </ul>
          <Note tone="warn">
            If your "attacker" computer is a <strong>company laptop</strong>, note that company
            security software may block attack tools or alert your IT team. Prefer the built-in{" "}
            <Code>ssh</Code> / <Code>curl</Code> commands below over installing tools like{" "}
            <Code>hydra</Code>.
          </Note>
        </Section>

        {/* 2 */}
        <Section id="how-it-works" title="2. How it works (30 seconds)">
          <p>
            Two small programs run on the machine you're protecting. The <strong>Collector</strong>{" "}
            reads the machine's log files, spots attacks, and sends them to ThreatBrain's AI. The AI
            works out how serious it is and suggests a response. You click <strong>Approve</strong>{" "}
            in this dashboard, and the <strong>Executor</strong> carries out the block. Every step is
            saved to a tamper-proof logbook.
          </p>
          <Pre>{`attack  →  Collector (detects)  →  AI pipeline (triage → investigate → suggest)
        →  you click Approve  →  Executor (blocks on Windows or Linux)`}</Pre>
        </Section>

        {/* 3 windows */}
        <Section id="setup-windows" title="3. Set up on Windows (protecting a Windows PC)">
          <Step n="1" title="Get the code and install">
            <p>Open <strong>PowerShell</strong> and run:</p>
            <Pre>{`git clone https://github.com/Vansh150705/ThreatBrain.git
cd ThreatBrain\\collector
python -m venv venv
.\\venv\\Scripts\\python.exe -m pip install -r requirements.txt`}</Pre>
          </Step>
          <Step n="2" title="Turn on SSH + file logging (Administrator PowerShell)">
            <p>This makes Windows record failed logins to a text file the Collector can read:</p>
            <Pre>{`Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd; Set-Service sshd -StartupType Automatic
# Open C:\\ProgramData\\ssh\\sshd_config in Notepad (as admin) and add these 2 lines:
#     SyslogFacility LOCAL0
#     LogLevel INFO
Restart-Service sshd`}</Pre>
            <p>
              Failed logins now appear in <Code>C:\ProgramData\ssh\logs\sshd.log</Code>.
            </p>
          </Step>
          <Step n="3" title="Create collector.yaml">
            <p>
              Copy the example and edit it: <Code>copy collector.example.yaml collector.yaml</Code>
            </p>
            <Pre>{`base_url: ${BASE_URL}
email: YOUR_THREATBRAIN_EMAIL
password: YOUR_THREATBRAIN_PASSWORD
collector_id: home-pc-01
asset_name: personal-laptop
log_path: "C:/ProgramData/ssh/logs/sshd.log"
threshold: 10`}</Pre>
          </Step>
          <Step n="4" title="Create executor.yaml">
            <Pre>{`base_url: ${BASE_URL}
email: YOUR_THREATBRAIN_EMAIL
password: YOUR_THREATBRAIN_PASSWORD
firewall: auto            # uses Windows Firewall automatically
allow_private: true       # attacker is on your home network (a private IP)
dry_run: true             # pretend first; change to false to really block
allowlist:
  - YOUR_OWN_IP           # so you never block yourself
enabled_actions:
  - block_ip
  # - block_range
  # - disable_user`}</Pre>
          </Step>
          <Step n="5" title="Run both (two Administrator PowerShell windows)">
            <Pre>{`.\\venv\\Scripts\\python.exe -m tb_collector --config collector.yaml
.\\venv\\Scripts\\python.exe -m tb_executor  --config executor.yaml`}</Pre>
          </Step>
          <Step n="6" title="Check a block worked">
            <Pre>{`netsh advfirewall firewall show rule name="ThreatBrain block ATTACKER-IP"`}</Pre>
          </Step>
        </Section>

        {/* 4 linux */}
        <Section id="setup-linux" title="4. Set up on Linux (protecting a Linux / Kali machine)">
          <Step n="1" title="Get the code and install">
            <Pre>{`git clone https://github.com/Vansh150705/ThreatBrain.git
cd ThreatBrain/collector
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
sudo systemctl start ssh        # failed logins go to /var/log/auth.log`}</Pre>
          </Step>
          <Step n="2" title="Create collector.yaml">
            <Pre>{`base_url: ${BASE_URL}
email: YOUR_THREATBRAIN_EMAIL
password: YOUR_THREATBRAIN_PASSWORD
collector_id: kali-lab-01
asset_name: kali-box
log_path: /var/log/auth.log
threshold: 10`}</Pre>
          </Step>
          <Step n="3" title="Create executor.yaml">
            <Pre>{`base_url: ${BASE_URL}
email: YOUR_THREATBRAIN_EMAIL
password: YOUR_THREATBRAIN_PASSWORD
firewall: auto            # uses iptables automatically
allow_private: true
dry_run: true             # set false to really block
allowlist:
  - YOUR_OWN_IP
enabled_actions:
  - block_ip`}</Pre>
          </Step>
          <Step n="4" title="Run both (two terminals, with sudo)">
            <Pre>{`sudo ./venv/bin/python -m tb_collector --config collector.yaml
sudo ./venv/bin/python -m tb_executor  --config executor.yaml`}</Pre>
          </Step>
          <Step n="5" title="Check a block worked">
            <Pre>{`sudo iptables -L INPUT -n | grep ATTACKER-IP`}</Pre>
          </Step>
        </Section>

        {/* 5 web */}
        <Section id="setup-web" title="5. Optional — watch a website too">
          <p>
            To also catch website attacks, run the included tiny demo website on the target and tell
            the Collector to watch its log. It only records requests — it isn't actually vulnerable.
          </p>
          <Pre>{`# On the target, start the demo website (logs every request):
#   Windows: .\\venv\\Scripts\\python.exe demo\\web_target.py --port 8080 --log C:/tb/access.log
#   Linux:   ./venv/bin/python demo/web_target.py --port 8080 --log /tmp/access.log

# Then in collector.yaml, replace "log_path" with a list of logs to watch:
log_paths:
  - /var/log/auth.log            # (or the Windows sshd.log path)
  - /tmp/access.log              # the demo website's log`}</Pre>
        </Section>

        {/* 6 attacks */}
        <Section id="attacks" title="6. The attacks & how to run them">
          <p>
            Run these from your <strong>attacker</strong> computer. First find the target's IP:{" "}
            <Code>ipconfig</Code> on Windows or <Code>ip a</Code> on Linux (e.g.{" "}
            <Code>192.168.1.20</Code>). Replace <Code>TARGET</Code> below with it.
          </p>

          <h3 className="mt-6 mb-1 text-[15.5px] font-semibold text-foreground">Password &amp; login attacks</h3>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-[13px]">
              <thead>
                <tr className="border-b border-border text-left">
                  <th className="py-2 pr-3 font-semibold">Attack</th>
                  <th className="py-2 pr-3 font-semibold">What it is</th>
                  <th className="py-2 font-semibold">Command on the attacker</th>
                </tr>
              </thead>
              <tbody className="align-top">
                <tr className="border-b border-border/60">
                  <td className="py-2 pr-3">Brute force + break-in</td>
                  <td className="py-2 pr-3">Guess many passwords for one account</td>
                  <td className="py-2 font-mono text-[12px]">hydra -l root -P words.txt ssh://TARGET<br/>(no hydra? type <span className="text-severity-high">ssh baduser@TARGET</span> with a wrong password ~12 times)</td>
                </tr>
                <tr className="border-b border-border/60">
                  <td className="py-2 pr-3">Password spraying</td>
                  <td className="py-2 pr-3">One password across many accounts</td>
                  <td className="py-2 font-mono text-[12px]">hydra -L users.txt -p 'Winter2025!' ssh://TARGET</td>
                </tr>
                <tr className="border-b border-border/60">
                  <td className="py-2 pr-3">Username enumeration</td>
                  <td className="py-2 pr-3">Poke to find which usernames exist</td>
                  <td className="py-2 font-mono text-[12px]">hydra -L madeup_names.txt -p x ssh://TARGET</td>
                </tr>
              </tbody>
            </table>
          </div>
          <p className="mt-2 text-[13.5px] text-muted-foreground">
            To see the <strong>CRITICAL "break-in"</strong> alert, include the target's real password
            in <Code>words.txt</Code> so one attempt actually succeeds.
          </p>

          <h3 className="mt-7 mb-1 text-[15.5px] font-semibold text-foreground">
            Website attacks (needs the demo website from step 5 running)
          </h3>
          <p className="text-[13.5px] text-muted-foreground">
            These even work when disguised (URL-encoded, comment-obfuscated) — ThreatBrain decodes
            them first.
          </p>
          <Pre>{`# SQL injection (trick the database)
curl "http://TARGET:8080/?id=1' OR 1=1--"

# XSS (inject a script)
curl "http://TARGET:8080/?q=<script>alert(1)</script>"

# Path traversal (read secret files)
curl "http://TARGET:8080/?file=../../etc/passwd"

# Command injection (run commands on the server)
curl "http://TARGET:8080/?cmd=;cat /etc/passwd"

# Scanner / recon tool
curl -A "sqlmap/1.7" "http://TARGET:8080/"        # or really run:  nikto -h TARGET:8080

# Directory / vulnerability scanning (caught by behaviour, even with a normal browser name)
for i in $(seq 1 20); do curl -s "http://TARGET:8080/admin$i" >/dev/null; done`}</Pre>

          <h3 className="mt-7 mb-1 text-[15.5px] font-semibold text-foreground">What you'll see each time</h3>
          <ol className="ml-5 list-decimal space-y-1">
            <li>The Collector window prints <Code>DETECTED ... -&gt; posting</Code>.</li>
            <li>A new <strong>threat</strong> and <strong>incident</strong> appear in the dashboard.</li>
            <li>A <strong>response suggestion</strong> (e.g. "Block Malicious IP") lands in <strong>Approvals</strong>.</li>
          </ol>
        </Section>

        {/* 7 approve */}
        <Section id="approve" title="7. How to approve (or reject) an action">
          <ol className="ml-5 list-decimal space-y-1.5">
            <li>Log into this site with your account (you own your workspace, so you have permission).</li>
            <li>Open the <strong>Approvals</strong> page from the left menu.</li>
            <li>
              You'll see suggestions like <em>"Block Malicious IP → 192.168.1.30"</em>, each with a
              reason from the AI.
            </li>
            <li>
              Click <strong>Approve</strong> to allow it or <strong>Reject</strong> to decline. You
              can add a note.
            </li>
            <li>Within ~10 seconds the Executor on the target carries out the action.</li>
            <li>
              Every decision — yours and the AI's — is saved to the <strong>Audit</strong> page, which
              can never be edited or deleted.
            </li>
          </ol>
          <Note tone="warn">
            Keep <Code>dry_run: true</Code> for your first run — approve an action and confirm the
            Executor <em>says</em> it would block, then switch to <Code>dry_run: false</Code> for real
            blocking. Always keep your own IP in the <Code>allowlist</Code>.
          </Note>
        </Section>

        {/* 8 actions */}
        <Section id="actions" title="8. What actions ThreatBrain can take">
          <p>
            The AI picks the action that fits the attack; the Executor carries out the ones you've
            turned on in <Code>enabled_actions</Code>. Each has its own safety guard.
          </p>
          <div className="overflow-x-auto">
            <table className="mt-2 w-full border-collapse text-[13px]">
              <thead>
                <tr className="border-b border-border text-left">
                  <th className="py-2 pr-3 font-semibold">Action</th>
                  <th className="py-2 pr-3 font-semibold">What it does</th>
                  <th className="py-2 font-semibold">Safety guard</th>
                </tr>
              </thead>
              <tbody className="align-top">
                <tr className="border-b border-border/60">
                  <td className="py-2 pr-3 font-mono text-[12px]">block_ip</td>
                  <td className="py-2 pr-3">Firewall-blocks one attacker IP (Windows Firewall / iptables)</td>
                  <td className="py-2">Never blocks loopback/your allowlist; private IPs only if <Code>allow_private</Code></td>
                </tr>
                <tr className="border-b border-border/60">
                  <td className="py-2 pr-3 font-mono text-[12px]">block_range</td>
                  <td className="py-2 pr-3">Blocks a whole subnet — for attackers who rotate across many IPs</td>
                  <td className="py-2">Refuses ranges that are too broad or contain an allowlisted IP</td>
                </tr>
                <tr className="border-b border-border/60">
                  <td className="py-2 pr-3 font-mono text-[12px]">disable_user</td>
                  <td className="py-2 pr-3">Locks a compromised account (usermod -L / net user /active:no)</td>
                  <td className="py-2">Never touches root/admin/system or your <Code>user_allowlist</Code></td>
                </tr>
              </tbody>
            </table>
          </div>
          <p className="mt-2 text-[13.5px] text-muted-foreground">
            <Code>block_ip</Code> is on by default. Turn on <Code>block_range</Code> and{" "}
            <Code>disable_user</Code> in <Code>executor.yaml</Code> when you want them.
          </p>
        </Section>

        {/* 9 config */}
        <Section id="config" title="9. Config reference">
          <h3 className="mb-1 text-[15.5px] font-semibold text-foreground">collector.yaml</h3>
          <ul className="ml-5 list-disc space-y-1 text-[13.5px]">
            <li><Code>base_url</Code> — the ThreatBrain API, ending in <Code>/api/v1</Code>.</li>
            <li><Code>email</Code> / <Code>password</Code> — your ThreatBrain account.</li>
            <li><Code>collector_id</Code> / <Code>asset_name</Code> — labels for this machine.</li>
            <li><Code>log_path</Code> or <Code>log_paths</Code> — the log file(s) to watch.</li>
            <li><Code>threshold</Code> — failed logins before it alerts (keep at 10+).</li>
          </ul>
          <h3 className="mb-1 mt-5 text-[15.5px] font-semibold text-foreground">executor.yaml</h3>
          <ul className="ml-5 list-disc space-y-1 text-[13.5px]">
            <li><Code>firewall</Code> — <Code>auto</Code> (recommended), <Code>iptables</Code>, or <Code>windows</Code>.</li>
            <li><Code>dry_run</Code> — <Code>true</Code> = pretend; <Code>false</Code> = really block.</li>
            <li><Code>allow_private</Code> — allow blocking private/LAN IPs (needed in a home lab).</li>
            <li><Code>allowlist</Code> — IPs to never block (put your own IP here).</li>
            <li><Code>user_allowlist</Code> — accounts to never disable.</li>
            <li><Code>enabled_actions</Code> — which actions are allowed (block_ip / block_range / disable_user).</li>
          </ul>
        </Section>

        {/* 10 safety */}
        <Section id="safety" title="10. Safety checklist">
          <ul className="ml-5 list-disc space-y-1.5">
            <li>Start with <Code>dry_run: true</Code>; switch to <Code>false</Code> only after you've seen it work.</li>
            <li>Always put your own IP in <Code>allowlist</Code> so you can't lock yourself out.</li>
            <li>The Executor needs Administrator / sudo to change the firewall.</li>
            <li>Only attack machines you own. On a company device, be aware IT may see the attempts.</li>
          </ul>
        </Section>

        <div className="mt-16 border-t border-border pt-6 text-center text-[13px] text-muted-foreground">
          Built by Vansh Mahajan ·{" "}
          <a href="https://github.com/Vansh150705/ThreatBrain" className="underline">
            source on GitHub
          </a>
        </div>
      </main>
    </div>
  );
}
