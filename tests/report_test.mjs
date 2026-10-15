import { readFileSync } from 'node:fs';
const workflow = readFileSync(process.argv[2] ?? new URL('../workflow/security-scan.template.yml', import.meta.url), 'utf8');
const src = workflow.match(/          script: \|\n([\s\S]*)$/)[1].split('\n').map((line) => line.slice(12)).join('\n');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
async function run(name, { owners, actor, author, existing = false, failed = 'yara,repo-policy' }) {
  const calls = [];
  process.env.SECURITY_OWNER = owners;
  process.env.FAILED = failed;
  const context = { actor, runId: 42, serverUrl: 'https://github.com', repo: { owner: 'acme', repo: 'web-app' },
    payload: { pull_request: { number: 7, user: { login: author }, html_url: 'https://github.com/x/pull/7', head: { sha: 'abc123' } } } };
  const github = { paginate: async () => (existing ? [{ number: 3, title: '⚠️ Security scan failed on PR #7' }] : []),
    rest: { issues: { listForRepo: () => {}, createLabel: async () => { const e = new Error('exists'); e.status = 422; throw e; },
      create: async (a) => calls.push(['create', a.body]), createComment: async (a) => calls.push(['comment #' + a.issue_number, a.body]) } } };
  const core = { warning: (m) => calls.push(['warning', m]) };
  await new AsyncFunction('context', 'github', 'core', src)(context, github, core);
  console.log(`\n===== ${name}`);
  for (const [kind, text] of calls) console.log(`[${kind}]\n${text.split('\n').filter((line) => kind === 'warning' || !line.startsWith('The ')).slice(0, kind === 'warning' ? 1 : 5).join('\n')}`);
}
await run('owner pushed own PR', { owners: 'carol', actor: 'carol', author: 'carol' });
await run('two owners, dev pushed own PR', { owners: '@Carol, alice', actor: 'bob', author: 'bob' });
await run('owner pushed to a dev PR', { owners: 'carol alice', actor: 'Alice', author: 'bob' });
await run('bot pushed', { owners: 'carol', actor: 'dependabot[bot]', author: 'dependabot[bot]' });
await run('owner var missing', { owners: '', actor: 'bob', author: 'bob' });
await run('repeat failure -> comment', { owners: 'carol', actor: 'bob', author: 'bob', existing: true });
await run('setup step failed', { owners: 'carol', actor: 'bob', author: 'bob', failed: '' });
