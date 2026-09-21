// Pure policy helpers. No network, credentials or model calls.
export function codexEnvironment(source, codexHome) {
  if (typeof codexHome !== 'string' || !codexHome.startsWith('/')) {
    throw new Error('Absolute dedicated Codex home required');
  }
  // Do not inherit GitHub/OIDC credentials, API keys, loader options or git hooks.
  return {
    PATH: source.PATH || '/usr/local/bin:/usr/bin:/bin',
    HOME: source.HOME || '/home/runner',
    CODEX_HOME: codexHome,
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    TERM: 'dumb',
    CI: '1',
  };
}

export function executionEvidence(log, exitCode) {
  const models = [...String(log).matchAll(/^\s*model:\s*([^\s]+)\s*$/gmi)].map(m => m[1]);
  const efforts = [...String(log).matchAll(/^\s*reasoning effort:\s*([^\r\n]+)\s*$/gmi)].map(m => m[1].trim());
  return {
    model: models[0] || '',
    effort: efforts[0] || '',
    verified: exitCode === 0 && models.length === 1 && efforts.length === 1
      && models[0] === 'gpt-5.6-luna' && efforts[0] === 'max',
  };
}
