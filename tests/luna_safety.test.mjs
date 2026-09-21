import test from 'node:test';
import assert from 'node:assert/strict';
import { codexEnvironment, executionEvidence } from '../scripts/luna_safety.mjs';

test('model process receives only allowlisted non-secret environment', () => {
  const input = { PATH:'/usr/bin', HOME:'/home/runner', LANG:'C.UTF-8',
    ACTIONS_ID_TOKEN_REQUEST_TOKEN:'synthetic-secret', GITHUB_TOKEN:'synthetic-secret',
    OPENAI_API_KEY:'synthetic-secret', CODEX_API_KEY:'synthetic-secret',
    NODE_OPTIONS:'synthetic-injection', GIT_CONFIG_COUNT:'1', LUNA_AUTH_BROKER:'synthetic' };
  const env=codexEnvironment(input, '/temporary/codex-home');
  assert.deepEqual(Object.keys(env).sort(), ['CI','CODEX_HOME','HOME','LANG','LC_ALL','PATH','TERM'].sort());
  assert.equal(env.CODEX_HOME, '/temporary/codex-home');
  assert.equal(env.PATH, '/usr/bin');
  assert.equal(input.GITHUB_TOKEN, 'synthetic-secret');
});
test('accepts explicit Luna Max banner only with successful process exit', () => {
  assert.equal(executionEvidence('model: gpt-5.6-luna\nreasoning effort: max\n',0).verified, true);
});
for (const [name, text, code] of [
  ['missing model', 'reasoning effort: max\n',0],
  ['other model', 'model: other\nreasoning effort: max\n',0],
  ['other effort', 'model: gpt-5.6-luna\nreasoning effort: medium\n',0],
  ['process failure', 'model: gpt-5.6-luna\nreasoning effort: max\n',1],
  ['missing exit', 'model: gpt-5.6-luna\nreasoning effort: max\n',null],
  ['contradictory banner', 'model: gpt-5.6-luna\nreasoning effort: max\nmodel: other\n',0],
]) {
  test(`rejects ${name}`, () => assert.equal(executionEvidence(text,code).verified,false));
}
