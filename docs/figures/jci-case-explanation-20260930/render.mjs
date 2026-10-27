import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from '../../../.codex-runtime/jci-figures/node_modules/playwright-core/index.mjs';

const root = path.dirname(fileURLToPath(import.meta.url));
const temporary = path.resolve(root, '../../../.codex-runtime/jci-figures/browser');
await fs.mkdir(temporary, { recursive: true });
const mermaidPath = 'D:/Program Files/nodejs/node_global/node_modules/@slidev/cli/node_modules/mermaid/dist/mermaid.min.js';
const browser = await chromium.launch({
  executablePath: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  headless: true,
  env: { ...process.env, TEMP: temporary, TMP: temporary },
  args: ['--disable-gpu'],
});
const page = await browser.newPage({ viewport: { width: 1400, height: 920 }, deviceScaleFactor: 2 });
await page.setContent('<!doctype html><html><head><meta charset="utf-8"><style>html,body{margin:0;padding:0;background:white;} svg{display:block;} @page{margin:0;}</style></head><body></body></html>');
await page.addScriptTag({ path: mermaidPath });
const sources = {};
for (const name of ['soft-direct', 'fci-query', 'jci-query', 'case74-semantics', 'case74-policies', 'real-query', 'real-jci-query']) {
  sources[name] = await fs.readFile(path.join(root, `${name}.mmd`), 'utf8');
}

const diagrams = await page.evaluate(async (sources) => {
  mermaid.initialize({
    startOnLoad: false,
    securityLevel: 'strict',
    theme: 'base',
    themeVariables: {
      fontFamily: 'Times New Roman, Times, serif', fontSize: '25px',
      primaryColor: '#ffffff', primaryTextColor: '#202020', primaryBorderColor: '#303030',
      lineColor: '#303030', secondaryColor: '#ffffff', tertiaryColor: '#ffffff',
      edgeLabelBackground: '#ffffff',
    },
    flowchart: { htmlLabels: false, curve: 'linear', nodeSpacing: 44, rankSpacing: 55, padding: 13 },
  });
  const output = {};
  for (const [name, source] of Object.entries(sources)) {
    const result = await mermaid.render(`graph-${name}`, source);
    const doc = new DOMParser().parseFromString(result.svg, 'image/svg+xml');
    if (doc.querySelector('parsererror')) throw new Error(`Invalid SVG: ${name}`);
    const svg = doc.documentElement;
    // Mermaid 负责布局；标准 SVG marker 表示 PAG 的混合端点。
    if (name === 'fci-query' || name === 'real-query') {
      const ns = 'http://www.w3.org/2000/svg';
      const defs = document.createElementNS(ns, 'defs');
      const circle = document.createElementNS(ns, 'marker');
      circle.id = `${name}-open-circle`;
      for (const [key, value] of Object.entries({ viewBox: '0 0 12 12', refX: '0', refY: '6', markerWidth: '10', markerHeight: '10', markerUnits: 'userSpaceOnUse', orient: 'auto' })) circle.setAttribute(key, value);
      const shape = document.createElementNS(ns, 'circle');
      for (const [key, value] of Object.entries({ cx: '6', cy: '6', r: '4', fill: 'white', stroke: '#303030', 'stroke-width': '1.8' })) shape.setAttribute(key, value);
      circle.append(shape);
      const arrow = document.createElementNS(ns, 'marker');
      arrow.id = `${name}-arrow`;
      for (const [key, value] of Object.entries({ viewBox: '0 0 10 10', refX: '9', refY: '5', markerWidth: '10', markerHeight: '10', markerUnits: 'userSpaceOnUse', orient: 'auto' })) arrow.setAttribute(key, value);
      const triangle = document.createElementNS(ns, 'path');
      triangle.setAttribute('d', 'M 0 1 L 9 5 L 0 9');
      triangle.setAttribute('fill', 'none');
      triangle.setAttribute('stroke', '#303030');
      triangle.setAttribute('stroke-width', '1.8');
      arrow.append(triangle);
      defs.append(circle, arrow);
      svg.prepend(defs);
      const edge = svg.querySelector('path.flowchart-link');
      if (!edge) throw new Error(`Missing query edge: ${name}`);
      edge.setAttribute('marker-start', `url(#${circle.id})`);
      edge.setAttribute('marker-end', `url(#${arrow.id})`);
    }
    output[name] = new XMLSerializer().serializeToString(svg);
  }
  return output;
}, sources);

for (const figure of [1, 2]) {
  const result = await page.evaluate(({ diagrams, figure }) => {
    const ns = 'http://www.w3.org/2000/svg';
    const W = 1400;
    const H = figure === 1 ? 880 : 940;
    const svg = document.createElementNS(ns, 'svg');
    const make = (tag, attrs = {}) => {
      const e = document.createElementNS(ns, tag);
      for (const [key, value] of Object.entries(attrs)) e.setAttribute(key, String(value));
      svg.append(e);
      return e;
    };
    for (const [key, value] of Object.entries({ xmlns: ns, viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: 'img' })) svg.setAttribute(key, value);
    make('rect', { width: W, height: H, fill: '#ffffff' });
    const text = (x, y, value, size = 23, attrs = {}) => {
      const t = make('text', { x, y, fill: '#242424', 'font-family': 'Times New Roman, Times, serif', 'font-size': size, ...attrs });
      t.textContent = value;
      return t;
    };
    const lines = (x, y, values, size = 23, gap = 31, attrs = {}) => values.forEach((v, i) => text(x, y + i * gap, v, size, attrs));
    const line = (x1, y1, x2, y2, color = '#d8d8d8') => make('line', { x1, y1, x2, y2, stroke: color, 'stroke-width': 1 });
    const diagram = (name, x, y, w, h) => {
      const doc = new DOMParser().parseFromString(diagrams[name], 'image/svg+xml');
      const child = doc.documentElement;
      child.setAttribute('x', x); child.setAttribute('y', y);
      child.setAttribute('width', w); child.setAttribute('height', h);
      child.setAttribute('style', '');
      child.setAttribute('preserveAspectRatio', 'xMidYMid meet');
      svg.append(child);
      return child;
    };
    const panel = (x, y, label, title) => {
      text(x, y, `(${label})`, 25, { 'font-weight': 'bold' });
      text(x + 42, y, title, 25, { 'font-weight': 'bold' });
    };
    const title = make('title');
    const desc = make('desc');
    if (figure === 1) {
      title.textContent = 'What JCI adds: resolving an internal causal endpoint';
      desc.textContent = 'Synthetic soft_direct evidence. The true mechanism C to X to Y and Z to Y generates 1000 independent rows per repetition. Without JCI assumptions, FCI returns X circle-arrow Y in 20 of 20 repetitions. JCI1 and JCI12 each return X arrow Y in 20 of 20 repetitions. At 200 rows each JCI setting recovers both endpoints in 16 of 20 repetitions.';
      text(40, 48, 'What JCI adds: resolving an internal causal endpoint', 34, { 'font-weight': 'bold' });
      text(40, 82, 'Synthetic soft_direct  |  C: randomized context; X, Z, Y: system variables  |  n = 1,000 per repetition', 21, { fill: '#666666' });
      line(40, 105, 1360, 105);
      panel(40, 151, 'a', 'Data-generating mechanism');
      panel(500, 151, 'b', 'FCI without JCI assumptions');
      panel(957, 151, 'c', 'FCI with JCI assumptions');
      line(475, 128, 475, 572); line(932, 128, 932, 572);
      diagram('soft-direct', 59, 186, 388, 221);
      diagram('fci-query', 553, 233, 301, 125);
      diagram('jci-query', 1010, 233, 301, 125);
      text(706, 393, '20 / 20 repetitions', 28, { 'text-anchor': 'middle' });
      text(1160, 393, '20 / 20 repetitions', 28, { 'text-anchor': 'middle', fill: '#315f85' });
      lines(54, 443, ['C changes the probability of X:', 'Pr(X = 1 | C = 0) ≈ 0.27', 'Pr(X = 1 | C = 1) ≈ 0.73'], 23, 32);
      lines(522, 443, ['The endpoint at X is unresolved.', 'An open circle records uncertainty.', 'Both methods use C, X, Z and Y.'], 22, 32);
      lines(975, 443, ['The tail at X is resolved.', 'X is an ancestor of Y in the PAG.', 'JCI1 and JCI12 each give this result.'], 22, 32);
      text(54, 550, 'Ground truth used for validation only.', 20, { fill: '#666666' });
      text(522, 550, 'Only the queried X–Y edge is shown.', 20, { fill: '#666666' });
      text(975, 550, 'Blue marks the additional orientation.', 20, { fill: '#315f85' });
      line(40, 590, 1360, 590);
      panel(40, 633, 'd', 'Information supplied by the design');
      lines(42, 674, [
        'JCI1: system variables do not cause C.   JCI2: C has no latent common cause with the system.',
        'Mechanism: C and Y are dependent; C and Y are independent given X.',
      ], 23, 33);
      make('rect', { x: 40, y: 734, width: 1320, height: 65, fill: '#edf3f8' });
      text(59, 761, 'Observed increment: X-side endpoint resolution at n = 1,000; JCI1 already supplies the gain here.', 23, { fill: '#284f70' });
      text(59, 787, 'At n = 200: 16/20 correct X–Y endpoint pairs for each JCI setting. Sample requirements are mechanism-specific.', 20, { fill: '#284f70' });
      text(40, 830, 'Evidence: 20 independent synthetic datasets per sample size. The reported increment concerns structural identification in this mechanism.', 19, { fill: '#555555' });
      text(40, 857, 'Graphical style informed by Mooij, Magliacane & Claassen (JMLR, 2020). Experiment: structural-query-evidence, 2026-09-29.', 18, { fill: '#777777' });
    } else {
      title.textContent = 'Case 74: prompt-policy evidence and the current JCI query';
      desc.textContent = 'Exploratory real-task evidence. A simplified semantic sketch identifies an HTML safety requirement. In the Raw-prepared policy, all four retained-requirement requests pass finite safety checks and all four removed-requirement requests show unsafe DOM features. The current ten-task structural panel uses C for P/N assignment and X for the preassigned REMOVE family. JCI adds only a context-to-outcome orientation in three of thirty-two resamples; no X-Y safety edge is found.';
      text(40, 48, 'Case 74: prompt-policy evidence and the current JCI query', 34, { 'font-weight': 'bold' });
      text(40, 82, 'Exploratory real-task evidence  |  HTML generation  |  Limited safety and functionality checks', 21, { fill: '#666666' });
      line(40, 105, 1360, 105);
      panel(40, 150, 'a', 'Semantic target');
      panel(548, 150, 'b', 'Executed prompt-policy comparison');
      line(510, 128, 510, 489);
      diagram('case74-semantics', 59, 174, 421, 229);
      text(57, 433, 'Simplified source-based semantic sketch.', 21, { fill: '#666666' });
      text(57, 465, 'Relations describe prompt meaning.', 22);
      diagram('case74-policies', 558, 190, 783, 178);
      lines(566, 399, [
        'Representative code: html.escape vs. direct insertion.',
        'Ordinary functional checks passed in both conditions.',
        'Raw-prepared policy; four generation requests per condition.',
      ], 22, 32);
      line(40, 510, 1360, 510);
      panel(40, 552, 'c', 'Variables in the current structural analysis');
      lines(44, 591, [
        'C: randomized P/N assignment',
        'X: preassigned REMOVE-policy family',
        'Y: oracle-evaluable secure-code yield',
      ], 23, 33);
      make('rect', { x: 40, y: 696, width: 555, height: 77, fill: '#f4f4f4' });
      text(56, 726, 'For this policy, X = 1 in both P and N.', 23);
      text(56, 755, 'Assignment changes the prompt; X stays fixed.', 21, { fill: '#555555' });
      panel(653, 552, 'd', 'Observed JCI contribution');
      diagram('real-query', 700, 581, 220, 86);
      diagram('real-jci-query', 1091, 581, 220, 86);
      text(1005, 630, 'JCI12', 23, { 'text-anchor': 'middle', fill: '#315f85' });
      text(810, 694, 'FCI-JCI0', 21, { 'text-anchor': 'middle' });
      text(1200, 694, 'FCI-JCI12', 21, { 'text-anchor': 'middle' });
      lines(674, 731, [
        '3/32 resamples of the 10-task policy-family panel.',
        'Orientation follows known assignment assumptions.',
        'No additional X–Y safety relation was identified.',
      ], 22, 30);
      line(40, 825, 1360, 825);
      text(40, 859, 'The policy comparison supports a task-specific behavioral contrast; a transferable semantic cause remains unestablished.', 23);
      text(40, 890, 'Four requests share one task. Resampling the same task panel does not increase its independent sample size.', 20, { fill: '#555555' });
      text(40, 918, 'Evidence: tsg-preparation-repair and causal-comparison-results, 2026-09-29. Semantic lines, workflow arrows and PAG edges have distinct meanings.', 17, { fill: '#777777' });
    }
    document.body.replaceChildren(svg);
    const outside = [];
    for (const el of svg.querySelectorAll('text')) {
      const r = el.getBoundingClientRect();
      if (r.left < -1 || r.right > W + 1 || r.top < -1 || r.bottom > H + 1) outside.push(el.textContent);
    }
    if (outside.length) throw new Error(`Text outside figure: ${outside.join('; ')}`);
    return { svg: new XMLSerializer().serializeToString(svg), height: H, textElements: svg.querySelectorAll('text').length };
  }, { diagrams, figure });
  const stem = figure === 1 ? 'figure-1-jci-increment' : 'figure-2-case74';
  await fs.writeFile(path.join(root, `${stem}.svg`), result.svg, 'utf8');
  await page.setViewportSize({ width: 1400, height: result.height });
  await page.locator('body > svg').screenshot({ path: path.join(root, `${stem}.png`) });
  await page.pdf({ path: path.join(root, `${stem}.pdf`), width: '1400px', height: `${result.height}px`, printBackground: true, margin: { top: 0, right: 0, bottom: 0, left: 0 } });
  console.log(JSON.stringify({ figure, width: 1400, height: result.height, textElements: result.textElements, outputs: ['svg', 'png', 'pdf'].map(ext => `${stem}.${ext}`) }));
}
await browser.close();
