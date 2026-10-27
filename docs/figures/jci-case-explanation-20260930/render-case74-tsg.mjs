import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { chromium } from '../../../.codex-runtime/jci-figures/node_modules/playwright-core/index.mjs';

const root = path.dirname(fileURLToPath(import.meta.url));
const workspace = path.resolve(root, '../../..');
const source = 'data/method/graph-guided-20260929/preparation-repair/targeted-20260929/main/case-0074/TSG/final.json';
const frozen = JSON.parse(await fs.readFile(path.join(workspace, source), 'utf8'));
const graph = frozen.representation.tsg;
assert.equal(graph.nodes.length, 21);
assert.equal(graph.edges.length, 26);
const temporary = path.join(workspace, '.codex-runtime/jci-figures/browser');
await fs.mkdir(temporary, { recursive: true });
const browser = await chromium.launch({
  executablePath: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  headless: true,
  env: { ...process.env, TEMP: temporary, TMP: temporary },
});
const page = await browser.newPage({ viewport: { width: 1800, height: 1750 }, deviceScaleFactor: 2 });
await page.setContent('<!doctype html><html><head><meta charset="utf-8"><style>html,body{margin:0;background:white}svg{display:block}@page{margin:0}</style></head><body></body></html>');
await page.addScriptTag({ path: 'D:/Program Files/nodejs/node_global/node_modules/@slidev/cli/node_modules/mermaid/dist/mermaid.min.js' });
const specifications = [];
for (const [name, candidate] of [['case74-full-tsg', null], ['case74-c1-subgraph', 'C1'], ['case74-c2-subgraph', 'C2']]) {
  const mmd = await fs.readFile(path.join(root, `${name}.mmd`), 'utf8');
  const subset = candidate ? frozen.candidates.find(item => item.candidate_id === candidate).subgraph : null;
  specifications.push({ name, mmd, nodes: graph.nodes.filter(n => !subset || subset.node_ids.includes(n.id)), edges: graph.edges.filter(e => !subset || subset.edge_ids.includes(e.id)) });
}

const rendered = await page.evaluate(async specifications => {
  mermaid.initialize({
    startOnLoad: false, securityLevel: 'strict', theme: 'base',
    themeVariables: { fontFamily: 'Times New Roman, Times, serif', fontSize: '23px', primaryColor: '#ffffff', primaryTextColor: '#222222', lineColor: '#666666', edgeLabelBackground: '#ffffff' },
    flowchart: { htmlLabels: false, curve: 'linear', nodeSpacing: 18, rankSpacing: 115, padding: 13, wrappingWidth: 360 },
  });
  const output = {};
  for (const item of specifications) {
    const parsed = await mermaid.mermaidAPI.getDiagramFromText(item.mmd);
    const actualNodes = [...parsed.db.getVertices().keys()].sort();
    const expectedNodes = item.nodes.map(n => n.id).sort();
    if (JSON.stringify(actualNodes) !== JSON.stringify(expectedNodes)) throw new Error(`Node mismatch: ${item.name}`);
    const actualEdges = parsed.db.getEdges();
    if (actualEdges.length !== item.edges.length) throw new Error(`Edge count mismatch: ${item.name}`);
    for (let i = 0; i < actualEdges.length; i++) {
      const a = actualEdges[i];
      const e = item.edges[i];
      const expectedText = item.name === 'case74-full-tsg' ? e.id : `${e.id}: ${e.relation}`;
      if (a.start !== e.source || a.end !== e.target || a.text !== expectedText) throw new Error(`Edge mismatch: ${item.name}/${e.id}`);
    }
    output[item.name] = (await mermaid.render(`diagram-${item.name}`, item.mmd)).svg;
  }
  return output;
}, specifications);

for (const figure of [1, 2]) {
  const result = await page.evaluate(({ rendered, graph, figure }) => {
    const ns = 'http://www.w3.org/2000/svg';
    const width = 1800;
    const height = figure === 1 ? 1750 : 1650;
    const svg = document.createElementNS(ns, 'svg');
    for (const [k, v] of Object.entries({ xmlns: ns, width, height, viewBox: `0 0 ${width} ${height}`, role: 'img' })) svg.setAttribute(k, v);
    const append = (name, attributes = {}) => {
      const e = document.createElementNS(ns, name);
      for (const [k, v] of Object.entries(attributes)) e.setAttribute(k, v);
      svg.append(e);
      return e;
    };
    append('rect', { width, height, fill: 'white' });
    const text = (x, y, value, size = 25, attributes = {}) => {
      const e = append('text', { x, y, 'font-family': 'Times New Roman, Times, serif', 'font-size': size, fill: '#222222', ...attributes });
      e.textContent = value;
    };
    const line = y => append('line', { x1: 42, y1: y, x2: 1758, y2: y, stroke: '#d5d5d5', 'stroke-width': 1 });
    const diagram = (name, x, y, w, h) => {
      const node = new DOMParser().parseFromString(rendered[name], 'image/svg+xml').documentElement;
      for (const [k, v] of Object.entries({ x, y, width: w, height: h, style: '', preserveAspectRatio: 'xMidYMid meet' })) node.setAttribute(k, v);
      svg.append(node);
    };
    const swatch = (x, label, fill, stroke) => {
      append('rect', { x, y: 117, width: 25, height: 22, fill, stroke, 'stroke-width': 2 });
      text(x + 38, 136, label, 23);
    };
    if (figure === 1) {
      text(42, 49, 'Case 74 — Complete Prompt TSG', 37, { 'font-weight': 'bold' });
      text(42, 85, '21 source-grounded nodes · 26 directed semantic relations · Original node and edge identifiers', 24, { fill: '#555555' });
      swatch(42, 'C1 only: safety-requirement removal', '#edf3f8', '#315f85');
      swatch(514, 'C2 only: options-role clarification', '#fbf0e8', '#a66536');
      swatch(1004, 'Shared by C1 and C2', '#f2edf7', '#755391');
      swatch(1370, 'Other source content', '#f6f6f6', '#777777');
      line(158);
      diagram('case74-full-tsg', 45, 182, 1710, 1110);
      line(1310);
      text(42, 1351, 'Relation key', 29, { 'font-weight': 'bold' });
      const c1 = new Set(['E3','E4','E5','E6','E7','E8','E9','E10','E11']);
      const c2 = new Set(['E14','E15']);
      const shared = new Set(['E18','E19','E20']);
      graph.edges.forEach((edge, i) => {
        const col = Math.floor(i / 9);
        const row = i % 9;
        const color = shared.has(edge.id) ? '#755391' : c1.has(edge.id) ? '#315f85' : c2.has(edge.id) ? '#a66536' : '#555555';
        text(42 + col * 585, 1390 + row * 29, `${edge.id}   ${edge.source} → ${edge.target}   ${edge.relation}`, 23, { fill: color });
      });
      line(1645);
      text(42, 1684, 'Colors indicate candidate membership. Relation directions encode source meaning; causal effects require separate experiments.', 24);
      text(42, 1720, 'Source: frozen Case74 TSG final.json, 2026-09-29. Disconnected components are preserved. All source, system and interface scopes are retained.', 21, { fill: '#666666' });
    } else {
      text(42, 49, 'Case 74 — The Two Selected Support Subgraphs', 37, { 'font-weight': 'bold' });
      text(42, 86, 'Exact selected nodes and edges from the frozen TSG; labels retain the original semantic relation names.', 24, { fill: '#555555' });
      line(111);
      text(42, 157, '(a) C1: remove the repeated HTML / XSS safety requirement', 30, { 'font-weight': 'bold', fill: '#315f85' });
      text(42, 194, '13 nodes · 12 relations · Three disconnected components · Source units SP2, SP3, SP5, SP6', 24);
      diagram('case74-c1-subgraph', 40, 216, 1720, 724);
      text(42, 981, 'P retains the requirement. N removes its expressions from Description, Context, Return and Security Policy.', 25);
      line(1010);
      text(42, 1054, '(b) C2: clarify the role of options as user-submitted content', 30, { 'font-weight': 'bold', fill: '#a66536' });
      text(42, 1091, '6 nodes · 5 relations · Two disconnected components · Source units SP4, SP5, SP6', 24);
      diagram('case74-c2-subgraph', 65, 1120, 1670, 340);
      text(42, 1503, 'P states the sanitization role in the options parameter description. N retains the original distributed wording.', 25);
      text(42, 1540, 'Disconnected source statements are interpreted jointly through their source references and the recorded support rationale.', 24);
      line(1569);
      text(42, 1606, 'Semantic support for a candidate does not establish its safety effect. These diagrams contain no inferred causal edges.', 24, { fill: '#555555' });
    }
    document.body.replaceChildren(svg);
    for (const node of svg.querySelectorAll('text')) {
      const box = node.getBoundingClientRect();
      if (box.left < -1 || box.top < -1 || box.right > width + 1 || box.bottom > height + 1) throw new Error(`Text outside canvas: ${node.textContent}`);
    }
    return { width, height, svg: new XMLSerializer().serializeToString(svg) };
  }, { rendered, graph, figure });
  const name = figure === 1 ? 'case74-complete-tsg' : 'case74-selected-subgraphs';
  await fs.writeFile(path.join(root, `${name}.svg`), result.svg, 'utf8');
  await page.setViewportSize({ width: result.width, height: result.height });
  await page.locator('body > svg').screenshot({ path: path.join(root, `${name}.png`) });
  await page.pdf({ path: path.join(root, `${name}.pdf`), width: `${result.width}px`, height: `${result.height}px`, printBackground: true });
  console.log(`${name}: SVG, PNG and PDF exported`);
}
await browser.close();
console.log('Verified: 21 nodes / 26 edges; C1: 13 / 12; C2: 6 / 5. All edge endpoints and relation labels match frozen input.');
