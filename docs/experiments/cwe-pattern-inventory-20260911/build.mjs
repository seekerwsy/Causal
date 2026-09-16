// Descriptive source inventory only. No extraction, selection, role assignment or API calls.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../../..');
const rel = p => path.relative(root, p).replaceAll('\\', '/');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const read = p => JSON.parse(fs.readFileSync(path.join(root, p), 'utf8'));
const allPath = 'data/dataset-curation/research-source-use-v2/prepared-tasks.json';
const poolPath = 'data/dataset-curation/research-candidate-pool-v2/tasks.json';
const baselinePath = 'data/dataset-curation/reviewer-task-unit-dataset-v5/task-units.jsonl';
const screeningPath = 'data/dataset-curation/research-candidate-pool-v2/screening.json';
const all = read(allPath);
const pool = read(poolPath);
const base = fs.readFileSync(path.join(root, baselinePath), 'utf8').trim().split(/\r?\n/).map(JSON.parse);
const screening = new Map(read(screeningPath).map(x => [x.task_unit_id, x.decision]));
const annotations = JSON.parse(fs.readFileSync(path.join(here, 'annotations.json'), 'utf8'));
const byId = new Map(all.map(t => [t.task_id, t]));
const baseline = new Map(base.map(t => [t.task_unit_id, t]));
const poolIds = new Set(pool.map(t => t.task_id));
const sources = {
  cyberseceval_instruct_prime: ['CyberSecEval Instruct Prime', 'cyberseceval_instruct_prime'],
  codesec_eval_plus: ['CodeSecEval', 'codesec_eval'],
  llmseceval: ['LLMSecEval', 'llmseceval'],
  secodeplt: ['SeCodePLT', 'secodeplt'],
  securityeval: ['SecurityEval', 'securityeval'],
  cweval: ['CWEval', 'cweval'],
  sallm: ['SALLM', 'sallm'],
};
const unique = values => [...new Set(values)];
const has = (t, c) => t.source_declared_cwe_ids.includes(c);
const cwes = unique(all.flatMap(t => t.source_declared_cwe_ids)).sort((a,b) => +a.slice(4)-+b.slice(4));
assert.deepEqual(cwes, Object.keys(annotations));
assert.equal(all.length, byId.size);
assert.equal(pool.length, poolIds.size);
assert.equal(pool.length, new Set(pool.map(t => t.near_duplicate_group_id)).size);
for (const t of pool) assert.deepEqual(t, byId.get(t.task_id));
assert.ok(all.every(t => t.source_declared_cwe_ids.length > 0 && t.source_declared_cwe_ids.length <= 2));

const examples = [];
const rows = cwes.map(c => {
  const a = annotations[c];
  for (const e of a.examples) {
    const t = byId.get(e.task_id);
    assert.ok(poolIds.has(e.task_id), 'Example must be in the unprotected candidate pool');
    assert.ok(has(t,c));
    assert.equal(sha(JSON.stringify(t.prompt)), t.prompt_sha256);
    const original = baseline.get(t.task_id);
    const member = original.source_members.find(m => m.record_id === original.representative_record_id);
    examples.push({cwe:c, form_zh:e.form_zh, task_id:t.task_id, language:t.language,
      source:sources[t.source_lineage_id][0], source_lineage_id:t.source_lineage_id,
      source_locator:member.source_locator, source_url:member.citation_url,
      prompt_sha256:t.prompt_sha256, source_prompt:t.prompt});
  }
  const p = pool.filter(t => has(t,c));
  return {cwe:c, name_zh:a.name_zh, name_en:a.name_en, entry_type:a.entry_type,
    all_task_identities:all.filter(t => has(t,c)).length, pool_task_units:p.length,
    python_pool:p.filter(t => t.language==='python').length,
    other_language_pool:p.filter(t => t.language!=='python').length,
    pool_by_language:Object.fromEntries(unique(p.map(t=>t.language)).sort().map(l=>[l,p.filter(t=>t.language===l).length])),
    pool_by_source:Object.fromEntries(Object.keys(sources).filter(s=>p.some(t=>t.source_lineage_id===s)).map(s=>[s,p.filter(t=>t.source_lineage_id===s).length])),
    descriptive_forms:unique(a.examples.map(e=>e.form_zh)), example_task_ids:a.examples.map(e=>e.task_id),
    pattern_assignment_status:'SOURCE_EXEMPLARS_ONLY_NOT_EXHAUSTIVE_NOT_FROZEN',
    total_pattern_count:null, per_pattern_task_counts:null};
});
const sourceRows = Object.entries(sources).map(([s,[name,ds]]) => ({
  source_lineage_id:s, dataset_id:ds, name,
  original_source_records:base.reduce((n,t)=>n+t.source_members.filter(m=>m.dataset_id===ds).length,0),
  all_primary_lineage_tasks:all.filter(t=>t.source_lineage_id===s).length,
  pool_primary_lineage_tasks:pool.filter(t=>t.source_lineage_id===s).length,
  pool_cwe_labels:unique(pool.filter(t=>t.source_lineage_id===s).flatMap(t=>t.source_declared_cwe_ids)).length,
}));
const identities = [allPath, poolPath, baselinePath, screeningPath,
  'data/dataset-curation/research-source-use-v2/manifest.json',
  'data/dataset-curation/research-candidate-pool-v2/manifest.json',
  'datasets/source-inventory/SeCodePLT-1f3da9ee48e0046359903cba0cc48d03665f96d5/generate_dataset/cwe-details.csv',
  rel(path.join(here,'annotations.json')), rel(fileURLToPath(import.meta.url))];
const report = {
  date:'2026-09-11', status:'DESCRIPTIVE_SOURCE_INVENTORY_NOT_A_FROZEN_PATTERN_TAXONOMY',
  scope:'Seven integrated source snapshots; pending external candidates and repeated experiment bundles excluded',
  source_record_count:sourceRows.reduce((n,s)=>n+s.original_source_records,0),
  all_task_identity_count:all.length, all_near_duplicate_group_count:new Set(all.map(t=>t.near_duplicate_group_id)).size,
  pool_independent_task_count:pool.length, cwe_label_count:cwes.length,
  weakness_entry_count:rows.filter(r=>r.entry_type==='Weakness').length,
  category_entry_count:rows.filter(r=>r.entry_type==='Category').length,
  all_cwe_memberships:rows.reduce((n,r)=>n+r.all_task_identities,0),
  pool_cwe_memberships:rows.reduce((n,r)=>n+r.pool_task_units,0),
  multiple_cwe_tasks:all.filter(t=>t.source_declared_cwe_ids.length>1).map(t=>({task_id:t.task_id,cwe_ids:t.source_declared_cwe_ids})),
  pool_size_bands:{'1-4':rows.filter(r=>r.pool_task_units<=4).length,'5-19':rows.filter(r=>r.pool_task_units>=5&&r.pool_task_units<=19).length,'20+':rows.filter(r=>r.pool_task_units>=20).length},
  pool_dispositions:Object.fromEntries(unique([...screening.values()]).sort().map(d=>[d,[...screening.values()].filter(v=>v===d).length])),
  source_example_count:examples.length, pattern_count:null,
  pattern_count_reason:'No complete task-to-pattern coding or canonicalization has been performed. The 214 source exemplars are not 214 validated patterns.',
  example_selection:'Up to three concise tasks from distinct primary source lineages per CWE, prioritizing non-CyberSecEval sources; five additional source examples for archive extraction, SQL identifiers, general sampling, pickle and URL downloads. Explicit IDs are in annotations.json. This is purposive coverage illustration, not representative sampling or a prevalence estimate.',
  source_only_curation:true, generated_code_or_outcomes_used:false, provider_calls:0,
  prompt_hash_definition:'SHA-256 of canonical JSON string encoding, matching records.content_hash(prompt); input_sha256 uses exact file bytes',
  protected_prompt_examples_opened:false, extractor_or_catalog_changed:false,
  active_protocol_unchanged:true, formal_admissions:0,
  cwe730_reference:'https://cwe.mitre.org/data/definitions/730.html',
  input_sha256:Object.fromEntries(identities.map(p=>[p,sha(fs.readFileSync(path.join(root,p)))])),
  cwe_rows:rows, source_rows:sourceRows,
};
assert.equal(report.source_record_count,2283);
assert.equal(all.length,2165);
assert.equal(pool.length,1992);
assert.equal(cwes.length,117);
assert.equal(sourceRows.reduce((n,s)=>n+s.pool_primary_lineage_tasks,0),pool.length);
fs.writeFileSync(path.join(here,'inventory.json'),JSON.stringify(report,null,2)+'\n');

const md = [
  '# 当前数据集的 CWE 与任务模式概览', '',
  '日期：2026-09-11。用途：研究范围讨论与数据描述。活动协议、资格状态和任务角色不变。', '',
  '**七个已纳入来源，共 117 个不同 CWE 编号；主研究候选池为 1,992 个独立任务。**', '',
  '严格区分：117 个编号中，116 个对应弱点条目，CWE-730 是历史分类条目（Category），并不是一个单独弱点。[MITRE 的 CWE-730 定义](https://cwe.mitre.org/data/definitions/730.html)确认了这一点。原始标签保留，不在本次盘点中重标。', '',
  '## 统计口径', '',
  '- 全量范围为 research-source-use-v2 的 2,165 个任务身份，对应 2,283 条来源记录、2,164 个近重复组。',
  '- 候选池范围为 research-candidate-pool-v2 的 1,992 个任务与 1,992 个近重复组；另外保留 125 个受保护输入、47 个待修正来源缺陷及 1 个依赖变体。',
  '- 每个 CWE 的数量按“任务是否带有该来源标签”计算。有一个任务同时带 CWE-120/121，因此全量行和为 2,166、候选池行和为 1,993；这不增加独立任务数。',
  '- 这些是来源标签覆盖数，不是已验证漏洞数、合格干预数或 Oracle 可评估数。CWE 的上位类与具体弱点也不是同一抽象层级。', '',
  '## 七个来源', '',
  '任务按现有代表来源谱系单一归属，下面的任务列可以相加；不是各来源“独有贡献”的估计。', '',
  '| 来源 | 原始记录 | 全量任务身份 | 候选池任务 | 候选池 CWE 编号数 |',
  '|---|---:|---:|---:|---:|',
  ...sourceRows.map(s=>`| ${s.name} | ${s.original_source_records} | ${s.all_primary_lineage_tasks} | ${s.pool_primary_lineage_tasks} | ${s.pool_cwe_labels} |`),
  '| 合计（CWE 去重） | 2,283 | 2,165 | 1,992 | 117 |', '',
  '本地待审来源不混入这些总数：CodeGuard+ 的 71 条基础 Python 条目、SecCodeBench 的 13 个 Python 案例、BaxBench 的 28 个场景，以及修复解析后尚未纳入的 5 条 SeCodePLT CWE-918 记录，沿用[既有盘点](../2026-09-09-data-preparation-next-steps.md)。它们不是已确认新增独立任务；历史运行、副本与代码生成变体也不重复相加。', '',
  '## 模式列的含义', '',
  '**下表覆盖全部 117 个 CWE 编号，但“任务模式示例”不是全量模式分类。** 这里依据 214 条候选池原始任务提供描述性任务形式，尚未逐题标注全部 1,992 个任务，也没有冻结模式等价规则，因此不填“总模式数”或“每模式样本量”。214 是展示依据的任务数，不是模式数。', '',
  '优先选取每个 CWE 下不同来源中的简洁任务，另补充归档解压、SQL 标识符、普通抽样、Pickle 和 URL 下载各一个示例。这种选择只展示实际存在的任务形式，不估计其频率。每个描述在 Excel“模式依据”页绑定任务 ID、来源定位与完整原始 Prompt；“任务清单”页仅含元数据，不展开受保护 Prompt。', '',
  '同一来源 CWE 下可能混有不同语义：例如 CWE-338 同时出现密码重置码、普通抽样和频道操作；CWE-78 的部分任务只要求读文件。表格据实保留这些形式，不因 CWE 标签补写安全边界。来源盘点不用于修改抽取器、TSG 概念、正式假设或选择器。', '',
  '## 全部 CWE 与任务形式', '',
  '| CWE | 简称 | 全量身份 | 候选池 | 其中 Python | 实际任务形式示例（未穷尽） |',
  '|---|---|---:|---:|---:|---|',
  ...rows.map(r=>`| ${r.cwe} | ${r.name_zh} | ${r.all_task_identities} | ${r.pool_task_units} | ${r.python_pool} | ${r.descriptive_forms.join('；')} |`), '',
  '## 对研究范围的含义', '',
  '候选池中有 53 个 CWE 编号各含 1–4 个任务，33 个各含 5–19 个，31 个各含至少 20 个。把每个 CWE 再细分成多种模式，样本会进一步分散。这是容量描述，不是功效检验。', '',
  '因此，论文可以用完整表说明数据覆盖；核心实验范围应依据明确的任务结构、干预语义、独立支持量和实际测量范围前瞻确定。模式应区分操作、输入控制与安全边界；语言作为统计与测量维度单独保留，不能仅因 CWE 相同就合并不同操作或测量条件。', '',
  '## 文件与复现', '',
  '- [Excel 全表](cwe-task-patterns.xlsx)：说明、CWE 总表、来源汇总、模式依据、任务清单、来源记录。',
  '- [精确统计与输入哈希](inventory.json)。',
  '- [任务形式描述及绑定](annotations.json)。',
  '- [表格生成入口](build.mjs)：从仓库根目录运行 `node docs/experiments/cwe-pattern-inventory-20260911/build.mjs`，重建 Markdown 与统计 JSON；加 XLSX 模板目录参数可生成待打包 XML。',
  '', '零 API 调用；没有读取研究生成代码、实验结局、选择器分数或保护预留的原始 Prompt 示例。表格属于描述性来源盘点，不构成正式效果证据。', '',
];
fs.writeFileSync(path.join(here,'README.md'),md.join('\n'));

// Optional Excel XML production, starting from the skill's OOXML template.
if (process.argv[2]) {
  const template=path.resolve(process.argv[2]);
  const work=path.join(root,'.tmp/cwe-pattern-inventory-20260911/xlsx-xml');
  fs.mkdirSync(work,{recursive:true});
  fs.cpSync(template,work,{recursive:true});
  const esc=x=>String(x).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');
  const ns='http://schemas.openxmlformats.org/spreadsheetml/2006/main';
  const sns='http://schemas.openxmlformats.org/officeDocument/2006/relationships';
  const decl='<?xml version="1.0" encoding="UTF-8" standalone="yes"?>';
  const strings=[], stringMap=new Map(); let stringRefs=0;
  const si=s=>{stringRefs++;if(!stringMap.has(s)){stringMap.set(s,strings.length);strings.push(s);}return stringMap.get(s);};
  const col=n=>{let s='';while(n){n--;s=String.fromCharCode(65+n%26)+s;n=Math.floor(n/26);}return s;};
  const formula=(f,v)=>({f,v});
  const T=all.length+1, S=report.source_record_count+1, E=examples.length+1, C=rows.length+1;
  const rawRows=[['任务 ID','来源 CWE 1','来源 CWE 2','语言','主来源谱系','进入候选池（1/0）','现有用途决定','近重复组','Prompt SHA-256'],
    ...all.map(t=>[t.task_id,t.source_declared_cwe_ids[0],t.source_declared_cwe_ids[1]||'',t.language,t.source_lineage_id,poolIds.has(t.task_id)?1:0,screening.get(t.task_id),t.near_duplicate_group_id,t.prompt_sha256])];
  const memberRows=[['来源记录 ID','任务 ID','来源数据集 ID','来源定位','版本'],
    ...base.flatMap(t=>t.source_members.map(m=>[m.record_id,t.task_unit_id,m.dataset_id,m.source_locator,m.source_version]))];
  const cweRows=[['CWE','简称','全量身份','候选池任务','其中 Python','其他语言','任务模式示例（未穷尽）','依据示例数','来源名称','条目类型','英文名称']];
  rows.forEach((r,i)=>{const n=i+2;
    const count = (extra='') => ['B','C'].map(c=>`COUNTIFS('任务清单'!$${c}$2:$${c}$${T},A${n}${extra})`).join('+');
    const poolCond=`,\'任务清单\'!$F$2:$F$${T},1`;
    cweRows.push([r.cwe,r.name_zh,formula(count(),r.all_task_identities),formula(count(poolCond),r.pool_task_units),
      formula(count(poolCond+`,\'任务清单\'!$D$2:$D$${T},"python"`),r.python_pool),
      formula(`D${n}-E${n}`,r.other_language_pool),r.descriptive_forms.join('\n'),
      formula(`COUNTIF('模式依据'!$A$2:$A$${E},A${n})`,r.example_task_ids.length),
      Object.keys(r.pool_by_source).map(s=>sources[s][0]).join('\n'),r.entry_type,r.name_en]);
  });
  const srcRows=[['来源','主来源谱系','来源数据集 ID','原始记录','全量任务身份','候选池任务']];
  sourceRows.forEach((s,i)=>{const n=i+2;srcRows.push([s.name,s.source_lineage_id,s.dataset_id,
    formula(`COUNTIF('来源记录'!$C$2:$C$${S},C${n})`,s.original_source_records),
    formula(`COUNTIF('任务清单'!$E$2:$E$${T},B${n})`,s.all_primary_lineage_tasks),
    formula(`COUNTIFS('任务清单'!$E$2:$E$${T},B${n},'任务清单'!$F$2:$F$${T},1)`,s.pool_primary_lineage_tasks)]);});
  srcRows.push(['合计','','',formula('SUM(D2:D8)',report.source_record_count),formula('SUM(E2:E8)',all.length),formula('SUM(F2:F8)',pool.length)]);
  const evidenceRows=[['CWE','描述性任务形式','任务 ID','来源','语言','完整原始 Prompt','来源文件定位','Prompt SHA-256'],
    ...examples.map(e=>[e.cwe,e.form_zh,e.task_id,e.source,e.language,e.source_prompt,e.source_locator,e.prompt_sha256])];
  const infoRows=[['当前数据集：CWE 与任务模式','数值 / 说明'],
    ['不同 CWE 编号',formula(`COUNTA('CWE总表'!A2:A${C})`,cwes.length)],
    ['其中弱点条目',formula(`COUNTIF('CWE总表'!J2:J${C},"Weakness")`,report.weakness_entry_count)],
    ['其中分类条目',formula(`COUNTIF('CWE总表'!J2:J${C},"Category")`,report.category_entry_count)],
    ['全量任务身份',formula(`COUNTA('任务清单'!A2:A${T})`,all.length)],
    ['当前独立候选池',formula(`SUM('任务清单'!F2:F${T})`,pool.length)],
    ['原始来源记录',formula(`COUNTA('来源记录'!A2:A${S})`,report.source_record_count)],
    ['来源示例任务数（不是模式数）',formula(`COUNTA('模式依据'!C2:C${E})`,examples.length)],
    ['候选池 CWE 行和',formula(`SUM('CWE总表'!D2:D${C})`,report.pool_cwe_memberships)],
    ['1–4 个候选任务的 CWE',formula(`COUNTIF('CWE总表'!D2:D${C},"<=4")`,report.pool_size_bands['1-4'])],
    ['5–19 个候选任务的 CWE',formula(`COUNTIFS('CWE总表'!D2:D${C},">=5",'CWE总表'!D2:D${C},"<=19")`,report.pool_size_bands['5-19'])],
    ['至少 20 个候选任务的 CWE',formula(`COUNTIF('CWE总表'!D2:D${C},">=20")`,report.pool_size_bands['20+'])],
    ['模式状态','描述性示例；尚未对全量任务逐题分类、归一化或冻结，因此总模式数与每模式样本数均未确定。'],
    ['数量含义','CWE 数量来自来源标签。标签不证明生成代码存在漏洞，也不证明任务能支持某项干预或安全测量。'],
    ['重复标签','一个任务同时标注 CWE-120/121；CWE 行和比独立任务数多 1。全量身份另有一个依赖变体，已从候选池排除。'],
    ['来源归属','来源汇总按既有代表来源谱系单一归属，保留跨来源去重结果；不是各来源独有贡献数。'],
    ['抽样说明','每 CWE 优先展示不同来源的简洁任务，另补充五个不同形式的实例。只展示存在性，不代表分布或穷尽覆盖。'],
    ['CWE-730','MITRE 将此编号定义为 OWASP Top Ten 2004 A9 拒绝服务 Category。原始标签保留，不当作独立弱点。https://cwe.mitre.org/data/definitions/730.html'],
    ['角色保护','原始 Prompt 示例全部来自未保护候选池；受保护任务仅做元数据计数。没有修改任何角色或资格结果。'],
    ['分析边界','仅盘点原始任务。未调用 API、未读取生成结局或选择器分数、未改动抽取器或概念目录。'],
    ['待审来源','CodeGuard+、SecCodeBench、BaxBench 等本地待审快照未计入已纳入总数；见同目录 README 的范围说明。'],
    ['时间与版本','2026-09-11；research-source-use-v2 + research-candidate-pool-v2。逐文件 SHA-256 见 inventory.json。'],
    ['查看方法','先看 CWE总表；筛选 CWE、来源或语言后，在模式依据页查看对应任务原文。统计数有可重算公式及已核对的显示缓存。'],
  ];
  const sheets=[
    ['说明',infoRows,[38,115],70],
    ['CWE总表',cweRows,[14,28,12,13,13,12,69,13,34,13,64],68],
    ['来源汇总',srcRows,[32,36,35,15,18,18],36],
    ['模式依据',evidenceRows,[13,43,46,32,14,120,70,70],300],
    ['任务清单',rawRows,[48,14,14,15,37,18,49,46,69],30],
    ['来源记录',memberRows,[48,48,34,75,45],30],
  ];
  let styles=fs.readFileSync(path.join(work,'xl/styles.xml'),'utf8');
  function append(tag,content,n=1){styles=styles.replace(new RegExp(`<${tag} count="(\\d+)">([\\s\\S]*?)<\\/${tag}>`),(_,count,body)=>`<${tag} count="${+count+n}">${body}${content}</${tag}>`);}
  append('fonts','<font><b/><sz val="11"/><name val="Microsoft YaHei"/><color rgb="00FFFFFF"/></font><font><sz val="11"/><name val="Microsoft YaHei"/><color rgb="00000000"/></font>',2);
  append('fills','<fill><patternFill patternType="solid"><fgColor rgb="001A365D"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="00EEF4F8"/><bgColor indexed="64"/></patternFill></fill>',2);
  const xf=(font,fill,num=0)=>`<xf numFmtId="${num}" fontId="${font}" fillId="${fill}" borderId="0" xfId="0" applyFont="1" applyFill="1" applyNumberFormat="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>`;
  append('cellXfs',xf(5,3)+xf(6,0)+xf(6,4)+xf(3,0,167)+xf(3,4,167)+xf(2,0,167)+xf(2,4,167),7);
  fs.writeFileSync(path.join(work,'xl/styles.xml'),styles);
  for(let i=0;i<sheets.length;i++){
    const [name,data,widths,height]=sheets[i];
    const dataXML=data.map((rr,j)=>{
      const row=j+1, alt=j%2===0;
      let h=j===0?32:height;
      if(name==='说明'&&j<12)h=30;
      if(name==='CWE总表'&&j>0)h=Math.max(height, String(rr[6]).split('\n').length*16+8, String(rr[8]).split('\n').length*16+8);
      return `<row r="${row}" ht="${h}" customHeight="1">`+rr.map((v,k)=>{
        const address=col(k+1)+row;
        const f=v&&typeof v==='object'&&'f'in v;
        const st=j===0?13:f?(v.f.includes('!')?(alt?17:16):(alt?19:18)):(alt?15:14);
        if(f)return `<c r="${address}" s="${st}"><f>${esc(v.f)}</f><v>${v.v}</v></c>`;
        if(typeof v==='number')return `<c r="${address}" s="${st}"><v>${v}</v></c>`;
        return `<c r="${address}" t="s" s="${st}"><v>${si(String(v??''))}</v></c>`;
      }).join('')+'</row>';
    }).join('');
    const filter=name==='说明'?'':`<autoFilter ref="A1:${col(widths.length)}${data.length}"/>`;
    const xml=decl+`<worksheet xmlns="${ns}"><dimension ref="A1:${col(widths.length)}${data.length}"/><sheetViews><sheetView workbookViewId="0" showGridLines="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><sheetFormatPr defaultRowHeight="18"/><cols>`+widths.map((w,k)=>`<col min="${k+1}" max="${k+1}" width="${w}" customWidth="1"/>`).join('')+`</cols><sheetData>${dataXML}</sheetData>${filter}<pageMargins left="0.3" right="0.3" top="0.5" bottom="0.5" header="0.2" footer="0.2"/><pageSetup orientation="landscape" fitToWidth="1" fitToHeight="0"/></worksheet>`;
    fs.writeFileSync(path.join(work,`xl/worksheets/sheet${i+1}.xml`),xml);
  }
  fs.writeFileSync(path.join(work,'xl/sharedStrings.xml'),decl+`<sst xmlns="${ns}" count="${stringRefs}" uniqueCount="${strings.length}">`+strings.map(s=>`<si><t xml:space="preserve">${esc(s)}</t></si>`).join('')+'</sst>');
  fs.writeFileSync(path.join(work,'xl/workbook.xml'),decl+`<workbook xmlns="${ns}" xmlns:r="${sns}"><sheets>`+sheets.map((s,i)=>`<sheet name="${s[0]}" sheetId="${i+1}" r:id="rId${i===0?1:i+3}"/>`).join('')+'</sheets><calcPr calcId="191029" fullCalcOnLoad="1" forceFullCalc="1"/></workbook>');
  fs.writeFileSync(path.join(work,'xl/_rels/workbook.xml.rels'),decl+'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'+sheets.map((s,i)=>`<Relationship Id="rId${i===0?1:i+3}" Type="${sns}/worksheet" Target="worksheets/sheet${i+1}.xml"/>`).join('')+`<Relationship Id="rId2" Type="${sns}/styles" Target="styles.xml"/><Relationship Id="rId3" Type="${sns}/sharedStrings" Target="sharedStrings.xml"/></Relationships>`);
  const ct='application/vnd.openxmlformats-officedocument.spreadsheetml';
  fs.writeFileSync(path.join(work,'[Content_Types].xml'),decl+'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'+`<Override PartName="/xl/workbook.xml" ContentType="${ct}.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="${ct}.styles+xml"/><Override PartName="/xl/sharedStrings.xml" ContentType="${ct}.sharedStrings+xml"/>`+sheets.map((s,i)=>`<Override PartName="/xl/worksheets/sheet${i+1}.xml" ContentType="${ct}.worksheet+xml"/>`).join('')+'</Types>');
  console.log(JSON.stringify({xlsx_xml:rel(work), sheets:sheets.map(s=>s[0])}));
}
console.log(JSON.stringify({cwes:cwes.length,weaknesses:report.weakness_entry_count,all:all.length,pool:pool.length,examples:examples.length}));
