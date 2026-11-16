from __future__ import annotations

from collections import deque
import hashlib
import itertools
import json
import os
from pathlib import Path
import subprocess
import time

import networkx as nx
import numpy as np
from scipy.stats import random_table


class ConditionalPermutation:
    def __init__(self, data, labels, draws, seed, minimum_per_level=0):
        raw = np.asarray(data)
        if raw.ndim != 2 or raw.dtype.kind not in 'biuf' or not np.isfinite(raw).all() or np.any(raw != np.floor(raw)):
            raise ValueError('Conditional permutation test requires finite discrete integer observations')
        self.data, self.labels = raw.astype(int), tuple(labels)
        self.draws, self.seed, self.cache = draws, seed, {}
        self.minimum_per_level = minimum_per_level
        if self.data.shape[1] != len(labels) or draws < 99:
            raise ValueError('Invalid conditional test dimensions or permutation count')

    def query(self, x, y, conditioned):
        x, y = sorted((x, y))
        conditioned = tuple(sorted(conditioned))
        key = (x, y, conditioned)
        if key in self.cache:
            return self.cache[key]['p']
        indexes = {name: i for i, name in enumerate(self.labels)}
        columns = [indexes[name] for name in conditioned]
        _, groups = (
            np.unique(self.data[:, columns], axis=0, return_inverse=True)
            if columns
            else (None, np.zeros(len(self.data), dtype=int))
        )
        query_seed = int.from_bytes(hashlib.sha256(json.dumps([self.seed, key]).encode()).digest()[:8], 'big')
        rng = np.random.default_rng(query_seed)
        observed, simulated, informative = 0.0, np.zeros(self.draws), 0
        tables = []
        for group in np.unique(groups):
            rows = self.data[groups == group]
            _, xi = np.unique(rows[:, indexes[x]], return_inverse=True)
            _, yi = np.unique(rows[:, indexes[y]], return_inverse=True)
            table = np.zeros((xi.max() + 1, yi.max() + 1), dtype=int)
            np.add.at(table, (xi, yi), 1)
            tables.append(table.tolist())
            if min(table.shape) == 1:
                continue
            informative += 1
            expected = np.outer(table.sum(1), table.sum(0)) / table.sum()
            observed += float(np.sum((table - expected) ** 2 / expected))
            null = random_table.rvs(table.sum(1), table.sum(0), size=self.draws, random_state=rng)
            simulated += np.sum((null - expected) ** 2 / expected, axis=(1, 2))
        exceedances = int(np.count_nonzero(simulated >= observed - 1e-12))
        p = (1 + exceedances) / (1 + self.draws)
        supported = informative > 0
        if self.minimum_per_level:
            supported = supported and all(
                min(np.asarray(table).shape) > 1
                and min(np.asarray(table).sum(0)) >= self.minimum_per_level
                and min(np.asarray(table).sum(1)) >= self.minimum_per_level
                for table in tables
            )
        if not supported:
            p = None
        self.cache[key] = dict(
            x=x,
            y=y,
            conditioned=list(conditioned),
            p=p,
            statistic=observed,
            informative_strata=informative,
            tables=tables,
            exceedances=exceedances,
            status='tested' if supported else 'insufficient_support',
        )
        return p


def _iter_unique_subsets(neighbors_a, neighbors_b, size):
    seen = set()
    for pool in (neighbors_a, neighbors_b):
        if len(pool) < size:
            continue
        for comb in itertools.combinations(pool, size):
            if comb not in seen:
                seen.add(comb)
                yield comb


def _is_potentially_directed_edge(pag, u, v):
    return pag[u, v] != 0 and pag[v, u] != 2 and pag[u, v] != 3


def _find_discriminating_paths(pag, adj, y, z):
    """Find discriminating paths <x, ..., w, y, z> for node y with circle mark at y on (z, y)."""
    p = pag.shape[0]
    definite_parents_of_z = {
        v for v in range(p) if v not in (y, z) and pag[v, z] == 2 and pag[z, v] == 3
    }
    if not definite_parents_of_z:
        return []
    paths = []
    # BFS backwards from y through colliders that are definite parents of z.
    queue = deque([[y]])
    while queue:
        rev_path = queue.popleft()
        curr = rev_path[-1]
        for prev in range(p):
            if prev in rev_path or prev == z or not adj[prev, curr]:
                continue
            # If curr is not y, it must be a collider on prev *-> curr <-* rev_path[-2]
            if curr != y and not (pag[prev, curr] == 2 and pag[rev_path[-2], curr] == 2):
                continue
            if not adj[prev, z] and len(rev_path) >= 2:
                # Candidate discriminating path: [prev, ...rev_path[::-1], z]
                paths.append(list(reversed([z, *rev_path, prev])))
                return paths
            if prev in definite_parents_of_z and len(rev_path) < 8:
                queue.append([*rev_path, prev])
    return paths


def _uncovered_pd_paths(pag, adj, start, target):
    """Find uncovered potentially directed paths from start to target (length >= 3)."""
    p = pag.shape[0]
    queue = deque([[start]])
    results = []
    while queue:
        path = queue.popleft()
        curr = path[-1]
        if len(path) >= 3 and curr == target:
            results.append(path)
            continue
        if len(path) >= 8:
            continue
        prev = path[-2] if len(path) >= 2 else None
        for nxt in range(p):
            if nxt in path or not adj[curr, nxt]:
                continue
            if not _is_potentially_directed_edge(pag, curr, nxt):
                continue
            if prev is not None and adj[prev, nxt]:
                continue
            queue.append([*path, nxt])
    return results


def discover_jci_pag(
    labels,
    ci,
    alpha,
    *,
    context_vars=('C1', 'C2'),
    max_order=3,
    majority_rule=True,
):
    """Native Python FCI + JCI-12 (exogenous context) PAG discovery.

    PAG endpoint convention matches pcalg: pag[i, j] stores the mark AT node j
    on edge (i, j), where 0=none, 1=circle, 2=arrowhead, 3=tail.
    """
    labels = list(labels)
    p = len(labels)
    if any(name not in labels for name in context_vars):
        raise ValueError('Declared context variables must be present in labels')
    roots = tuple(labels.index(name) for name in context_vars)
    root_set = set(roots)

    adj = np.ones((p, p), dtype=bool)
    np.fill_diagonal(adj, False)
    for r1 in roots:
        for r2 in roots:
            adj[r1, r2] = False

    sepset: dict[tuple[int, int], tuple[int, ...]] = {}
    largest_conditioning = 0

    def abort_insufficient():
        return dict(
            type='result',
            status='insufficient_support',
            pag=None,
            ancestry=None,
            separating_sets=[],
            conservative=not majority_rule,
            majority_rule=bool(majority_rule),
            maximum_skeleton_conditioning_order=int(max_order),
            maximum_conditioning_order=int(largest_conditioning),
            context_variables=[labels[r] for r in roots],
            backend='python-jci12',
        )

    order = 0
    while order <= max_order:
        snap = {i: sorted(np.flatnonzero(adj[i]).tolist()) for i in range(p)}
        if not any(
            adj[i, j] and (len(snap[i]) - 1 >= order or len(snap[j]) - 1 >= order)
            for i in range(p)
            for j in range(i + 1, p)
        ):
            break
        removals = []
        for i in range(p):
            for j in range(i + 1, p):
                if not adj[i, j]:
                    continue
                neigh_i = [n for n in snap[i] if n != j]
                neigh_j = [n for n in snap[j] if n != i]
                for comb in _iter_unique_subsets(neigh_i, neigh_j, order):
                    largest_conditioning = max(largest_conditioning, len(comb))
                    p_val = ci.query(labels[i], labels[j], [labels[idx] for idx in comb])
                    if p_val is None:
                        return abort_insufficient()
                    if p_val > alpha:
                        sepset[(i, j)] = comb
                        removals.append((i, j))
                        break
        for i, j in removals:
            adj[i, j] = adj[j, i] = False
        order += 1

    pag = adj.astype(int)
    # JCI-12 exogenous context orientation: r -> z for all r in roots, z not in roots.
    for r in roots:
        for z in range(p):
            if adj[r, z] and z not in root_set:
                pag[r, z] = 2
                pag[z, r] = 3

    ambiguous_triples: set[tuple[int, int, int]] = set()
    for y in range(p):
        if y in root_set:
            continue
        neighbors = sorted(np.flatnonzero(adj[y]).tolist())
        for idx_a in range(len(neighbors)):
            i = neighbors[idx_a]
            for idx_b in range(idx_a + 1, len(neighbors)):
                k = neighbors[idx_b]
                if adj[i, k]:
                    continue
                pair = (min(i, k), max(i, k))
                if majority_rule:
                    neigh_i = [n for n in np.flatnonzero(adj[i]).tolist() if n != k]
                    neigh_k = [n for n in np.flatnonzero(adj[k]).tolist() if n != i]
                    sep_list = []
                    base_sep = sepset.get(pair)
                    if base_sep is not None:
                        sep_list.append(base_sep)
                    cap_order = min(max_order, 2 if max(len(neigh_i), len(neigh_k)) > 8 else max_order)
                    for sub_ord in range(cap_order + 1):
                        for comb in _iter_unique_subsets(neigh_i, neigh_k, sub_ord):
                            if comb == base_sep:
                                continue
                            largest_conditioning = max(largest_conditioning, len(comb))
                            p_val = ci.query(labels[pair[0]], labels[pair[1]], [labels[idx] for idx in comb])
                            if p_val is None:
                                return abort_insufficient()
                            if p_val > alpha:
                                sep_list.append(comb)
                    if not sep_list:
                        continue
                    frac_with_y = sum(1 for comb in sep_list if y in comb) / len(sep_list)
                    if frac_with_y < 0.5:
                        pag[i, y] = 2
                        pag[k, y] = 2
                    elif frac_with_y == 0.5:
                        ambiguous_triples.add((pair[0], y, pair[1]))
                else:
                    base_sep = sepset.get(pair, ())
                    if y not in base_sep:
                        pag[i, y] = 2
                        pag[k, y] = 2

    def orient_mark(u, v, mark):
        if mark == 2 and v in root_set:
            return False
        if pag[u, v] == mark:
            return False
        pag[u, v] = mark
        return True

    # Zhang (2008) PAG orientation rules R1-R4, R8-R10 (selectionBias=False).
    for _ in range(100):
        changed = False
        # R1: a *-> b o-* c (a, c non-adjacent, unambiguous) => b -> c
        for b in range(p):
            if b in root_set:
                continue
            adj_b = np.flatnonzero(adj[b]).tolist()
            for a in adj_b:
                if pag[a, b] != 2:
                    continue
                for c in adj_b:
                    if c == a or adj[a, c] or pag[c, b] != 1:
                        continue
                    if (min(a, c), b, max(a, c)) in ambiguous_triples:
                        continue
                    changed |= orient_mark(b, c, 2)
                    changed |= orient_mark(c, b, 3)

        # R2: (a -> b *-> c or a *-> b -> c) and a *-o c => a *-> c
        for a in range(p):
            for c in np.flatnonzero(adj[a]).tolist():
                if pag[a, c] != 1 or c in root_set:
                    continue
                for b in np.flatnonzero(adj[a]).tolist():
                    if b == c or not adj[b, c]:
                        continue
                    cond1 = pag[a, b] == 2 and pag[b, a] == 3 and pag[b, c] == 2
                    cond2 = pag[a, b] == 2 and pag[b, c] == 2 and pag[c, b] == 3
                    if cond1 or cond2:
                        changed |= orient_mark(a, c, 2)
                        break

        # R3: a *-> b <-* c (not adj(a,c)), a *-o d o-* c, d *-o b => d *-> b
        for b in range(p):
            if b in root_set:
                continue
            into_b = [x for x in np.flatnonzero(adj[b]).tolist() if pag[x, b] == 2]
            circle_b = [d for d in np.flatnonzero(adj[b]).tolist() if pag[d, b] == 1]
            if len(into_b) < 2 or not circle_b:
                continue
            for idx_a in range(len(into_b)):
                a = into_b[idx_a]
                for idx_c in range(idx_a + 1, len(into_b)):
                    c = into_b[idx_c]
                    if adj[a, c]:
                        continue
                    for d in circle_b:
                        if adj[a, d] and adj[c, d] and pag[a, d] == 1 and pag[c, d] == 1:
                            if (min(a, c), d, max(a, c)) not in ambiguous_triples:
                                changed |= orient_mark(d, b, 2)

        # R4: Discriminating paths
        for y in range(p):
            if y in root_set:
                continue
            for z in np.flatnonzero(adj[y]).tolist():
                if pag[z, y] != 1 or z in root_set:
                    continue
                for path in _find_discriminating_paths(pag, adj, y, z):
                    x, w = path[0], path[-3]
                    pair = (min(x, z), max(x, z))
                    sep = sepset.get(pair, ())
                    if y in sep:
                        changed |= orient_mark(y, z, 2)
                        changed |= orient_mark(z, y, 3)
                    else:
                        changed |= orient_mark(w, y, 2)
                        changed |= orient_mark(y, w, 2)
                        changed |= orient_mark(y, z, 2)
                        changed |= orient_mark(z, y, 2)

        # R8: (a -> b or a -o b) and b -> c and a o-> c => a -> c
        for a in range(p):
            for c in np.flatnonzero(adj[a]).tolist():
                if not (pag[a, c] == 2 and pag[c, a] == 1):
                    continue
                for b in np.flatnonzero(adj[a]).tolist():
                    if b == c or not adj[b, c]:
                        continue
                    if pag[b, a] == 3 and pag[a, b] in (1, 2) and pag[b, c] == 2 and pag[c, b] == 3:
                        changed |= orient_mark(c, a, 3)
                        break

        # R9: a o-> c and uncovered p.d. path <a, b, ..., c> with not adj(b, c) => a -> c
        for a in range(p):
            for c in np.flatnonzero(adj[a]).tolist():
                if not (pag[a, c] == 2 and pag[c, a] == 1):
                    continue
                for path in _uncovered_pd_paths(pag, adj, a, c):
                    if not adj[path[1], c]:
                        changed |= orient_mark(c, a, 3)
                        break

        # R10: a o-> c, b -> c <- d, uncovered p.d. paths a..b and a..d with distinct non-adj first steps => a -> c
        for c in range(p):
            if c in root_set:
                continue
            parents_c = [x for x in np.flatnonzero(adj[c]).tolist() if pag[x, c] == 2 and pag[c, x] == 3]
            if len(parents_c) < 2:
                continue
            for a in np.flatnonzero(adj[c]).tolist():
                if not (pag[a, c] == 2 and pag[c, a] == 1):
                    continue
                paths_by_parent = {
                    b: _uncovered_pd_paths(pag, adj, a, b)
                    for b in parents_c
                    if b != a
                }
                oriented = False
                for idx1 in range(len(parents_c)):
                    b = parents_c[idx1]
                    if b == a or not paths_by_parent.get(b):
                        continue
                    for idx2 in range(idx1 + 1, len(parents_c)):
                        d = parents_c[idx2]
                        if d == a or not paths_by_parent.get(d):
                            continue
                        for p1 in paths_by_parent[b]:
                            for p2 in paths_by_parent[d]:
                                if p1[1] != p2[1] and not adj[p1[1], p2[1]]:
                                    changed |= orient_mark(c, a, 3)
                                    oriented = True
                                    break
                            if oriented:
                                break
                        if oriented:
                            break
                    if oriented:
                        break

        if not changed:
            break

    directed = nx.DiGraph()
    directed.add_nodes_from(range(p))
    directed.add_edges_from((int(u), int(v)) for u, v in np.argwhere((pag == 2) & (pag.T == 3)))
    ancestry = np.zeros((p, p), dtype=int)
    for u in range(p):
        for v in nx.descendants(directed, u):
            ancestry[u, v] = 1
    return dict(
        type='result',
        status='evaluated',
        pag=pag.tolist(),
        ancestry=ancestry.tolist(),
        ambiguous_triples=[list(item) for item in sorted(ambiguous_triples)],
        conservative=not majority_rule,
        majority_rule=bool(majority_rule),
        maximum_skeleton_conditioning_order=int(max_order),
        maximum_conditioning_order=int(largest_conditioning),
        context_variables=[labels[r] for r in roots],
        backend='python-jci12',
    )


class StructureBackend:
    def __init__(self, rscript=None, log=None, r_source=None):
        self.rscript = None if rscript is None or str(rscript).lower() == 'native' else Path(rscript)
        self.log = log
        self.process = None
        if self.rscript is not None:
            environment = dict(
                os.environ,
                LC_ALL='C',
                LANG='C',
                LC_COLLATE='C',
                LC_CTYPE='C',
                LC_MONETARY='C',
                LC_TIME='C',
            )
            log_path = Path(log)
            temporary = log_path.parent.resolve() / 'r-tmp'
            temporary.mkdir(mode=0o700, exist_ok=True)
            environment.update(TMPDIR=str(temporary), TMP=str(temporary), TEMP=str(temporary))
            source = Path(__file__).with_name('jci_context.R') if r_source is None else Path(r_source)
            if not source.is_file():
                raise FileNotFoundError(source)
            self._log_handle = log_path.open('x', encoding='utf-8')
            self.process = subprocess.Popen(
                [str(self.rscript), str(source)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=self._log_handle,
                text=True,
                encoding='utf-8',
                env=environment,
            )

    def search(self, labels, method, ci, alpha, *, max_order=3, context_vars=('C1', 'C2')):
        started = time.monotonic()
        if self.process is None:
            majority = method in ('attribute_majority', 'attribute_majority_merged', 'python-jci12', 'jci12')
            answer = discover_jci_pag(
                labels,
                ci,
                alpha,
                context_vars=context_vars,
                max_order=max_order,
                majority_rule=majority,
            )
            answer['seconds'] = time.monotonic() - started
            if self.log is not None:
                Path(self.log).write_text(
                    json.dumps(
                        dict(
                            backend=answer['backend'],
                            status=answer['status'],
                            queries=len(ci.cache),
                            seconds=answer['seconds'],
                        ),
                        indent=2,
                    ),
                    encoding='utf-8',
                )
            return answer

        self.process.stdin.write(json.dumps(dict(labels=labels, method=method, alpha=alpha)) + '\n')
        self.process.stdin.flush()
        while True:
            line = self.process.stdout.readline()
            if not line:
                raise RuntimeError(f'FCI backend terminated unexpectedly with code {self.process.poll()}')
            answer = json.loads(line)
            if answer['type'] == 'result':
                answer['seconds'] = time.monotonic() - started
                answer.setdefault('backend', 'r-pcalg')
                return answer
            if answer['type'] != 'query':
                raise ValueError('Structure backend returned an invalid message type')
            p = ci.query(answer['x'], answer['y'], answer['conditioned'])
            self.process.stdin.write(json.dumps(dict(p=p)) + '\n')
            self.process.stdin.flush()

    def close(self):
        if self.process is not None:
            self.process.stdin.close()
            code = self.process.wait(timeout=30)
            self.process.stdout.close()
            self._log_handle.close()
            if code:
                raise RuntimeError(f'Structure backend exited with non-zero status: {code}')
