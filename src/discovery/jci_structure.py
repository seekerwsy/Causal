from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

import numpy as np
from scipy.stats import random_table


class ConditionalPermutation:
    def __init__(self, data, labels, draws, seed):
        self.data, self.labels = np.asarray(data, dtype=int), tuple(labels)
        self.draws, self.seed, self.cache = draws, seed, {}
        if self.data.shape[1] != len(labels) or draws < 99:
            raise ValueError('条件检验输入或抽样数量无效')

    def query(self, x, y, conditioned):
        x, y = sorted((x, y))
        conditioned = tuple(sorted(conditioned))
        key = (x, y, conditioned)
        if key in self.cache:
            return self.cache[key]['p']
        indexes = {name: i for i, name in enumerate(self.labels)}
        columns = [indexes[name] for name in conditioned]
        _, groups = np.unique(self.data[:, columns], axis=0, return_inverse=True) if columns else (
            None, np.zeros(len(self.data), dtype=int))
        query_seed = int.from_bytes(hashlib.sha256(json.dumps([self.seed, key]).encode()).digest()[:8], 'big')
        rng = np.random.default_rng(query_seed)
        observed, simulated, informative = 0., np.zeros(self.draws), 0
        tables = []
        for group in np.unique(groups):
            rows = self.data[groups == group]
            _, xi = np.unique(rows[:, indexes[x]], return_inverse=True)
            _, yi = np.unique(rows[:, indexes[y]], return_inverse=True)
            table = np.zeros((xi.max()+1, yi.max()+1), dtype=int)
            np.add.at(table, (xi, yi), 1)
            tables.append(table.tolist())
            if min(table.shape) == 1:
                continue
            informative += 1
            expected = np.outer(table.sum(1), table.sum(0))/table.sum()
            observed += float(np.sum((table-expected)**2/expected))
            null = random_table.rvs(table.sum(1), table.sum(0), size=self.draws, random_state=rng)
            simulated += np.sum((null-expected)**2/expected, axis=(1, 2))
        exceedances = int(np.count_nonzero(simulated >= observed-1e-12))
        p = (1+exceedances)/(1+self.draws)
        self.cache[key] = dict(x=x, y=y, conditioned=list(conditioned), p=p, statistic=observed,
                               informative_strata=informative, tables=tables, exceedances=exceedances)
        return p


class StructureBackend:
    def __init__(self, rscript, log, r_source=None):
        environment = dict(os.environ, LC_ALL='C', LANG='C', LC_COLLATE='C', LC_CTYPE='C',
                           LC_MONETARY='C', LC_TIME='C')
        source = Path(__file__).with_name('jci_sharing.R') if r_source is None else Path(r_source)
        if not source.is_file():
            raise FileNotFoundError(source)
        self.log = log.open('x', encoding='utf-8')
        self.process = subprocess.Popen([str(rscript), str(source)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log, text=True, encoding='utf-8',
            env=environment)

    def search(self, labels, method, ci, alpha):
        started = time.monotonic()
        self.process.stdin.write(json.dumps(dict(labels=labels, method=method, alpha=alpha))+'\n')
        self.process.stdin.flush()
        while True:
            line = self.process.stdout.readline()
            if not line:
                raise RuntimeError(f'真实 FCI 后端终止，退出状态 {self.process.poll()}；请核对后端日志')
            answer = json.loads(line)
            if answer['type'] == 'result':
                answer['seconds'] = time.monotonic()-started
                return answer
            if answer['type'] != 'query':
                raise ValueError('结构后端返回了未规定的记录')
            p = ci.query(answer['x'], answer['y'], answer['conditioned'])
            self.process.stdin.write(json.dumps(dict(p=p))+'\n')
            self.process.stdin.flush()

    def close(self):
        self.process.stdin.close()
        code = self.process.wait(timeout=30)
        self.process.stdout.close()
        self.log.close()
        if code:
            raise RuntimeError(f'结构后端退出状态异常：{code}')
