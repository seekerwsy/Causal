import hashlib

import libcst as cst
from libcst.metadata import (
    Assignment,ByteSpanPositionProvider,ExpressionContext,ExpressionContextProvider,
    MetadataWrapper,ParentNodeProvider,PositionProvider,QualifiedNameProvider,ScopeProvider,
)

from prompt_mechanism_study.records import content_hash,content_id


def source_call_catalog(text,*,source_path):
    encoded = text.encode('utf-8')
    source_sha256 = hashlib.sha256(encoded).hexdigest()
    wrapper = MetadataWrapper(cst.parse_module(text))
    assert wrapper.module.code==text

    class Collector(cst.CSTVisitor):
        METADATA_DEPENDENCIES = (ByteSpanPositionProvider,PositionProvider,ParentNodeProvider,
            ExpressionContextProvider,QualifiedNameProvider,ScopeProvider)

        def __init__(self):
            self.operations = []
            self.reads = []
            self.assignments = []

        def anchor(self,node):
            span = self.get_metadata(ByteSpanPositionProvider,node)
            position = self.get_metadata(PositionProvider,node)
            record = dict(source_path=source_path,source_sha256=source_sha256,
                byte_start=span.start,byte_end=span.start+span.length,
                start_line=position.start.line,start_column=position.start.column,
                end_line=position.end.line,end_column=position.end.column,
                text=encoded[span.start:span.start+span.length].decode('utf-8'),kind=type(node).__name__)
            record['id'] = content_id('source_occurrence_',dict(source_path=source_path,source_sha256=source_sha256,
                byte_start=record['byte_start'],byte_end=record['byte_end'],kind=record['kind']))
            return record

        def parents(self,node):
            current = self.get_metadata(ParentNodeProvider,node,None)
            while current is not None:
                yield current
                current = self.get_metadata(ParentNodeProvider,current,None)

        def context(self,node):
            ancestors = list(self.parents(node))
            lexical = [dict(kind=type(parent).__name__,name=parent.name.value,anchor=self.anchor(parent.name))
                for parent in reversed(ancestors) if isinstance(parent,(cst.FunctionDef,cst.ClassDef))]
            enclosing = next((self.anchor(parent)['id'] for parent in ancestors
                if isinstance(parent,(cst.Call,cst.Subscript,cst.BinaryOperation))),None)
            conditions = []
            for parent in reversed(ancestors):
                if isinstance(parent,(cst.If,cst.IfExp,cst.While)):
                    conditions.append(dict(kind=type(parent).__name__,test=self.anchor(parent.test)))
                elif isinstance(parent,cst.Else):
                    conditions.append(dict(kind='Else',branch={key:value for key,value in self.anchor(parent).items() if key!='text'}))
            return dict(lexical_context=lexical,enclosing_operation_id=enclosing,syntactic_conditions=conditions,
                execution_path_established=False)

        def visit_Call(self,node):
            record = self.anchor(node)
            record.update(self.context(node))
            record['callable'] = self.anchor(node.func)
            names = self.get_metadata(QualifiedNameProvider,node.func,set())
            record['possible_qualified_names'] = sorted([dict(name=value.name,source=value.source.name)
                for value in names],key=lambda value:(value['name'],value['source']))
            record['arguments'] = [dict(keyword=arg.keyword.value if arg.keyword is not None else None,
                star=arg.star,value=self.anchor(arg.value)) for arg in node.args]
            self.operations.append(record)

        def visit_Subscript(self,node):
            record = self.anchor(node)
            record.update(self.context(node))
            record['value'] = self.anchor(node.value)
            self.operations.append(record)

        def visit_BinaryOperation(self,node):
            record = self.anchor(node)
            record.update(self.context(node))
            record.update(operator=type(node.operator).__name__,left=self.anchor(node.left),right=self.anchor(node.right))
            self.operations.append(record)

        def visit_Assign(self,node):
            record = self.anchor(node)
            record.update(self.context(node))
            record.update(targets=[self.anchor(target.target) for target in node.targets],value=self.anchor(node.value))
            self.assignments.append(record)

        def visit_AnnAssign(self,node):
            record = self.anchor(node)
            record.update(self.context(node))
            record.update(targets=[self.anchor(node.target)],value=self.anchor(node.value) if node.value is not None else None)
            self.assignments.append(record)

        def visit_AugAssign(self,node):
            record = self.anchor(node)
            record.update(self.context(node))
            record.update(targets=[self.anchor(node.target)],value=self.anchor(node.value))
            self.assignments.append(record)

        def read(self,node):
            if self.get_metadata(ExpressionContextProvider,node,None)!=ExpressionContext.LOAD:
                return
            record = self.anchor(node)
            record.update(self.context(node))
            names = self.get_metadata(QualifiedNameProvider,node,set())
            record['possible_qualified_names'] = sorted([dict(name=value.name,source=value.source.name)
                for value in names],key=lambda value:(value['name'],value['source']))
            candidates = []
            record['lexical_access_state'] = 'attribute_target_not_resolved'
            if isinstance(node,cst.Name):
                scope = self.get_metadata(ScopeProvider,node,None)
                if scope is None:
                    record['lexical_access_state'] = 'scope_not_available'
                elif node not in scope.accesses:
                    record['lexical_access_state'] = 'not_a_recorded_access'
                else:
                    record['lexical_access_state'] = 'lexical_access'
                    for access in scope.accesses[node]:
                        for assignment in access.referents:
                            candidate = dict(kind=type(assignment).__name__,name=assignment.name)
                            if isinstance(assignment,Assignment):
                                declared = assignment.node.name if isinstance(assignment.node,(cst.FunctionDef,cst.ClassDef)) else assignment.node
                                candidate['anchor'] = self.anchor(declared)
                            candidates.append(candidate)
            unique = {content_hash(value):value for value in candidates}
            record['lexical_assignment_candidates'] = sorted(unique.values(),key=lambda value:(value['name'],
                value.get('anchor',{}).get('byte_start',-1),value['kind']))
            record['runtime_definition_established'] = False
            self.reads.append(record)

        def visit_Name(self,node):
            self.read(node)

        def visit_Attribute(self,node):
            self.read(node)

    collector = Collector()
    wrapper.visit(collector)
    ordered = lambda rows: sorted(rows,key=lambda row:(row['byte_start'],row['byte_end'],row['kind']))
    return dict(source_path=source_path,source_sha256=source_sha256,source_bytes=len(encoded),
        operations=ordered(collector.operations),reads=ordered(collector.reads),assignments=ordered(collector.assignments),
        source_executed=False,source_modified=False,causal_structure_established=False,
        runtime_dataflow_established=False)
