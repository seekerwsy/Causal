.libPaths(c('.codex-runtime/r-lib',.libPaths()))
suppressPackageStartupMessages(library(pcalg))
suppressPackageStartupMessages(library(jsonlite))
args <- commandArgs(trailingOnly=TRUE)
stopifnot(length(args)==3L,as.character(packageVersion('pcalg'))=='2.7.12')
parent <- args[1]
maximum <- as.integer(args[3])
files <- sort(list.files(file.path(parent,'cells'),pattern='^result.json$',recursive=TRUE,full.names=TRUE))
if (maximum>0L) files <- head(files,maximum)
key <- function(x,y,S) toJSON(list(pair=sort(c(x,y)),conditioned=sort(as.character(S))),auto_unbox=FALSE)
traces <- list()
for (file_index in seq_along(files)) {
  cell <- fromJSON(files[file_index],simplifyVector=FALSE)
  if(!is.null(cell$graph$majority_rule) && isTRUE(cell$graph$majority_rule)) {
    labels <- c('C1','C2',sprintf('X%02d',0:63))
    p <- length(labels)
    lookup <- new.env(hash=TRUE,parent=emptyenv())
    for(query in cell$queries) lookup[[key(query$x,query$y,unlist(query$conditioned))]] <- query
    checked <- function(x,y,S,suffStat) {
      query <- lookup[[key(labels[x],labels[y],labels[S])]]
      if(is.null(query)) stop('缺少冻结属性查询')
      if(is.null(query$p)) stop(structure(list(message='条件查询没有支持',call=NULL),
        class=c('unsupported_ci','error','condition')))
      query$p
    }
    gaps <- matrix(FALSE,p,p)
    gaps[1:2,1:2] <- TRUE
    diag(gaps) <- FALSE
    actual <- tryCatch({
      fit <- fci(list(),checked,alpha=.05,labels=labels,type='anytime',fixedGaps=gaps,
        skel.method='stable',NAdelete=FALSE,m.max=cell$graph$maximum_skeleton_conditioning_order,
        pdsep.max=Inf,conservative=FALSE,maj.rule=TRUE,selectionBias=FALSE,jci='12',contextVars=1:2,verbose=FALSE)
      list(status='evaluated',pag=fit@amat,ancestry=pag2anc(fit@amat))
    },unsupported_ci=function(condition) list(status='insufficient_support'))
    stopifnot(identical(actual$status,cell$graph$status))
    if(actual$status=='evaluated') {
      expected <- do.call(rbind,lapply(cell$graph$pag,unlist))
      ancestry <- do.call(rbind,lapply(cell$graph$ancestry,unlist))
      stopifnot(all(expected==actual$pag),all(ancestry==actual$ancestry))
    }
    traces[[length(traces)+1L]] <- list(cell=basename(dirname(files[file_index])),method='native_attribute_majority',status=actual$status)
    if(file_index%%8L==0L) cat('属性图原生重放完成:',file_index,'cells\n',file=stderr())
    next
  }
  if(!is.null(cell$graphs)) {
    labels <- unlist(cell$labels)
    stopifnot(identical(labels,c('C1','C2',sprintf('X%02d',0:63))))
    p <- length(labels)
    lookup <- new.env(hash=TRUE,parent=emptyenv())
    for(query in cell$queries) lookup[[key(query$x,query$y,unlist(query$conditioned))]] <- query
    checked <- function(x,y,S,suffStat) {
      answer <- lookup[[key(labels[x],labels[y],labels[S])]]
      if(is.null(answer)) stop('缺少冻结条件查询')
      if(is.null(answer$p)) stop(structure(list(message='条件查询没有支持',call=NULL),
        class=c('unsupported_ci','error','condition')))
      stopifnot(is.finite(answer$p))
      answer$p
    }
    gaps <- matrix(FALSE,p,p)
    gaps[1:2,1:2] <- TRUE
    diag(gaps) <- FALSE
    for(method in c('attribute_standard','attribute_majority')) {
      saved <- cell$graphs[[method]]
      actual <- tryCatch({
        fit <- fci(list(),checked,alpha=.05,labels=labels,type='anytime',fixedGaps=gaps,
          skel.method='stable',NAdelete=FALSE,m.max=2,pdsep.max=Inf,conservative=FALSE,
          maj.rule=identical(method,'attribute_majority'),selectionBias=FALSE,jci='12',contextVars=1:2,verbose=FALSE)
        list(status='evaluated',pag=fit@amat,ancestry=pag2anc(fit@amat))
      },unsupported_ci=function(condition) list(status='insufficient_support'))
      stopifnot(identical(actual$status,saved$status))
      if(actual$status=='evaluated') {
        expected <- do.call(rbind,lapply(saved$pag,unlist))
        ancestry <- do.call(rbind,lapply(saved$ancestry,unlist))
        stopifnot(identical(dim(expected),dim(actual$pag)),all(expected==actual$pag),all(ancestry==actual$ancestry))
      }
      traces[[length(traces)+1L]] <- list(cell=basename(dirname(files[file_index])),method=method,status=actual$status)
    }
    next
  }
  for (sample_index in seq_along(cell$learned$graphs)) {
    saved <- cell$learned$graphs[[sample_index]]
    labels <- unlist(saved$labels)
    p <- length(labels)
    width <- (p-1L)/2L
    stopifnot(width==4L)
    lookup <- new.env(hash=TRUE,parent=emptyenv())
    for (query in saved$queries) {
      lookup[[key(query$x,query$y,unlist(query$conditioned))]] <- query
    }
    checked <- function(x,y,S,suffStat) {
      query <- lookup[[key(labels[x],labels[y],labels[S])]]
      if (is.null(query)) stop(paste('Missing frozen query:',key(labels[x],labels[y],labels[S])))
      stopifnot(is.finite(query$p))
      pair <- key(labels[x],labels[y],character())
      if (query$p>=.05 && is.null(removals[[pair]])) removals[[pair]] <- query
      query$p
    }
    for (method in c('time','jci12','jci123')) {
      mode <- switch(method,time='1',jci12='12',jci123='123')
      removals <- new.env(hash=TRUE,parent=emptyenv())
      fit <- fci(list(),checked,alpha=.05,labels=labels,skel.method='stable',NAdelete=FALSE,
        m.max=Inf,pdsep.max=Inf,rules=rep(TRUE,10),doPdsep=TRUE,selectionBias=FALSE,
        jci=mode,contextVars=seq_len(width),verbose=FALSE)
      initial <- pag2anc(fit@amat)
      pag <- fit@amat
      rules <- rep(TRUE,10)
      rules[5:7] <- FALSE
      for (iteration in seq_len(100)) {
        previous <- pag
        pag <- udag2pag(pag,fit@sepset,rules=rules,jci='1',contextVars=seq_len(p-1),orientCollider=FALSE)
        pag <- udag2pag(pag,fit@sepset,rules=rules,jci=mode,contextVars=seq_len(width),orientCollider=FALSE)
        if (identical(previous,pag)) break
        stopifnot(iteration<100)
      }
      expected <- do.call(rbind,lapply(saved$results[[method]]$pag,unlist))
      stopifnot(all(dim(expected)==dim(pag)),all(expected==pag))
      ancestry <- pag2anc(pag)
      for (policy in seq_len(width)) {
        query <- if (pag[policy,p]==0L) removals[[key(labels[policy],labels[p],character())]] else NULL
        if (pag[policy,p]==0L) stopifnot(!is.null(query),query$p>=.05)
        traces[[length(traces)+1L]] <- list(cell=paste(cell$mechanism,cell$n,sprintf('%02d',cell$repetition),sep='-'),
          mechanism=cell$mechanism,n=cell$n,repetition=cell$repetition,sample=sample_index-1L,method=method,
          policy=policy-1L,beta=unlist(cell$beta)[policy],initial_ancestry=initial[policy,p],
          final_ancestry=ancestry[policy,p],context_outcome_adjacent=pag[policy,p]!=0L,
          context_target_adjacent=pag[policy,width+policy]!=0L,target_outcome_adjacent=pag[width+policy,p]!=0L,
          separating_set=if (is.null(query)) list() else query$conditioned,removal_query=query)
      }
    }
  }
  if (file_index%%8L==0L) cat('Frozen FCI traces replayed:',file_index,'cells\n',file=stderr())
}
writeLines(toJSON(list(cells=length(files),traces=traces,pcalg=as.character(packageVersion('pcalg'))),
  auto_unbox=TRUE,null='null',digits=16),args[2],useBytes=TRUE)
