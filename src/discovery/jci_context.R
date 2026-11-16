.libPaths(c('.codex-runtime/r-lib', .libPaths()))
suppressPackageStartupMessages(library(pcalg))
suppressPackageStartupMessages(library(jsonlite))
input <- file('stdin', open='r')
emit <- function(value) {
  cat(toJSON(value, auto_unbox=TRUE, null='null', digits=16), '\n', sep='')
  flush(stdout())
}
repeat {
  line <- readLines(input, n=1L, warn=FALSE)
  if (!length(line)) break
  request <- fromJSON(line)
  labels <- request$labels
  native_attribute <- request$method %in% c('attribute_standard','attribute_majority','attribute_majority_merged')
  majority_attribute <- request$method %in% c('attribute_majority','attribute_majority_merged')
  attribute_order <- if(identical(request$method,'attribute_majority_merged')) 3L else 2L
  stopifnot(!native_attribute || identical(labels,c('C1','C2',sprintf('X%02d',0:63))))
  highdim <- identical(labels,c('C1','C2',sprintf('X%02d',0:63),'Y')) ||
    identical(labels,c('C1','C2',sprintf('X%02d',0:63)))
  domain <- identical(labels,c('E','C1','C2','A','W','X','N','D1','D2','Y'))
  stopifnot(!domain)
  arm_specific <- identical(labels,c('C1','C2','W','X','N','D1','D2','Y')) ||
    identical(labels,c('C1','C2','W','N','D1','D2','Y'))
  directional <- arm_specific || identical(labels,c('C1','C2','A','W','X','N','D1','D2','Y'))
  roots <- match(if(arm_specific || highdim) c('C1','C2') else c('C1','C2','A'),labels)
  stopifnot(highdim || directional || identical(labels, c('E','A','W','Z1','Z2','Y')))
  stopifnot(request$method %in% c('jci','fci_same_knowledge','directional','attribute_standard','attribute_majority','attribute_majority_merged'))
  largest_conditioning <- 0L
  checked <- function(x,y,S,suffStat) {
    largest_conditioning <<- max(largest_conditioning,length(S))
    emit(list(type='query',x=labels[x],y=labels[y],conditioned=as.list(labels[S])))
    answer <- fromJSON(readLines(input,n=1L,warn=FALSE))
    if (is.null(answer$p)) stop(structure(list(message='条件检验缺少支持',call=NULL),
      class=c('unsupported_ci','error','condition')))
    stopifnot(is.finite(answer$p), answer$p>=0, answer$p<=1)
    answer$p
  }
  p <- length(labels)
  gaps <- matrix(FALSE,p,p)
  if (directional) {
    contexts <- match(c('C1','C2'),labels)
    baseline <- match(c('W','D1','D2'),labels)
    assigned <- match('A',labels)
    before <- setdiff(seq_len(p),match('Y',labels))
    gaps[roots,roots] <- TRUE
    gaps[contexts,baseline] <- TRUE
    gaps[baseline,contexts] <- TRUE
    if(!arm_specific) {
      gaps[assigned,before] <- TRUE
      gaps[before,assigned] <- TRUE
    }
  } else if(highdim) gaps[roots,roots] <- TRUE else gaps[1:3,1:3] <- TRUE
  diag(gaps) <- FALSE
  result <- tryCatch({
  if(highdim) {
    graph <- fci(list(),checked,alpha=request$alpha,labels=labels,type='anytime',
      fixedGaps=gaps,skel.method='stable',NAdelete=FALSE,m.max=attribute_order,pdsep.max=Inf,
      conservative=FALSE,maj.rule=majority_attribute,selectionBias=FALSE,jci='12',contextVars=roots,verbose=FALSE)
    pag <- graph@amat
    rules <- rep(TRUE,10)
    rules[5:7] <- FALSE
    if(!native_attribute) for(iteration in seq_len(100)) {
      previous <- pag
      if(tail(labels,1)=='Y') pag <- udag2pag(pag,graph@sepset,rules=rules,jci='1',contextVars=seq_len(p-1),orientCollider=FALSE)
      pag <- udag2pag(pag,graph@sepset,rules=rules,jci='12',contextVars=roots,orientCollider=FALSE)
      if(identical(previous,pag)) break
      stopifnot(iteration<100)
    }
    list(type='result',status='evaluated',pag=pag,ancestry=pag2anc(pag),
      conservative=FALSE,majority_rule=majority_attribute,maximum_skeleton_conditioning_order=attribute_order,
      maximum_conditioning_order=largest_conditioning,context_variables=as.list(labels[roots]),
      pcalg=as.character(packageVersion('pcalg')))
  } else {
  graph <- fci(list(),checked,alpha=request$alpha,labels=labels,
    fixedGaps=gaps,skel.method='stable',NAdelete=FALSE,
    m.max=Inf,pdsep.max=Inf,conservative=TRUE,maj.rule=FALSE,
    selectionBias=FALSE,jci='12',contextVars=if(directional) roots else 1:2,verbose=FALSE)
  if (directional) {
    skeleton <- new('pcAlgo',graph=as(1L*(graph@amat!=0L),'graphNEL'),
      call=graph@call,n=graph@n,max.ord=graph@max.ord,n.edgetests=graph@n.edgetests,
      sepset=graph@sepset,pMax=graph@pMax,zMin=matrix(NA,1,1))
    triples <- pc.cons.intern(skeleton,list(),checked,request$alpha,
      version.unf=c(1,1),maj.rule=FALSE,verbose=FALSE)
    pag <- graph@amat
    rules <- rep(TRUE,10)
    rules[5:7] <- FALSE
    for (iteration in seq_len(100)) {
      previous <- pag
      pag <- udag2pag(pag,triples$sk@sepset,rules=rules,unfVect=triples$unfTripl,jci='1',
        contextVars=seq_len(p-1),orientCollider=FALSE)
      pag <- udag2pag(pag,triples$sk@sepset,rules=rules,unfVect=triples$unfTripl,jci='12',
        contextVars=roots,orientCollider=FALSE)
      if (identical(previous,pag)) break
      stopifnot(iteration<100)
    }
    list(type='result',status='evaluated',pag=pag,ancestry=pag2anc(pag),
      ambiguous_triples=as.list(triples$unfTripl),
      conservative=TRUE,context_variables=as.list(labels[roots]),pcalg=as.character(packageVersion('pcalg')))
  } else {
  # 两个名称获得相同随机分配知识，算法等价时保留等价结果。
  list(type='result',status='evaluated',pag=graph@amat,
    separating_sets=list(as.list(labels[graph@sepset[[1]][[6]]]),
                         as.list(labels[graph@sepset[[6]][[1]]])),
    conservative=TRUE,context_variables=as.list(labels[1:2]),pcalg=as.character(packageVersion('pcalg')))
  }
  }
  },unsupported_ci=function(condition) {
    unsupported <- list(type='result',status='insufficient_support',pag=NULL,
      separating_sets=list(),conservative=!highdim,context_variables=as.list(labels[if(directional || highdim) roots else 1:2]),pcalg=as.character(packageVersion('pcalg')))
    if(identical(request$method,'attribute_majority_merged')) {
      unsupported$majority_rule <- TRUE
      unsupported$maximum_skeleton_conditioning_order <- attribute_order
      unsupported$maximum_conditioning_order <- largest_conditioning
    }
    unsupported
  })
  emit(result)
}
close(input)
