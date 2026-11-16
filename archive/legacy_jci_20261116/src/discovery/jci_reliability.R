.libPaths(c('.codex-runtime/r-lib',.libPaths()))
suppressPackageStartupMessages(library(pcalg))
suppressPackageStartupMessages(library(jsonlite))
input <- file('stdin',open='r')
emit <- function(value) {
  cat(toJSON(value,auto_unbox=TRUE,null='null',digits=16),'\n',sep='')
  flush(stdout())
}
repeat {
  line <- readLines(input,n=1L,warn=FALSE)
  if (!length(line)) break
  request <- fromJSON(line)
  labels <- request$labels
  context <- grep('^C[0-9]+$',labels)
  p <- length(labels)
  stopifnot(length(context)==4L,identical(context,1:4),tail(labels,1)=='Y')
  mode <- switch(request$method,time='1',jci12='12',jci123='123',
    standard_time='1',standard_jci12='12',standard_jci123='123')
  conservative <- request$method %in% c('time','jci12','jci123')
  stopifnot(!is.null(mode))
  checked <- function(x,y,S,suffStat) {
    emit(list(type='query',x=labels[x],y=labels[y],conditioned=as.list(labels[S])))
    answer <- fromJSON(readLines(input,n=1L,warn=FALSE))
    stopifnot(is.finite(answer$p),answer$p>=0,answer$p<=1)
    answer$p
  }
  graph <- fci(list(),checked,alpha=request$alpha,labels=labels,skel.method='stable',NAdelete=FALSE,
    m.max=Inf,pdsep.max=Inf,rules=rep(TRUE,10),doPdsep=TRUE,selectionBias=FALSE,
    conservative=conservative,maj.rule=FALSE,jci=mode,contextVars=context,verbose=FALSE)
  ambiguous <- integer()
  sepset <- graph@sepset
  if (conservative) {
    skeleton <- new('pcAlgo',graph=as(1L*(graph@amat!=0L),'graphNEL'),call=graph@call,n=graph@n,
      max.ord=graph@max.ord,n.edgetests=graph@n.edgetests,sepset=graph@sepset,pMax=graph@pMax,
      zMin=matrix(NA,1,1))
    checked_triples <- pc.cons.intern(skeleton,list(),checked,request$alpha,
      version.unf=c(1,1),maj.rule=FALSE,verbose=FALSE)
    ambiguous <- checked_triples$unfTripl
    sepset <- checked_triples$sk@sepset
  }
  pag <- graph@amat
  rules <- rep(TRUE,10)
  rules[5:7] <- FALSE
  for (iteration in seq_len(100)) {
    previous <- pag
    pag <- udag2pag(pag,sepset,rules=rules,unfVect=ambiguous,jci='1',
      contextVars=seq_len(p-1),orientCollider=FALSE)
    pag <- udag2pag(pag,sepset,rules=rules,unfVect=ambiguous,jci=mode,
      contextVars=context,orientCollider=FALSE)
    if (identical(previous,pag)) break
    stopifnot(iteration<100)
  }
  ancestry <- pag2anc(pag)
  emit(list(type='result',pag=pag,ancestry=ancestry,context_ancestry=as.list(ancestry[context,p]),
    ambiguous_triples=as.list(ambiguous),conservative=conservative,pcalg=as.character(packageVersion('pcalg'))))
}
close(input)
