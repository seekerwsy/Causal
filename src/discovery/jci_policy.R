.libPaths(c('.codex-runtime/r-lib', .libPaths()))
suppressPackageStartupMessages(library(pcalg))
suppressPackageStartupMessages(library(jsonlite))
input <- file('stdin', open='r')
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
  stopifnot(length(context)>=2L,identical(context,seq_along(context)),tail(labels,1)=='Y')
  mode <- switch(request$method,time='1',jci12='12',jci123='123')
  stopifnot(!is.null(mode))
  checked_ci <- function(x,y,S,suffStat) {
    emit(list(type='query',x=labels[x],y=labels[y],conditioned=as.list(labels[S])))
    answer <- fromJSON(readLines(input,n=1L,warn=FALSE))
    stopifnot(is.finite(answer$p),answer$p>=0,answer$p<=1)
    answer$p
  }
  graph <- fci(list(),checked_ci,alpha=request$alpha,labels=labels,
    skel.method='stable',NAdelete=FALSE,m.max=Inf,pdsep.max=Inf,
    rules=rep(TRUE,10),doPdsep=TRUE,selectionBias=FALSE,jci=mode,
    contextVars=context,verbose=FALSE)
  pag <- graph@amat
  rules <- rep(TRUE,10)
  rules[5:7] <- FALSE
  for (iteration in seq_len(100)) {
    previous <- pag
    pag <- udag2pag(pag,graph@sepset,rules=rules,jci='1',
      contextVars=seq_len(p-1),orientCollider=FALSE)
    pag <- udag2pag(pag,graph@sepset,rules=rules,jci=mode,
      contextVars=context,orientCollider=FALSE)
    if (identical(previous,pag)) break
    stopifnot(iteration<100)
  }
  ancestors <- pag2anc(pag)
  emit(list(type='result',status='determined',pag=pag,
    ancestry=ancestors,context_ancestry=as.list(ancestors[context,p]),
    pcalg=as.character(packageVersion('pcalg'))))
}
close(input)
