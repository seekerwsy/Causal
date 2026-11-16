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
  p <- length(labels)
  assigned <- grep('^C[0-9]+$', labels)
  environment <- which(labels == 'E')
  source <- grep('^W[0-9]+$', labels)
  stopifnot(length(environment)==1L, length(assigned)==4L, length(source)==3L, tail(labels,1)=='Y')
  stopifnot(request$method %in% c('time','jci'))
  checked <- function(x,y,S,suffStat) {
    emit(list(type='query', x=labels[x], y=labels[y], conditioned=as.list(labels[S])))
    answer <- fromJSON(readLines(input,n=1L,warn=FALSE))
    stopifnot(is.finite(answer$p), answer$p>=0, answer$p<=1)
    answer$p
  }
  gaps <- matrix(FALSE,p,p)
  gaps[assigned,c(environment,source)] <- TRUE
  gaps[c(environment,source),assigned] <- TRUE
  graph <- fci(list(), checked, alpha=request$alpha, labels=labels,
    fixedGaps=gaps, skel.method='stable', NAdelete=FALSE, m.max=Inf,
    pdsep.max=Inf, conservative=TRUE, maj.rule=FALSE, selectionBias=FALSE,
    jci='1', contextVars=seq_len(p-1), verbose=FALSE)
  skeleton <- new('pcAlgo',graph=as(1L*(graph@amat!=0L),'graphNEL'),call=graph@call,n=graph@n,
    max.ord=graph@max.ord,n.edgetests=graph@n.edgetests,sepset=graph@sepset,pMax=graph@pMax,
    zMin=matrix(NA,1,1))
  triples <- pc.cons.intern(skeleton,list(),checked,request$alpha,version.unf=c(1,1),maj.rule=FALSE,verbose=FALSE)
  pag <- graph@amat
  rules <- rep(TRUE,10)
  rules[5:7] <- FALSE
  for (iteration in seq_len(100)) {
    previous <- pag
    pag <- udag2pag(pag,triples$sk@sepset,rules=rules,unfVect=triples$unfTripl,
      jci='1',contextVars=seq_len(p-1),orientCollider=FALSE)
    if (request$method=='jci') {
      pag <- udag2pag(pag,triples$sk@sepset,rules=rules,unfVect=triples$unfTripl,
        jci='1',contextVars=c(environment,assigned),orientCollider=FALSE)
      pag <- udag2pag(pag,triples$sk@sepset,rules=rules,unfVect=triples$unfTripl,
        jci='123',contextVars=assigned,orientCollider=FALSE)
    }
    if (identical(previous,pag)) break
    stopifnot(iteration<100)
  }
  emit(list(type='result',pag=pag,ancestry=pag2anc(pag),ambiguous_triples=as.list(triples$unfTripl),
    conservative=TRUE,pcalg=as.character(packageVersion('pcalg'))))
}
close(input)
