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
  stopifnot(identical(labels[1:5], c('E','A','W1','W2','W3')), tail(labels,1)=='Y')
  checked_ci <- function(x,y,S,suffStat) {
    emit(list(type='query',x=labels[x],y=labels[y],conditioned=as.list(labels[S])))
    answer <- fromJSON(readLines(input,n=1L,warn=FALSE))
    stopifnot(is.finite(answer$p),answer$p>=0,answer$p<=1)
    answer$p
  }
  gaps <- matrix(FALSE,p,p)
  gaps[2,c(1,3:5)] <- gaps[c(1,3:5),2] <- TRUE
  graph <- fci(list(),checked_ci,alpha=request$alpha,labels=labels,
               skel.method='stable',fixedGaps=gaps,NAdelete=FALSE,
               m.max=Inf,pdsep.max=Inf,rules=rep(TRUE,10),doPdsep=TRUE,
               selectionBias=FALSE,jci='1',contextVars=1:5,verbose=FALSE)
  pag <- graph@amat
  rules <- rep(TRUE,10)
  rules[5:7] <- FALSE
  for (iteration in seq_len(100)) {
    previous <- pag
    pag <- udag2pag(pag,graph@sepset,rules=rules,jci='1',contextVars=1:5,orientCollider=FALSE)
    pag <- udag2pag(pag,graph@sepset,rules=rules,jci='1',contextVars=seq_len(p-1),orientCollider=FALSE)
    if (request$method=='jci')
      pag <- udag2pag(pag,graph@sepset,rules=rules,jci='12',contextVars=2L,orientCollider=FALSE)
    if (identical(previous,pag)) break
    stopifnot(iteration<100)
  }
  mag <- pag2magAM(pag,x=2L,max.chordal=p)
  if (is.null(mag)) {
    emit(list(type='result',status='non_evaluable_pag',pag=pag,mag=NULL,
              sufficient=as.list(integer()),minimal=as.list(integer()),proposals=as.list(7L)))
    next
  }
  stopifnot(identical(pag!=0L,mag!=0L),all(mag[pag %in% c(2L,3L)]==pag[pag %in% c(2L,3L)]))
  sufficient <- integer()
  for (mask in 0:7) {
    retained <- which(as.logical(intToBits(mask)[1:3]))
    omitted <- setdiff(1:3,retained)
    if (!length(omitted) || dsepAM(p,omitted+2L,S=c(1L,2L,retained+2L),amat=mag))
      sufficient <- c(sufficient,mask)
  }
  minimal <- sufficient[vapply(sufficient,function(mask)
    !any(sufficient!=mask & bitwAnd(sufficient,mask)==sufficient),logical(1))]
  proposals <- sort(unique(c(7L,unlist(lapply(minimal,function(mask)
    (0:7)[bitwAnd(0:7,mask)==0:7])))))
  emit(list(type='result',status='determined',pag=pag,mag=mag,
            sufficient=as.list(sufficient),minimal=as.list(minimal),proposals=as.list(proposals),
            pcalg=as.character(packageVersion('pcalg'))))
}
close(input)
