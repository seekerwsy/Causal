.libPaths(c('.codex-runtime/r-lib', .libPaths()))
suppressPackageStartupMessages(library(pcalg))
suppressPackageStartupMessages(library(jsonlite))
root <- commandArgs(trailingOnly=TRUE)[1]
records <- list()
for (path in list.files(file.path(root,'cells'),pattern='result.json',recursive=TRUE,full.names=TRUE)) {
  cell <- fromJSON(path,simplifyVector=FALSE)
  for (view_name in names(cell$views)) {
    view <- cell$views[[view_name]]
    labels <- unlist(view$structure$labels)
    for (method in c('time','jci')) {
      result <- view$structure$results[[method]]
      if (result$status!='determined') next
      pag <- do.call(rbind,lapply(result$pag,unlist))
      for (variable in intersect(c('A','X'),labels)) {
        adjustment <- backdoor(pag,match(variable,labels),match('Y',labels),type='pag',max.chordal=length(labels))
        identified <- !anyNA(adjustment)
        records[[length(records)+1L]] <- list(mechanism=cell$mechanism,n=cell$n,repetition=cell$repetition,
          view=view_name,method=method,variable=variable,identified_by_gbc=identified,
          adjustment=if (identified) as.list(labels[adjustment]) else NULL)
      }
    }
  }
}
cat(toJSON(records,auto_unbox=TRUE,null='null',digits=16))
