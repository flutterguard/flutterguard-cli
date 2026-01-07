package analyzer

// ProgressEvent represents a progress update emitted during analysis.
type ProgressEvent struct {
	Percent int    // coarse percent complete (0-100)
	Stage   string // short stage name, e.g., "decompile"
	Detail  string // optional detail, e.g., "aapt2 metadata"
}

// ProgressReporter receives progress updates.
type ProgressReporter func(ProgressEvent)

func emitProgress(report ProgressReporter, percent int, stage, detail string) {
	if report == nil {
		return
	}
	report(ProgressEvent{Percent: percent, Stage: stage, Detail: detail})
}
