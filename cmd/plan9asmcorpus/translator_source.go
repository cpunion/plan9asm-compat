package main

// Direct unit fixtures may use one synthetic tree. The real corpus entrypoint
// requires a separately pinned translator checkout during provenance capture.
func (cfg discoveryCorpusConfig) translatorSourceRoot() string {
	if cfg.TranslatorRoot != "" {
		return cfg.TranslatorRoot
	}
	return cfg.RepoRoot
}
