package detector

import (
	sig "github.com/mihanistudio/mihanisecurity/pkg/signatures"
)

type SignatureDBAdapter struct {
	*sig.DB
}

func (a *SignatureDBAdapter) MatchFile(path string) ([]SigMatch, error) {
	hits, err := a.DB.MatchFile(path)
	if err != nil {
		return nil, err
	}
	out := make([]SigMatch, 0, len(hits))
	for _, h := range hits {
		out = append(out, SigMatch{
			Name:     h.Sig.Name,
			Severity: h.Sig.Severity,
			Family:   h.Sig.Family,
			Evidence: h.Evidence,
		})
	}
	return out, nil
}
