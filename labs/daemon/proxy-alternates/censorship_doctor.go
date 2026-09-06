package proxy

import "github.com/maybeknott/luminet/internal/censorshipdoctor"

type CensorshipDiagnosis = censorshipdoctor.CensorshipDiagnosis
type CensorshipDoctor = censorshipdoctor.CensorshipDoctor

func NewCensorshipDoctor(target string) *CensorshipDoctor {
	return censorshipdoctor.NewCensorshipDoctor(target)
}
