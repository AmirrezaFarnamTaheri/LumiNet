package api

import "github.com/maybeknott/luminet/internal/workflows/jobs"

func (s *Server) createAndStartJob(intent jobs.JobIntent) (string, error) {
	id, err := s.jobManager.CreateJob(intent)
	if err != nil {
		return "", err
	}
	if err := s.jobManager.StartJob(id); err != nil {
		return "", err
	}
	return id, nil
}
