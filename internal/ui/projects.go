package ui

import (
	"errors"
	"net/http"
	"strings"

	"tokenzy/internal/db"
	"tokenzy/internal/model"
)

// ProjectRow is one card on the projects page.
type ProjectRow struct {
	Project model.Project
	Created string
	Envs    []model.Environment
}

// ProjectsView backs projects.html and the "projects_panel" fragment.
type ProjectsView struct {
	Layout
	Rows  []ProjectRow
	Error string
}

// EnvRow is one row in a project's environment table.
type EnvRow struct {
	Project string
	Env     model.Environment
	Created string
	Tokens  int64
}

// ProjectView backs project.html and the "envs_panel" fragment.
type ProjectView struct {
	Layout
	Rows  []EnvRow
	Error string
}

func (s *Server) projectsView(r *http.Request, errMsg string) (ProjectsView, error) {
	projects, err := s.db.ListProjects(r.Context())
	if err != nil {
		return ProjectsView{}, err
	}

	rows := make([]ProjectRow, 0, len(projects))
	for _, p := range projects {
		envs, err := s.db.ListEnvironments(r.Context(), p.ID)
		if err != nil {
			return ProjectsView{}, err
		}
		rows = append(rows, ProjectRow{Project: p, Created: formatTime(p.CreatedAt), Envs: envs})
	}

	return ProjectsView{
		Layout: s.layoutFor(r, "Projects", nil, nil, nil, ""),
		Rows:   rows,
		Error:  errMsg,
	}, nil
}

func (s *Server) projectsPage(w http.ResponseWriter, r *http.Request) {
	view, err := s.projectsView(r, "")
	if err != nil {
		internalError(w, "list projects", err)
		return
	}
	s.renderPage(w, http.StatusOK, "projects.html", view)
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	slug := strings.TrimSpace(r.FormValue("slug"))
	name := strings.TrimSpace(r.FormValue("name"))

	var errMsg string
	switch {
	case !model.ValidSlug(slug):
		errMsg = "Invalid slug: " + model.ErrInvalidSlug.Error()
	case name == "":
		errMsg = "Name cannot be empty."
	default:
		_, err := s.db.CreateProject(r.Context(), slug, name)
		if errors.Is(err, db.ErrDuplicate) {
			errMsg = "This slug is already taken: " + slug
		} else if err != nil {
			internalError(w, "create project", err)
			return
		}
	}

	s.renderProjectsPanel(w, r, errMsg)
}

func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request) {
	project, ok := s.resolveProject(w, r)
	if !ok {
		return
	}

	if err := s.db.DeleteProject(r.Context(), project.ID); err != nil && !errors.Is(err, db.ErrNotFound) {
		internalError(w, "delete project", err)
		return
	}

	s.renderProjectsPanel(w, r, "")
}

func (s *Server) renderProjectsPanel(w http.ResponseWriter, r *http.Request, errMsg string) {
	view, err := s.projectsView(r, errMsg)
	if err != nil {
		internalError(w, "list projects", err)
		return
	}
	s.renderFragment(w, http.StatusOK, "projects_panel", view)
}

func (s *Server) projectView(r *http.Request, project model.Project, errMsg string) (ProjectView, error) {
	envs, err := s.db.ListEnvironments(r.Context(), project.ID)
	if err != nil {
		return ProjectView{}, err
	}

	rows := make([]EnvRow, 0, len(envs))
	for _, e := range envs {
		// The token count is what makes "delete this environment" a decision
		// rather than a click: it says how much is about to go.
		counts, err := s.db.CountTokensByStatus(r.Context(), e.ID)
		if err != nil {
			return ProjectView{}, err
		}
		var total int64
		for _, n := range counts {
			total += n
		}

		rows = append(rows, EnvRow{
			Project: project.Slug,
			Env:     e,
			Created: formatTime(e.CreatedAt),
			Tokens:  total,
		})
	}

	return ProjectView{
		Layout: s.layoutFor(r, project.Name, &project, nil, nil, ""),
		Rows:   rows,
		Error:  errMsg,
	}, nil
}

func (s *Server) projectPage(w http.ResponseWriter, r *http.Request) {
	project, ok := s.resolveProject(w, r)
	if !ok {
		return
	}
	view, err := s.projectView(r, project, "")
	if err != nil {
		internalError(w, "list environments", err)
		return
	}
	s.renderPage(w, http.StatusOK, "project.html", view)
}

func (s *Server) createEnvironment(w http.ResponseWriter, r *http.Request) {
	project, ok := s.resolveProject(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	slug := strings.TrimSpace(r.FormValue("slug"))

	var errMsg string
	if !model.ValidSlug(slug) {
		errMsg = "Invalid slug: " + model.ErrInvalidSlug.Error()
	} else {
		_, err := s.db.CreateEnvironment(r.Context(), project.ID, slug)
		if errors.Is(err, db.ErrDuplicate) {
			errMsg = "This environment already exists: " + slug
		} else if err != nil {
			internalError(w, "create environment", err)
			return
		}
	}

	s.renderEnvsPanel(w, r, project, errMsg)
}

func (s *Server) deleteEnvironment(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.resolveEnv(w, r)
	if !ok {
		return
	}
	if err := s.db.DeleteEnvironment(r.Context(), scope.Env.ID); err != nil && !errors.Is(err, db.ErrNotFound) {
		internalError(w, "delete environment", err)
		return
	}
	s.renderEnvsPanel(w, r, scope.Project, "")
}

func (s *Server) renderEnvsPanel(w http.ResponseWriter, r *http.Request, project model.Project, errMsg string) {
	view, err := s.projectView(r, project, errMsg)
	if err != nil {
		internalError(w, "list environments", err)
		return
	}
	s.renderFragment(w, http.StatusOK, "envs_panel", view)
}
