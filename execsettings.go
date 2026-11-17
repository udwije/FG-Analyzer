package main

import (
	"encoding/json"
	"net/http"
)

// v5.15: /api/exec/settings: the executive report settings (organisation name, status limits, exclusions, report
// layout) from the report's own Customise menu. Everyone who can open the report can read them; admins can change
// them. They are the same values as Settings > Executive summary and apply to everyone.
func (a *App) handleExecSettings(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r.Context())
	admin := roleOf(s.Role) >= RoleAdmin
	switch r.Method {
	case http.MethodGet:
		e := a.store.Get().Exec
		e.defaults()
		jsonOut(w, map[string]any{"exec": e, "can_edit": admin})
	case http.MethodPut:
		if !admin {
			jsonError(w, http.StatusForbidden, "only an admin can change the report settings")
			return
		}
		var in ExecConfig
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<18)).Decode(&in); err != nil {
			jsonError(w, http.StatusBadRequest, "bad request")
			return
		}
		c := a.store.Get()
		c.Exec = in
		if err := a.store.Save(c); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		clearCache()
		a.audit(r, "exec_settings_saved", "")
		e := a.store.Get().Exec
		setRevision(w, a.store) // v6.0.13
		jsonOut(w, map[string]any{"exec": e, "can_edit": true})
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method")
	}
}
