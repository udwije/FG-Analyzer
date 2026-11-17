//go:build windows

package main

import (
	"context"

	"golang.org/x/sys/windows/svc"
)

type serviceHandler struct{ app *App }

func (h *serviceHandler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.app.Run(ctx) }()
	const accepts = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.Running, Accepts: accepts}
	for {
		select {
		case q := <-req:
			switch q.Cmd {
			case svc.Interrogate:
				status <- q.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		case e := <-done:
			if e != nil {
				return true, 1
			}
			return false, 0
		}
	}
}

func runService(app *App) error { return svc.Run(windowsServiceName, &serviceHandler{app}) }
func isService() (bool, error)  { return svc.IsWindowsService() }

// v6.0: the Windows service is installed as "LogSikka" (scripts/install-service.ps1).
const windowsServiceName = "LogSikka"
