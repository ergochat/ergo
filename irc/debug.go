package irc

import (
	"os"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"time"
)

func (msg *DebugCommand) HandleServer(server *Server) {
	client := msg.Client()
	if !client.flags[Operator] {
		return
	}

	switch msg.subCommand {
	case "GCSTATS":
		stats := debug.GCStats{
			Pause:          make([]time.Duration, 10),
			PauseQuantiles: make([]time.Duration, 5),
		}
		debug.ReadGCStats(&stats)

		server.Replyf(client, "last GC:     %s", stats.LastGC.Format(time.RFC1123))
		server.Replyf(client, "num GC:      %d", stats.NumGC)
		server.Replyf(client, "pause total: %s", stats.PauseTotal)
		server.Replyf(client, "pause quantiles min%%: %s", stats.PauseQuantiles[0])
		server.Replyf(client, "pause quantiles 25%%:  %s", stats.PauseQuantiles[1])
		server.Replyf(client, "pause quantiles 50%%:  %s", stats.PauseQuantiles[2])
		server.Replyf(client, "pause quantiles 75%%:  %s", stats.PauseQuantiles[3])
		server.Replyf(client, "pause quantiles max%%: %s", stats.PauseQuantiles[4])

	case "NUMGOROUTINE":
		count := runtime.NumGoroutine()
		server.Replyf(client, "num goroutines: %d", count)

	case "PROFILEHEAP":
		profFile := "ergonomadic.mprof"
		file, err := os.Create(profFile)
		if err != nil {
			server.Replyf(client, "error: %s", err)
			break
		}
		defer file.Close()
		pprof.Lookup("heap").WriteTo(file, 0)
		server.Replyf(client, "written to %s", profFile)

	case "STARTCPUPROFILE":
		profFile := "ergonomadic.prof"
		file, err := os.Create(profFile)
		if err != nil {
			server.Replyf(client, "error: %s", err)
			break
		}
		if err := pprof.StartCPUProfile(file); err != nil {
			defer file.Close()
			server.Replyf(client, "error: %s", err)
			break
		}

		server.Replyf(client, "CPU profile writing to %s", profFile)

	case "STOPCPUPROFILE":
		pprof.StopCPUProfile()
		server.Reply(client, "CPU profiling stopped")
	}
}
