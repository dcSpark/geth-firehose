// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package debug

import (
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"

	"github.com/ethereum/go-ethereum/deepmind"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/metrics/exp"
	"github.com/fjl/memsize/memsizeui"
	colorable "github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"gopkg.in/urfave/cli.v1"
)

var Memsize memsizeui.Handler

var (
	verbosityFlag = cli.IntFlag{
		Name:  "verbosity",
		Usage: "Logging verbosity: 0=silent, 1=error, 2=warn, 3=info, 4=debug, 5=detail",
		Value: 3,
	}
	vmoduleFlag = cli.StringFlag{
		Name:  "vmodule",
		Usage: "Per-module verbosity: comma-separated list of <pattern>=<level> (e.g. eth/*=5,p2p=4)",
		Value: "",
	}
	backtraceAtFlag = cli.StringFlag{
		Name:  "backtrace",
		Usage: "Request a stack trace at a specific logging statement (e.g. \"block.go:271\")",
		Value: "",
	}
	debugFlag = cli.BoolFlag{
		Name:  "debug",
		Usage: "Prepends log messages with call-site location (file and line number)",
	}
	pprofFlag = cli.BoolFlag{
		Name:  "pprof",
		Usage: "Enable the pprof HTTP server",
	}
	pprofPortFlag = cli.IntFlag{
		Name:  "pprofport",
		Usage: "pprof HTTP server listening port",
		Value: 6060,
	}
	pprofAddrFlag = cli.StringFlag{
		Name:  "pprofaddr",
		Usage: "pprof HTTP server listening interface",
		Value: "127.0.0.1",
	}
	memprofilerateFlag = cli.IntFlag{
		Name:  "memprofilerate",
		Usage: "Turn on memory profiling with the given rate",
		Value: runtime.MemProfileRate,
	}
	blockprofilerateFlag = cli.IntFlag{
		Name:  "blockprofilerate",
		Usage: "Turn on block profiling with the given rate",
	}
	cpuprofileFlag = cli.StringFlag{
		Name:  "cpuprofile",
		Usage: "Write CPU profile to the given file",
	}
	traceFlag = cli.StringFlag{
		Name:  "trace",
		Usage: "Write execution trace to the given file",
	}

	// Deep Mind Flags
	deepMindFlag = cli.BoolFlag{
		Name:  "firehose-deep-mind",
		Usage: "Activate/deactivate deep-mind instrumentation, disabled by default",
	}
	deepMindSyncInstrumentationFlag = cli.BoolTFlag{
		Name:  "firehose-deep-mind-sync-instrumentation",
		Usage: "Activate/deactivate deep-mind sync output instrumentation, enabled by default",
	}
	deepMindMiningEnabledFlag = cli.BoolFlag{
		Name:  "firehose-deep-mind-mining-enabled",
		Usage: "Activate/deactivate mining code even if deep-mind is active, required speculative execution on local miner node, disabled by default",
	}
	deepMindBlockProgressFlag = cli.BoolFlag{
		Name:  "firehose-deep-mind-block-progress",
		Usage: "Activate/deactivate deep-mind block progress output instrumentation, disabled by default",
	}
	deepMindCompactionDisabledFlag = cli.BoolFlag{
		Name:  "firehose-deep-mind-compaction-disabled",
		Usage: "Disabled database compaction, enabled by default",
	}
	deepMindArchiveBlocksToKeepFlag = cli.Uint64Flag{
		Name:  "firehose-deep-mind-archive-blocks-to-keep",
		Usage: "Controls how many archive blocks the node should keep, this tweaks the core/blockchain.go constant value TriesInMemory, the default value of 0 can be used to use Geth default value instead which is 128",
		Value: deepmind.ArchiveBlocksToKeep,
	}
	deepMindGenesisFileFlag = cli.StringFlag{
		Name:  "firehose-deep-mind-genesis",
		Usage: "Invalid flag for Firehose 'fh1' versions, if you provided this flag (maybe implicitely through sf-ethereum), you are using the wrong tagged version, uses 'fh2' versions instead",
		Value: "",
	}
)

// Flags holds all command-line flags required for debugging.
var Flags = []cli.Flag{
	verbosityFlag, vmoduleFlag, backtraceAtFlag, debugFlag,
	pprofFlag, pprofAddrFlag, pprofPortFlag,
	memprofilerateFlag, blockprofilerateFlag, cpuprofileFlag, traceFlag,
}

// DeepMindFlags holds all dfuse Deep Mind related command-line flags.
var DeepMindFlags = []cli.Flag{
	deepMindFlag, deepMindSyncInstrumentationFlag, deepMindMiningEnabledFlag, deepMindBlockProgressFlag,
	deepMindCompactionDisabledFlag, deepMindArchiveBlocksToKeepFlag, deepMindGenesisFileFlag,
}

var (
	ostream log.Handler
	glogger *log.GlogHandler
)

func init() {
	usecolor := (isatty.IsTerminal(os.Stderr.Fd()) || isatty.IsCygwinTerminal(os.Stderr.Fd())) && os.Getenv("TERM") != "dumb"
	output := io.Writer(os.Stderr)
	if usecolor {
		output = colorable.NewColorableStderr()
	}
	ostream = log.StreamHandler(output, log.TerminalFormat(usecolor))
	glogger = log.NewGlogHandler(ostream)
}

// Setup initializes profiling and logging based on the CLI flags.
// It should be called as early as possible in the program.
func Setup(ctx *cli.Context, logdir string) error {
	// logging
	log.PrintOrigins(ctx.GlobalBool(debugFlag.Name))
	if logdir != "" {
		rfh, err := log.RotatingFileHandler(
			logdir,
			262144,
			log.JSONFormatOrderedEx(false, true),
		)
		if err != nil {
			return err
		}
		glogger.SetHandler(log.MultiHandler(ostream, rfh))
	}
	glogger.Verbosity(log.Lvl(ctx.GlobalInt(verbosityFlag.Name)))
	glogger.Vmodule(ctx.GlobalString(vmoduleFlag.Name))
	glogger.BacktraceAt(ctx.GlobalString(backtraceAtFlag.Name))
	log.Root().SetHandler(glogger)

	// profiling, tracing
	runtime.MemProfileRate = ctx.GlobalInt(memprofilerateFlag.Name)
	Handler.SetBlockProfileRate(ctx.GlobalInt(blockprofilerateFlag.Name))
	if traceFile := ctx.GlobalString(traceFlag.Name); traceFile != "" {
		if err := Handler.StartGoTrace(traceFile); err != nil {
			return err
		}
	}
	if cpuFile := ctx.GlobalString(cpuprofileFlag.Name); cpuFile != "" {
		if err := Handler.StartCPUProfile(cpuFile); err != nil {
			return err
		}
	}

	// pprof server
	if ctx.GlobalBool(pprofFlag.Name) {
		address := fmt.Sprintf("%s:%d", ctx.GlobalString(pprofAddrFlag.Name), ctx.GlobalInt(pprofPortFlag.Name))
		StartPProf(address)
	}

	// Deep mind
	log.Info("Initializing deep mind")
	deepmind.Enabled = ctx.GlobalBool(deepMindFlag.Name)
	deepmind.SyncInstrumentationEnabled = ctx.GlobalBoolT(deepMindSyncInstrumentationFlag.Name)
	deepmind.MiningEnabled = ctx.GlobalBool(deepMindMiningEnabledFlag.Name)
	deepmind.BlockProgressEnabled = ctx.GlobalBool(deepMindBlockProgressFlag.Name)
	deepmind.CompactionDisabled = ctx.GlobalBool(deepMindCompactionDisabledFlag.Name)
	deepmind.ArchiveBlocksToKeep = ctx.GlobalUint64(deepMindArchiveBlocksToKeepFlag.Name)

	if ctx.GlobalString(deepMindGenesisFileFlag.Name) != "" {
		log.Error("invalid flag for Firehose 'fh1' versions, if you provided this flag (maybe implicitely through sf-ethereum), you are using the wrong tagged version, uses 'fh2' versions instead")
		os.Exit(1)
	}

	log.Info("Deep mind initialized",
		"enabled", deepmind.Enabled,
		"sync_instrumentation_enabled", deepmind.SyncInstrumentationEnabled,
		"mining_enabled", deepmind.MiningEnabled,
		"block_progress_enabled", deepmind.BlockProgressEnabled,
		"compaction_disabled", deepmind.CompactionDisabled,
		"archive_blocks_to_keep", deepmind.ArchiveBlocksToKeep,
	)

	return nil
}

func StartPProf(address string) {
	// Hook go-metrics into expvar on any /debug/metrics request, load all vars
	// from the registry into expvar, and execute regular expvar handler.
	exp.Exp(metrics.DefaultRegistry)
	http.Handle("/memsize/", http.StripPrefix("/memsize", &Memsize))
	log.Info("Starting pprof server", "addr", fmt.Sprintf("http://%s/debug/pprof", address))
	go func() {
		if err := http.ListenAndServe(address, nil); err != nil {
			log.Error("Failure in running pprof server", "err", err)
		}
	}()
}

// Exit stops all running profiles, flushing their output to the
// respective file.
func Exit() {
	Handler.StopCPUProfile()
	Handler.StopGoTrace()
}
