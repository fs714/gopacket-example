package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime/pprof"

	"github.com/fs714/gopacket-example/gopacket_perf/engine"
	"github.com/fs714/gopacket-example/utils/log"
)

var ifaceName string
var filter string
var engineName string
var cpuProfile string
var isShowVersion bool

func init() {
	flag.StringVar(&ifaceName, "i", "", "Interface name")
	flag.StringVar(&filter, "bpf", "", "BPF filter")
	flag.StringVar(&engineName, "e", "v1", "Select engine")
	flag.StringVar(&cpuProfile, "cpu", "", "CPU profile path")
	flag.BoolVar(&isShowVersion, "v", false, "Version")
	flag.Parse()

	if isShowVersion {
		fmt.Println("0.0.1")
		os.Exit(0)
	}
}

func main() {
	if os.Geteuid() != 0 {
		log.Errorln("must run as root")
		os.Exit(0)
	}

	if cpuProfile != "" {
		f, err := os.Create(cpuProfile)
		if err != nil {
			log.Errorln(err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Errorln(err)
		}
		defer pprof.StopCPUProfile()
	}

	ctx, cancel := context.WithCancel(context.Background())
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt)
	go func() {
		select {
		case <-signalCh:
			cancel()
			return
		}
	}()

	if engineName == "v1" {
		go engine.DefaultEagerEngine(ifaceName, filter, ctx)
	} else if engineName == "v2" {
		go engine.ZeroCopyEagerEngine(ifaceName, filter, ctx)
	} else if engineName == "v3" {
		go engine.ZeroCopyEagerWithChannelEngine(ifaceName, filter, ctx)
	} else if engineName == "v4" {
		go engine.ZeroCopyPacketBuilderEngine(ifaceName, filter, ctx)
	} else if engineName == "v5" {
		go engine.ZeroCopyParserEngine(ifaceName, filter, ctx)
	} else if engineName == "v6" {
		go engine.ZeroCopyDecoderEngine(ifaceName, filter, ctx)
	} else if engineName == "v7" {
		go engine.AfpacketDecoderEngine(ifaceName, filter, ctx)
	} else {
		log.Errorf("invalid engine: %s", engineName)
		os.Exit(0)
	}

	<-ctx.Done()
}
