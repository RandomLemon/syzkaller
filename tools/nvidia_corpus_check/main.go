// Copyright 2026 TensorFunnel project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
//
// nvidia_corpus_check loads a syzkaller corpus.db with the CURRENT tree's
// descriptions and reports how many programs syz-manager would accept as seeds.
// It mirrors every check pkg/manager/seeds.go parseProg applies, so any
// non-zero `bad` count means syz-manager will treat the program as broken and
// DELETE it from the corpus (pkg/manager/seeds.go LoadSeeds), i.e. the
// converter output never reaches the fuzzer.
//
// The checks are: Deserialize(NonStrict), then call count <= prog.MaxCalls and
// no fail_nth>0 call (pkg/manager/seeds.go:272-291). Deserialization alone is
// NOT sufficient: the converters emit one program per trace, which is far
// longer than prog.MaxCalls and is therefore discarded in full.
//
// Drop this file into a syzkaller checkout and run:
//
//	mkdir -p tools/nvidia_corpus_check
//	cp docs/artifacts/tools/nvidia_corpus_check.go tools/nvidia_corpus_check/main.go
//	go run ./tools/nvidia_corpus_check /path/to/corpus.db
//
// Expected:
//
//	records: 1 prog.MaxCalls: 40
//	FAIL <key>: longer than 40 calls (672)   <- current converters: one program per trace
//	deserialized ok=0 bad=1
//
// Once the converters emit programs of at most prog.MaxCalls calls, a healthy
// NVIDIA corpus must report ok>=1 bad=0.
package main

import (
	"fmt"
	"os"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: nvidia_corpus_check <corpus.db>")
		os.Exit(2)
	}
	target, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load target: %v\n", err)
		os.Exit(1)
	}
	d, err := db.Open(os.Args[1], false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open corpus: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("records:", len(d.Records), "prog.MaxCalls:", prog.MaxCalls)

	ok, bad := 0, 0
	for key, rec := range d.Records {
		// NonStrict is what syz-manager uses for corpus programs (pkg/manager/seeds.go
		// ParseSeed -> parseProg(..., prog.NonStrict, ...)).
		p, err := target.Deserialize(rec.Val, prog.NonStrict)
		if err != nil {
			bad++
			fmt.Printf("FAIL %s: %v\n", key, err)
			continue
		}
		if len(p.Calls) > prog.MaxCalls {
			bad++
			fmt.Printf("FAIL %s: longer than %d calls (%d)\n", key, prog.MaxCalls, len(p.Calls))
			continue
		}
		failNth := false
		for _, call := range p.Calls {
			if call.Props.FailNth > 0 {
				failNth = true
				break
			}
		}
		if failNth {
			bad++
			fmt.Printf("FAIL %s: input has fail_nth > 0\n", key)
			continue
		}
		ok++
	}
	fmt.Printf("deserialized ok=%d bad=%d\n", ok, bad)
	if bad != 0 {
		os.Exit(1)
	}
}
