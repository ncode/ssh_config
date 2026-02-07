# ssh_config

This is a Go parser for `ssh_config` files. Importantly, this parser attempts
to preserve comments in a given file, so you can manipulate a `ssh_config` file
from a program, if your heart desires.

## Fork Notice

This repository is a personal long-term public fork of the original `ssh_config`
project, maintained under its own roadmap.

It's designed to be used with the excellent
[x/crypto/ssh](https://golang.org/x/crypto/ssh) package, which handles SSH
negotiation but isn't very easy to configure.

Use the Resolve API for OpenSSH-accurate evaluation, including `Match` blocks
and spec defaults.

## Resolver API (OpenSSH-accurate)

```go
ctx := ssh_config.Context{HostArg: "myhost"}
res, err := ssh_config.DefaultUserSettings.Resolve(ctx, ssh_config.Strict())
if err != nil {
    log.Fatal(err)
}
port := res.Get("Port")
files := res.GetAll("IdentityFile")
```

You can also load a config file and resolve values from it.

```go
var config = `
Host *.test
  Compression yes
`

cfg, err := ssh_config.Decode(strings.NewReader(config))
if err != nil {
    log.Fatal(err)
}

ctx := ssh_config.Context{HostArg: "example.test"}
res, err := cfg.Resolve(ctx, ssh_config.Strict())
if err != nil {
    log.Fatal(err)
}
port := res.Get("Port")
files := res.GetAll("IdentityFile")
```

Strict mode validates directives and values against the vendored OpenSSH
client spec. Unknown directives are rejected unless `IgnoreUnknown` matches
them; deprecated directives are only accepted when they alias a supported
directive. Defaults from the OpenSSH 10.2 spec are applied in `Resolve`.

`Resolve` also supports multi-pass evaluation via `FinalPass()` and optional
canonicalization via `Canonicalize(...)`. `Match exec` and `Match localnetwork`
require callbacks on `Context` (`Exec` and `LocalNetwork`) when strict.

### Manipulating SSH config files

Here's how you can manipulate an SSH config file, and then write it back to
disk.

```go
f, _ := os.Open(filepath.Join(os.Getenv("HOME"), ".ssh", "config"))
cfg, _ := ssh_config.Decode(f)
for _, host := range cfg.Hosts {
    fmt.Println("patterns:", host.Patterns)
    for _, node := range host.Nodes {
        // Manipulate the nodes as you see fit, or use a type switch to
        // distinguish between Empty, KV, and Include nodes.
        fmt.Println(node.String())
    }
}

// Print the config to stdout:
fmt.Println(cfg.String())
```

For parsed configs (`Decode`/`DecodeBytes`), mutate `cfg.Blocks` if you want
changes reflected by both `Resolve` and `String`. `cfg.Hosts` remains useful for
legacy traversal, but Hosts-only mutations are not authoritative when
`cfg.Blocks` is populated.

## Spec compliance

Wherever possible we try to implement the specification as documented in
the `ssh_config` manpage. Unimplemented features should be present in the
[issues][issues] list.

`Match` is supported in the `Resolve` API.

[issues]: https://github.com/ncode/ssh_config/issues

## OpenSSH client spec

The OpenSSH client option spec is generated from a local OpenSSH source
checkout in `openssh-portable/` and stored in `testdata/openssh_client_spec.json`.
The generator extracts keywords, defaults, aliases, types, and token/env
expansion metadata from `readconf.c`, `myproposal.h`, and `ssh_config.5`.
If `openssh-portable/` is missing, the generator will clone the upstream
OpenSSH portable repository into that git-ignored directory on demand.

To update the spec after bumping OpenSSH:

1. Update the `openssh-portable/` tree.
2. Run `go run ./cmd/openssh-specgen`.
3. Run `go test ./...`.

## Attribution

Huge thanks to Kevin Burke and all prior contributors for the original
`ssh_config` project and the foundation this fork builds on.

Contributor credits are listed in `AUTHORS.txt`.
