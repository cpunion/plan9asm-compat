#!/usr/bin/env bash
# Sourced by harness entrypoints. Never silently build another translator.

prepare_translator_source() {
  local harness_root=$1
  local repository revision actual state version
  repository=$(jq -er '.repository | select(test("^https://github.com/[A-Za-z0-9_.-]+/plan9asm[.]git$"))' "$harness_root/translator.json") || return
  revision=$(jq -er '.revision | select(test("^[0-9a-f]{40}$"))' "$harness_root/translator.json") || return
  version=$(GOWORK=off go list -C "$harness_root" -m -f '{{with .Replace}}{{.Version}}{{else}}{{.Version}}{{end}}' github.com/xgo-dev/plan9asm) || return
  if [[ "$version" != *"-${revision:0:12}" ]]; then
    echo "translator.json and the go.mod library pin disagree" >&2
    return 1
  fi
  translator_root=${PLAN9ASM_TRANSLATOR_ROOT:-"$harness_root/_out/translator"}
  if [[ ! -e "$translator_root" ]]; then
    mkdir -p "$(dirname "$translator_root")" || return
    git clone --no-checkout "$repository" "$translator_root" >&2 || return
    git -C "$translator_root" checkout --detach "$revision" >&2 || return
  fi
  actual=$(git -C "$translator_root" rev-parse HEAD) || return
  state=$(git -C "$translator_root" status --porcelain) || return
  if [[ "$actual" != "$revision" || -n "$state" ]]; then
    echo "translator checkout is dirty or does not match translator.json; use a fresh checkout" >&2
    return 1
  fi
  if [[ ! -f "$translator_root/cmd/plan9asmll/go.mod" ]]; then
    echo "translator checkout lacks cmd/plan9asmll" >&2
    return 1
  fi
  export PLAN9ASM_TRANSLATOR_ROOT="$translator_root"
}
