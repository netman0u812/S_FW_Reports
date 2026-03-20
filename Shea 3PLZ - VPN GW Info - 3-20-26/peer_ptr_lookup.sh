#!/usr/bin/env bash
# shellcheck disable=SC2002
set -euo pipefail

# peer_ptr_tool.sh (macOS Bash 3.2 compatible)
#
# Flags:
#   -h                Help
#   -c [input]        Clean/dedupe: read text IPs (or stdin), strip comments/blanks,
#                     sort unique, write to clean_lookup_list.txt, and exit
#   -l <input>        Lookup: read text IP list from file, do PTR + forward A verification
#   -o <output>       (Lookup) CSV output file (default: peers_lookup_res.txt)
#   -d                Debug: verbose logs to stderr (timing, dig exit codes, counts)
#
# Env (optional):
#   TIMEOUT_SEC       dig timeout seconds (default: 2)
#   TRIES             dig tries per query   (default: 1)
#   SLEEP_MS          pause between IPs in lookup mode, milliseconds (default: 0)

TIMEOUT_SEC="${TIMEOUT_SEC:-2}"
TRIES="${TRIES:-1}"
DEFAULT_LOOKUP_OUT="peers_lookup_res.txt"
DEBUG=0
SLEEP_MS="${SLEEP_MS:-0}"

ts() { date +"%Y-%m-%d %H:%M:%S"; }
dbg() { if [[ $DEBUG -eq 1 ]]; then printf "[%s] %s\n" "$(ts)" "$*" >&2; fi; }

print_help() {
  cat <<'EOF'
Usage:
  peer_ptr_tool.sh -h
  peer_ptr_tool.sh -c [input_file]
  peer_ptr_tool.sh -l <input_file> [-o <output_file>] [-d]

Flags:
  -h                  Show this help.
  -c [input_file]     Clean/dedupe mode. Reads IPs from input_file (or stdin if omitted),
                      removes duplicates/comments/blanks, sorts, writes to:
                        clean_lookup_list.txt
                      then exits (no DNS lookups).
  -l <input_file>     Lookup mode. Reads IPs from input_file, performs reverse DNS (PTR) and
                      forward A-record verification, writing CSV to a file.
  -o <output_file>    (Lookup mode) CSV output file. If omitted, defaults to:
                        peers_lookup_res.txt
  -d                  Debug logs to stderr (progress, dig exit codes, counts, timing).

Input format:
  Plain text, one IPv4 per line. Lines beginning with '#' and blank lines are ignored.

Environment (optional):
  TIMEOUT_SEC   dig timeout seconds (default: 2)
  TRIES         dig tries per query   (default: 1)
  SLEEP_MS      pause between IPs (milliseconds; default: 0)

Examples:
  ./peer_ptr_tool.sh -c peers.txt
  cat peers.txt | ./peer_ptr_tool.sh -c
  ./peer_ptr_tool.sh -l clean_lookup_list.txt
  ./peer_ptr_tool.sh -l clean_lookup_list.txt -o peers_ptr.csv -d
  TIMEOUT_SEC=3 TRIES=2 SLEEP_MS=100 ./peer_ptr_tool.sh -l clean_lookup_list.txt -o peers_ptr.csv -d
EOF
}

# --- Helpers ---

# Read IPs -> tmp file: strip comments/blanks, validate IPv4, sort unique
read_ips_to_tmp() {
  # $1: optional file path; writes cleaned IP list to $2 (tmp file)
  local src="${1-}"
  local out_tmp="$2"

  if [[ -n "$src" ]]; then
    [[ -f "$src" ]] || { echo "ERROR: file not found: $src" >&2; exit 2; }
    cat "$src"
  else
    cat -
  fi \
  | awk 'BEGIN { FS="[[:space:]]+" } /^[[:space:]]*#/ { next } /^[[:space:]]*$/ { next } { print $1 }' \
  | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' \
  | sort -u > "$out_tmp"

  local n; n=$(wc -l < "$out_tmp" | tr -d '[:space:]')
  dbg "read_ips_to_tmp: wrote $n unique IP(s) to $out_tmp"
}

dig_ptr() {
  local ip="$1"
  local out; local rc=0
  out=$(dig +timeout="$TIMEOUT_SEC" +tries="$TRIES" -x "$ip" +short 2>/dev/null) || rc=$?
  dbg "dig PTR for $ip -> rc=$rc"
  printf "%s" "$out" | tr -d '\r'
}

dig_a_records() {
  local name="$1"
  local out; local rc=0
  out=$(dig +timeout="$TIMEOUT_SEC" +tries="$TRIES" "$name" A +short 2>/dev/null) || rc=$?
  dbg "dig A for $name -> rc=$rc"
  printf "%s" "$out" | tr -d '\r'
}

join_semicolon() {
  # reads lines on stdin, joins into single line separated by ';'
  awk 'BEGIN{first=1} { if(NF){ if(!first){printf(";")} printf("%s",$0); first=0 } }'
}

dedupe_lines() {
  awk '!seen[$0]++' | sort
}

sleep_ms() {
  # sleep in milliseconds if SLEEP_MS > 0
  if [[ "$SLEEP_MS" -gt 0 ]]; then
    # macOS sleep supports fractional seconds
    awk -v ms="$SLEEP_MS" 'BEGIN { printf("%.3f\n", ms/1000) }' | {
      read secs || true
      dbg "sleep ${secs}s"
      sleep "$secs"
    }
  fi
}

# --- Parse flags ---

if [[ $# -eq 0 ]]; then
  print_help
  exit 0
fi

MODE=""
INPUT_FILE=""
LOOKUP_OUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h)
      print_help; exit 0 ;;
    -c)
      MODE="clean"
      shift
      if [[ $# -gt 0 && ! "$1" =~ ^- ]]; then
        INPUT_FILE="$1"; shift
      fi
      ;;
    -l)
      MODE="lookup"
      shift
      if [[ $# -eq 0 || "$1" =~ ^- ]]; then
        echo "ERROR: -l requires an input filename" >&2; exit 2
      fi
      INPUT_FILE="$1"; shift
      ;;
    -o)
      shift
      if [[ $# -eq 0 || "$1" =~ ^- ]]; then
        echo "ERROR: -o requires an output filename" >&2; exit 2
      fi
      LOOKUP_OUT="$1"; shift
      ;;
    -d)
      DEBUG=1; shift ;;
    *)
      echo "ERROR: unknown arg: $1" >&2
      print_help
      exit 2
      ;;
  esac
done

# --- Execute modes ---

if [[ "$MODE" == "clean" ]]; then
  tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
  read_ips_to_tmp "$INPUT_FILE" "$tmp"
  mv "$tmp" clean_lookup_list.txt
  echo "Wrote clean, deduplicated list to: clean_lookup_list.txt" >&2
  exit 0
fi

if [[ "$MODE" == "lookup" ]]; then
  [[ -n "$INPUT_FILE" ]] || { echo "ERROR: -l requires an input filename" >&2; exit 2; }
  : "${LOOKUP_OUT:=$DEFAULT_LOOKUP_OUT}"

  dbg "Lookup start. Input=$INPUT_FILE, Output=$LOOKUP_OUT, TIMEOUT_SEC=$TIMEOUT_SEC, TRIES=$TRIES, SLEEP_MS=$SLEEP_MS"
  dbg "Bash version: $BASH_VERSION"
  dbg "ulimit -n (open files): $(ulimit -n || true)"

  tmp_in="$(mktemp)"; trap 'rm -f "$tmp_in"' EXIT
  read_ips_to_tmp "$INPUT_FILE" "$tmp_in"

  # Open output for writing
  exec 3>"$LOOKUP_OUT"
  printf "Peer IP,Peer PTR (rDNS),Verified A Records,Match\n" >&3

  # Iterate IPs
  while IFS= read -r ip; do
    [[ -z "$ip" ]] && continue
    dbg "=== IP: $ip ==="

    # Reverse DNS
    ptrs_tmp="$(mktemp)"
    dig_ptr "$ip" | sed '/^[[:space:]]*$/d' > "$ptrs_tmp" || true

    if [[ ! -s "$ptrs_tmp" ]]; then
      printf '%s,,,\n' "$ip" >&3
      rm -f "$ptrs_tmp"
      sleep_ms
      continue
    fi

    a_tmp="$(mktemp)"
    match="false"

    # Forward A for each PTR
    while IFS= read -r ptr; do
      [[ -z "$ptr" ]] && continue
      dbg "PTR: $ptr"
      dig_a_records "$ptr" | sed '/^[[:space:]]*$/d' >> "$a_tmp" || true
    done < "$ptrs_tmp"

    # Join/dedupe
    if [[ -s "$a_tmp" ]]; then
      if grep -Fxq "$ip" "$a_tmp"; then
        match="true"
      fi
      a_joined="$(cat "$a_tmp" | dedupe_lines | join_semicolon)"
      a_count=$(wc -l < "$a_tmp" | tr -d '[:space:]')
    else
      a_joined=""
      a_count=0
    fi
    ptr_joined="$(cat "$ptrs_tmp" | dedupe_lines | join_semicolon)"
    ptr_count=$(wc -l < "$ptrs_tmp" | tr -d '[:space:]')

    dbg "Counts: PTRs=$ptr_count, A-records=$a_count, Match=$match"
    printf '%s,%s,%s,%s\n' "$ip" "$ptr_joined" "$a_joined" "$match" >&3

    # cleanup per-iteration
    rm -f "$ptrs_tmp" "$a_tmp"
    sleep_ms
  done < "$tmp_in"

  exec 3>&-
  echo "Lookup results written to: $LOOKUP_OUT" >&2
  exit 0
fi

print_help
exit 2