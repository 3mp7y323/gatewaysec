#!/bin/bash
# ============================================================
# gwsec_dr_test_v7.sh - Do DR/FPR/latency 4 vuln
# MOI: --verbose (in payload bi lot), --full (chay het khong sample),
#      ghi payload lot ra file de phan tich.
# ============================================================
TARGET="http://192.0.2.10:8080"
N_SQLI=150; N_XSS=150; N_TRAV=150; N_CMDI=0
VERBOSE=0
MISS_DIR="./missed_payloads"

# --- Parse tham so ---
for arg in "$@"; do
  case "$arg" in
    --full)    N_SQLI=0; N_XSS=0; N_TRAV=0; N_CMDI=0 ;;
    --target=*) TARGET="${arg#*=}" ;;
  esac
done

find_file() { find . -maxdepth 1 -type f -iname "*$1*.txt" 2>/dev/null | head -n1; }
SQLI_FILE=$(find_file "sqli"); [ -z "$SQLI_FILE" ] && SQLI_FILE=$(find_file "payload" | grep -iv xss | grep -iv trav | grep -iv cmdi | head -n1)
XSS_FILE=$(find_file "xss")
TRAV_FILE=$(find_file "trav")
CMDI_FILE=$(find_file "cmdi"); [ -z "$CMDI_FILE" ] && CMDI_FILE=$(find_file "command")

pct() { awk "BEGIN{ if($2>0) printf \"%.1f\", $1*100/$2; else printf \"N/A\" }"; }
urlenc_raw() { python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$1" 2>/dev/null; }
smart_enc() {
  local pl="$1"
  if echo "$pl" | grep -qE '%[0-9a-fA-F]{2}'; then echo "$pl" | sed 's/ /%20/g'
  else urlenc_raw "$pl"; fi
}

mkdir -p "$MISS_DIR"
echo "============================================================"
echo " GATEWAYSEC - DR / FPR / LATENCY (4 vuln)"
echo " Target: $TARGET | $(date '+%Y-%m-%d %H:%M:%S')"
[ "$N_SQLI" -eq 0 ] && echo " Che do: FULL (chay het payload, khong sample)" || echo " Che do: SAMPLE ($N_SQLI/$N_XSS/$N_TRAV)"
echo "============================================================"
hc=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$TARGET/")
echo " Health check: HTTP $hc"
echo " Files: SQLi=${SQLI_FILE:-X} XSS=${XSS_FILE:-X} Trav=${TRAV_FILE:-X} CMDi=${CMDI_FILE:-X}"
echo ""

test_file() {
  local name="$1" file="$2" limit="$3" tag="$4"
  [ -z "$file" ] || [ ! -f "$file" ] && { echo "$name|0|0"; return; }
  local lines missfile="$MISS_DIR/missed_${tag}.txt"
  : > "$missfile"
  if [ "$limit" -gt 0 ]; then lines=$(grep -v '^\s*$' "$file" | grep -vE '^#|^===' | shuf | head -n "$limit")
  else lines=$(grep -v '^\s*$' "$file" | grep -vE '^#|^==='); fi
  local blocked=0 total=0
  while IFS= read -r pl; do
    [ -z "$pl" ] && continue
    total=$((total+1))
    enc=$(smart_enc "$pl")
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "${TARGET}/?q=${enc}")
    if [ "$code" == "403" ]; then
      blocked=$((blocked+1))
    else
      # payload KHONG bi chan -> ghi lai
      printf '[%s] %s\n' "$code" "$pl" >> "$missfile"
    fi
  done <<< "$lines"
  echo "$name|$blocked|$total"
}

declare -a BENIGN=("hello world" "iphone 15 pro" "laptop gaming" "about us" "john smith" "books" "sort price" "user profile" "search results" "contact" "product 12345" "blue shirt" "cook rice" "weather today" "news" "id 100" "page 2" "electronics" "filter new" "order asc")
test_benign() {
  local blocked=0 total=${#BENIGN[@]}
  for pl in "${BENIGN[@]}"; do
    enc=$(urlenc_raw "$pl")
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "${TARGET}/?q=${enc}")
    [ "$code" == "403" ] && blocked=$((blocked+1))
  done
  echo "$blocked|$total"
}
lat_test() {
  local tmp=$(mktemp)
  for i in $(seq 1 20); do
    curl -s -o /dev/null -w "%{time_total}\n" --max-time 8 "${TARGET}/?id=$i" >> "$tmp"
  done
  sort -n "$tmp" | awk '{a[NR]=$1*1000} END{ m=(NR%2==1)?a[int(NR/2)+1]:(a[NR/2]+a[NR/2+1])/2; printf "%.1f", m }'
  rm -f "$tmp"
}

echo ">>> SQLi..."; r_sqli=$(test_file "SQL Injection" "$SQLI_FILE" "$N_SQLI" "sqli")
echo ">>> XSS..."; r_xss=$(test_file "XSS" "$XSS_FILE" "$N_XSS" "xss")
echo ">>> Path Traversal..."; r_trav=$(test_file "Path Traversal" "$TRAV_FILE" "$N_TRAV" "trav")
echo ">>> Command Injection..."; r_cmdi=$(test_file "Command Injection" "$CMDI_FILE" "$N_CMDI" "cmdi")
echo ">>> Benign (FPR)..."; r_benign=$(test_benign)
echo ">>> Latency..."; med_lat=$(lat_test)
echo ""

echo "============================================================"
echo " DETECTION RATE"
echo "============================================================"
printf "%-20s %-12s %-9s %s\n" "Lop tan cong" "Chan/Tong" "DR" "Pham vi"
printf "%-20s %-12s %-9s %s\n" "--------------------" "----------" "-------" "----------"
tb=0; tt=0; inb=0; intt=0
for r in "$r_sqli" "$r_xss" "$r_trav" "$r_cmdi"; do
  name=$(echo "$r"|cut -d'|' -f1); b=$(echo "$r"|cut -d'|' -f2); t=$(echo "$r"|cut -d'|' -f3)
  dr=$(pct "$b" "$t")
  case "$name" in
    "SQL Injection"|"XSS") scope="trong pham vi"; inb=$((inb+b)); intt=$((intt+t));;
    "Path Traversal") scope="mo rong";;
    "Command Injection") scope="NGOAI pham vi";;
  esac
  printf "%-20s %-12s %-9s %s\n" "$name" "$b/$t" "${dr}%" "$scope"
  tb=$((tb+b)); tt=$((tt+t))
done
printf "%-20s %-12s %-9s %s\n" "-----" "-----" "-----" "-----"
in_dr=$(pct "$inb" "$intt"); total_dr=$(pct "$tb" "$tt")
printf "%-20s %-12s %-9s %s\n" "TRONG PHAM VI" "$inb/$intt" "${in_dr}%" "SQLi+XSS (doi chieu 95%)"
printf "%-20s %-12s %-9s %s\n" "TONG GOP" "$tb/$tt" "${total_dr}%" "gom ca CMDi ngoai scope"

echo ""
echo "============================================================"
echo " FALSE POSITIVE RATE + LATENCY"
echo "============================================================"
bb=$(echo "$r_benign"|cut -d'|' -f1); bt=$(echo "$r_benign"|cut -d'|' -f2)
fpr=$(pct "$bb" "$bt")
echo " Benign chan nham: $bb/$bt  ->  FPR = ${fpr}%"
echo " Latency trung vi: ${med_lat} ms"
echo ""
echo " Tieu chi 1.1.3: DR >= 95% | FPR < 5% | latency < 100ms"
echo " CSRF: bao ve bang ModSecurity CSRF token (khong do bang payload)"
echo "============================================================"
echo ""
echo " >> Payload bi lot da luu tai: $MISS_DIR/"
echo "    Xem SQLi lot: cat $MISS_DIR/missed_sqli.txt"
for tag in sqli xss trav cmdi; do
  mf="$MISS_DIR/missed_${tag}.txt"
  [ -f "$mf" ] && echo "    $tag: $(grep -c . "$mf" 2>/dev/null) payload lot -> $mf"
done
echo "============================================================"
