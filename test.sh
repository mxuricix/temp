#!/usr/bin/env bash
#
# strike_linux_posture_audit.sh
# -------------------------------------------------------------------------
# Audit de POSTURA DE TELEMETRIA de un endpoint Linux frente a la metodologia
# STRIKE (certificacion SOC - iSOC / Devel Group).
#
# Para cada paso (comando) del escenario Linux de STRIKE, determina QUE fuente
# de datos se necesita para detectarlo y verifica si el host esta configurado
# para generarla y enviarla al SIEM:
#
#   * auditd instalado y corriendo (auditctl -s / systemctl).
#   * Reglas de auditoria: execve (ejecucion de procesos) y watches sobre
#     rutas sensibles: /etc/passwd, /etc/shadow, /etc/group, /etc/sudoers,
#     /etc/cron*, /etc/rc.local, /etc/rc.common, ~/.bash_history.
#   * rsyslog / syslog-ng activo y REENVIANDO a un destino remoto (SIEM).
#   * journald con almacenamiento persistente.
#   * Telemetria extra opcional: sysmon-for-linux, auditbeat, osquery, falco.
#
# NO ejecuta ninguno de los comandos ofensivos de STRIKE: solo lee config.
# Genera reporte en consola + HTML de certificacion (con logo) + CSV.
#
# Uso:
#   sudo ./strike_linux_posture_audit.sh              # recomendado (auditctl -l needs root)
#   ./strike_linux_posture_audit.sh --full --output-dir /var/tmp/soc
#
# Autor: Devel Security - Certificacion SOC / STRIKE
# -------------------------------------------------------------------------

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ----------------------------- defaults -----------------------------------
CATALOG=""
OUTPUT_DIR="./strike-linux-audit-out"
LOGO=""
FULL="0"
NO_HTML="0"

usage() {
    cat <<'EOF'
Uso: strike_linux_posture_audit.sh [opciones]
      --catalog PATH     Ruta a strike_catalog.json (autodetecta si se omite)
      --output-dir PATH  Carpeta de reportes (default ./strike-linux-audit-out)
      --logo PATH        Logo para el HTML (autodetecta logo.png si se omite)
      --full             Imprime TODOS los pasos en consola (no solo con brechas)
      --no-html          No generar HTML (solo consola + CSV)
  -h, --help             Esta ayuda

Correr como root (sudo) para que 'auditctl -l/-s' devuelva datos reales.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --catalog)    CATALOG="$2"; shift 2;;
        --output-dir) OUTPUT_DIR="$2"; shift 2;;
        --logo)       LOGO="$2"; shift 2;;
        --full)       FULL="1"; shift;;
        --no-html)    NO_HTML="1"; shift;;
        -h|--help)    usage; exit 0;;
        *) echo "arg desconocido: $1 (usa --help)" >&2; exit 1;;
    esac
done

log() { printf '%s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

IS_ROOT="0"; [ "$(id -u 2>/dev/null)" = "0" ] && IS_ROOT="1"

# ------------------------- localizar catalogo -----------------------------
if [ -z "$CATALOG" ]; then
    for c in "$SCRIPT_DIR/strike_catalog.json" "$SCRIPT_DIR/../catalog/strike_catalog.json" \
             "./strike_catalog.json" "./catalog/strike_catalog.json"; do
        [ -f "$c" ] && { CATALOG="$c"; break; }
    done
fi
[ -n "$CATALOG" ] && [ -f "$CATALOG" ] || die "no encuentro strike_catalog.json (usa --catalog)"

# ----------------------- helpers de deteccion -----------------------------
have() { command -v "$1" >/dev/null 2>&1; }

# auditctl -l cacheado (requiere root)
AUDIT_RULES=""
if have auditctl; then AUDIT_RULES="$(auditctl -l 2>/dev/null)"; fi
# fallback: reglas en disco
AUDIT_RULES_FILES=""
for f in /etc/audit/audit.rules /etc/audit/rules.d/*.rules; do
    [ -f "$f" ] && AUDIT_RULES_FILES="$AUDIT_RULES_FILES"$'\n'"$(cat "$f" 2>/dev/null)"
done
ALL_AUDIT_RULES="$AUDIT_RULES"$'\n'"$AUDIT_RULES_FILES"

rules_match() { printf '%s' "$ALL_AUDIT_RULES" | grep -Eiq "$1"; }

svc_active() {
    # $1 = nombre servicio; intenta systemctl, luego service, luego pgrep
    if have systemctl; then systemctl is-active --quiet "$1" 2>/dev/null && return 0; fi
    if have service; then service "$1" status >/dev/null 2>&1 && return 0; fi
    pgrep -x "$1" >/dev/null 2>&1 && return 0
    return 1
}

# ----------------------- señales (posture) --------------------------------
declare -A SIG_STATE SIG_NAME SIG_DETAIL
set_sig() { SIG_STATE["$1"]="$2"; SIG_NAME["$1"]="$3"; SIG_DETAIL["$1"]="$4"; }

# --- auditd instalado / corriendo ---
if have auditctl || have auditd; then
    if svc_active auditd || { have auditctl && auditctl -s 2>/dev/null | grep -q 'enabled 1'; }; then
        st_detail="$(auditctl -s 2>/dev/null | tr '\n' ' ' | sed 's/  */ /g')"
        [ -z "$st_detail" ] && st_detail="servicio auditd activo"
        set_sig AUDITD OK "auditd (demonio de auditoria)" "$st_detail"
    else
        set_sig AUDITD PARTIAL "auditd (demonio de auditoria)" "instalado pero no se confirma corriendo (correr como root / systemctl start auditd)"
    fi
else
    set_sig AUDITD MISSING "auditd (demonio de auditoria)" "no instalado (apt/yum install auditd)"
fi

# si no somos root, auditctl -l suele venir vacio -> marcar incertidumbre
AUDIT_READABLE="1"
if have auditctl && [ -z "$AUDIT_RULES" ] && [ "$IS_ROOT" = "0" ]; then AUDIT_READABLE="0"; fi

sig_rule() { # key name regex remediation-not-here
    local key="$1" name="$2" rx="$3"
    if rules_match "$rx"; then
        set_sig "$key" OK "$name" "regla presente"
    elif [ "$AUDIT_READABLE" = "0" ]; then
        set_sig "$key" UNKNOWN "$name" "no se pudo leer auditctl -l (correr como root)"
    else
        set_sig "$key" MISSING "$name" "sin regla que la capture"
    fi
}

sig_rule EXECVE      "Auditoria de ejecucion de procesos (execve)"       '(-S[ =]execve|arch=b64.*execve|arch=b32.*execve|always,exit.*execve)'
sig_rule W_IDENTITY  "Watch de identidad (/etc/passwd,/etc/shadow,/etc/group)" '(/etc/passwd|/etc/shadow|/etc/group|identity)'
sig_rule W_SUDOERS   "Watch de /etc/sudoers"                             '(/etc/sudoers)'
sig_rule W_CRON      "Watch de cron (/etc/cron*, crontab)"               '(/etc/cron|/var/spool/cron|crontab)'
sig_rule W_RC        "Watch de RC/init (rc.local, rc.common, init.d)"    '(rc\.local|rc\.common|/etc/init\.d|/etc/rc)'
sig_rule W_HIST      "Watch de historial de shell (.bash_history)"       '(bash_history|\.history)'
sig_rule W_MODULES   "Watch de carga de modulos / firewall (init_module, iptables)" '(init_module|finit_module|iptables|nft|/sbin/xtables)'

# --- reenvio de syslog al SIEM ---
SYSLOG_DAEMON="ninguno"
if svc_active rsyslog; then SYSLOG_DAEMON="rsyslog"; elif svc_active syslog-ng; then SYSLOG_DAEMON="syslog-ng"; elif pgrep -x rsyslogd >/dev/null 2>&1; then SYSLOG_DAEMON="rsyslogd"; fi
if [ "$SYSLOG_DAEMON" != "ninguno" ]; then
    set_sig SYSLOG_RUN OK "Daemon de syslog activo" "$SYSLOG_DAEMON"
else
    set_sig SYSLOG_RUN MISSING "Daemon de syslog activo" "no se detecta rsyslog/syslog-ng"
fi

# destino remoto configurado (@host udp / @@host tcp en rsyslog, o destination{} en syslog-ng)
FWD_HIT=""
for f in /etc/rsyslog.conf /etc/rsyslog.d/*.conf; do
    [ -f "$f" ] || continue
    h="$(grep -EH '^\s*[^#].*(@@?[A-Za-z0-9._-]+:?[0-9]*|action\(.*type="omfwd")' "$f" 2>/dev/null | head -1)"
    [ -n "$h" ] && { FWD_HIT="$h"; break; }
done
if [ -z "$FWD_HIT" ] && [ -f /etc/syslog-ng/syslog-ng.conf ]; then
    grep -Eq 'destination\s+\w+\s*\{\s*(network|tcp|udp|syslog)\(' /etc/syslog-ng/syslog-ng.conf 2>/dev/null && FWD_HIT="syslog-ng destination network()"
fi
if [ -n "$FWD_HIT" ]; then
    set_sig SYSLOG_FWD OK "Reenvio de syslog al SIEM" "$(printf '%s' "$FWD_HIT" | cut -c1-80)"
else
    set_sig SYSLOG_FWD MISSING "Reenvio de syslog al SIEM" "sin destino remoto (@/@@/omfwd) configurado"
fi

# --- journald persistente ---
JPERSIST="volatile"
if [ -d /var/log/journal ]; then JPERSIST="persistent (/var/log/journal)"; fi
if grep -Eqs '^\s*Storage\s*=\s*persistent' /etc/systemd/journald.conf 2>/dev/null; then JPERSIST="persistent (config)"; fi
if printf '%s' "$JPERSIST" | grep -q persistent; then
    set_sig JOURNALD OK "journald persistente" "$JPERSIST"
else
    set_sig JOURNALD PARTIAL "journald persistente" "volatil (se pierde al reiniciar): Storage=persistent"
fi

# --- telemetria extra (informativa) ---
EXTRA=""
for t in sysmon auditbeat osqueryd falco; do have "$t" && EXTRA="$EXTRA $t"; done
if [ -n "$EXTRA" ]; then
    set_sig EXTRA OK "Telemetria extendida (EDR/sensores)" "detectado:$EXTRA"
else
    set_sig EXTRA PARTIAL "Telemetria extendida (EDR/sensores)" "no se detecta sysmon-for-linux/auditbeat/osquery/falco (opcional)"
fi

# ----------------------- remediacion por señal ----------------------------
declare -A REM_WHAT REM_CMD
rem() { REM_WHAT["$1"]="$2"; REM_CMD["$1"]="$3"; }
rem AUDITD     "Instalar y habilitar el demonio de auditoria." "apt-get install -y auditd || yum install -y audit ; systemctl enable --now auditd"
rem EXECVE     "Auditar la ejecucion de todos los procesos (base de deteccion)." "auditctl -a always,exit -F arch=b64 -S execve -k strike_exec ; auditctl -a always,exit -F arch=b32 -S execve -k strike_exec"
rem W_IDENTITY "Vigilar cambios de identidad (altas de cuentas)." "auditctl -w /etc/passwd -p wa -k strike_identity ; auditctl -w /etc/shadow -p wa -k strike_identity ; auditctl -w /etc/group -p wa -k strike_identity"
rem W_SUDOERS  "Vigilar cambios de sudoers (escalamiento)." "auditctl -w /etc/sudoers -p wa -k strike_priv ; auditctl -w /etc/sudoers.d -p wa -k strike_priv"
rem W_CRON     "Vigilar persistencia por cron." "auditctl -w /etc/crontab -p wa -k strike_cron ; for d in cron.d cron.daily cron.hourly cron.weekly cron.monthly; do auditctl -w /etc/\$d -p wa -k strike_cron; done"
rem W_RC       "Vigilar persistencia por RC/init." "auditctl -w /etc/rc.local -p wa -k strike_rc ; auditctl -w /etc/rc.common -p wa -k strike_rc ; auditctl -w /etc/init.d -p wa -k strike_rc"
rem W_HIST     "Vigilar manipulacion del historial de shell." "auditctl -w /root/.bash_history -p wa -k strike_hist   # replicar por cada usuario relevante"
rem W_MODULES  "Vigilar carga de modulos y cambios de firewall." "auditctl -a always,exit -F arch=b64 -S init_module -S finit_module -k strike_modules ; auditctl -w /sbin/iptables -p x -k strike_fw"
rem SYSLOG_RUN "Tener un daemon de syslog activo." "systemctl enable --now rsyslog"
rem SYSLOG_FWD "Reenviar logs (incluido auditd via imfile/omfwd) al SIEM." "echo '*.* @@SIEM_IP:514' >> /etc/rsyslog.d/60-strike-siem.conf ; systemctl restart rsyslog   # usar @ para UDP, @@ para TCP"
rem JOURNALD   "Hacer persistente el journal." "mkdir -p /var/log/journal ; sed -i 's/^#\\?Storage=.*/Storage=persistent/' /etc/systemd/journald.conf ; systemctl restart systemd-journald"
rem EXTRA      "Opcional: desplegar un sensor extendido para mayor contexto." "# p.ej. Microsoft sysmon-for-linux, Elastic auditbeat, osquery o Falco"

# ----------------------- leer pasos linux del catalogo --------------------
read_linux_steps() {
    if have python3; then
        python3 - "$CATALOG" <<'PY'
import json,sys
d=json.load(open(sys.argv[1],encoding="utf-8"))
def c(s): return (s or "").replace("\t"," ").replace("\r"," ").replace("\n"," ")
for s in d["steps"]:
    if s["platform"]!="linux": continue
    cmd=s.get("summary_cmd") or s.get("command") or s["title"]
    print("\t".join(c(x) for x in [s["strike_id"],s["mitre"],s["title"],cmd]))
PY
    elif have jq; then
        jq -r '.steps[]|select(.platform=="linux")|[.strike_id,.mitre,.title,(.summary_cmd//.command//.title)]|map(gsub("[\t\r\n]";" "))|@tsv' "$CATALOG"
    else
        die "necesito python3 o jq para leer el catalogo"
    fi
}

# ----------------------- mapeo paso -> requisitos -------------------------
# Devuelve, por stdout, pares "LABEL|ALT1,ALT2|critical" (uno por linea).
required_for() {
    local cmd="$1" mitre="$2"
    local c; c="$(printf '%s %s' "$cmd" "$mitre" | tr 'A-Z' 'a-z')"
    echo "Ejecucion de proceso (auditd execve)|EXECVE,EXTRA|1"
    echo "Llega al SIEM (reenvio syslog)|SYSLOG_FWD,EXTRA|0"
    case "$c" in
        *useradd*|*/etc/passwd*|*/etc/shadow*|*groupadd*|*usermod*|*adduser*)
            echo "Alta/cambio de cuenta (watch identidad)|W_IDENTITY,EXECVE|0";;
    esac
    case "$c" in
        *cron*) echo "Persistencia cron (watch cron)|W_CRON,EXECVE|0";;
    esac
    case "$c" in
        *rc.local*|*rc.common*|*init.d*|*rc.d*) echo "Persistencia RC/init (watch rc)|W_RC,EXECVE|0";;
    esac
    case "$c" in
        *bash_history*|*logger*|*.history*) echo "Manipulacion de historial (watch hist)|W_HIST,EXECVE|0";;
    esac
    case "$c" in
        *iptables*|*nft*|*ufw*|*firewall*|*init_module*) echo "Firewall/modulos (watch modules)|W_MODULES,EXECVE|0";;
    esac
    case "$c" in
        *sudo*|*sudoers*) echo "Escalamiento (watch sudoers)|W_SUDOERS,EXECVE|0";;
    esac
}

eval_alt() { # $1=csv de alternativas -> OK/PARTIAL/MISSING
    local best="MISSING" k st
    IFS=',' read -ra alts <<< "$1"
    for k in "${alts[@]}"; do
        st="${SIG_STATE[$k]:-NA}"
        [ "$st" = "OK" ] && { echo OK; return; }
        { [ "$st" = "PARTIAL" ] || [ "$st" = "UNKNOWN" ]; } && best="PARTIAL"
    done
    echo "$best"
}

# ----------------------- evaluacion por paso ------------------------------
RESULTS_TSV=""   # strike_id \t mitre \t verdict \t missing \t partial \t title
TOT_COV=0; TOT_PAR=0; TOT_NC=0; TOT=0
while IFS=$'\t' read -r sid mitre title cmd; do
    [ -n "$sid" ] || continue
    missing=""; partial=""; critfail=0
    while IFS='|' read -r label alts crit; do
        [ -n "$label" ] || continue
        st="$(eval_alt "$alts")"
        if [ "$st" = "MISSING" ]; then missing="${missing:+$missing | }$label"; [ "$crit" = "1" ] && critfail=1
        elif [ "$st" = "PARTIAL" ]; then partial="${partial:+$partial | }$label"; [ "$crit" = "1" ] && critfail=1; fi
    done < <(required_for "$cmd" "$mitre")

    if [ "$critfail" = "1" ]; then verdict="NOT_COVERED"; TOT_NC=$((TOT_NC+1))
    elif [ -n "$missing" ] || [ -n "$partial" ]; then verdict="PARTIAL"; TOT_PAR=$((TOT_PAR+1))
    else verdict="COVERED"; TOT_COV=$((TOT_COV+1)); fi
    TOT=$((TOT+1))
    # centinela '-' para campos vacios: el TAB es whitespace para 'read' y
    # colapsa campos vacios consecutivos, desalineando columnas.
    [ -z "$missing" ] && missing="-"
    [ -z "$partial" ] && partial="-"
    RESULTS_TSV="$RESULTS_TSV$sid"$'\t'"$mitre"$'\t'"$verdict"$'\t'"$missing"$'\t'"$partial"$'\t'"$title"$'\n'
done < <(read_linux_steps)

# ------------------------------ consola -----------------------------------
col() { case "$1" in OK|COVERED) printf '\033[32m';; PARTIAL|UNKNOWN) printf '\033[33m';; MISSING|NOT_COVERED) printf '\033[31m';; *) printf '\033[90m';; esac; }
rst() { printf '\033[0m'; }
hr() { printf '=%.0s' $(seq 1 72); echo; }

echo; hr
echo "  STRIKE - Audit de telemetria Linux (iSOC / Devel Group)"
hr
printf '  Host  : %s\n' "$(hostname 2>/dev/null)"
printf '  Fecha : %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
printf '  Root  : %s\n' "$([ "$IS_ROOT" = 1 ] && echo SI || echo 'NO (auditctl -l puede venir vacio; correr con sudo)')"
printf '  Catalogo: %s\n' "$CATALOG"

echo; echo "  == Postura de fuentes de datos =="
for k in AUDITD EXECVE W_IDENTITY W_SUDOERS W_CRON W_RC W_HIST W_MODULES SYSLOG_RUN SYSLOG_FWD JOURNALD EXTRA; do
    [ -n "${SIG_STATE[$k]:-}" ] || continue
    printf '  '; col "${SIG_STATE[$k]}"; printf '[%-8s]' "${SIG_STATE[$k]}"; rst
    printf ' %-48s %s\n' "${SIG_NAME[$k]}" "${SIG_DETAIL[$k]}"
done

echo; echo "  == Resultado por paso STRIKE (Linux) =="
printf '%s' "$RESULTS_TSV" | while IFS=$'\t' read -r sid mitre verdict missing partial title; do
    [ -n "$sid" ] || continue
    if [ "$FULL" = "0" ] && [ "$verdict" = "COVERED" ]; then continue; fi
    printf '  '; col "$verdict"; printf '%-6s %-11s %-12s' "$sid" "$mitre" "$verdict"; rst; printf ' %s\n' "$title"
    [ "$missing" != "-" ] && printf '          falta  : %s\n' "$missing"
    [ "$partial" != "-" ] && printf '          parcial: %s\n' "$partial"
done

echo; echo "  == Resumen =="
printf '  COVERED=%d  PARTIAL=%d  NOT_COVERED=%d  (de %d pasos Linux)\n' "$TOT_COV" "$TOT_PAR" "$TOT_NC" "$TOT"
hr

# ------------------------------ export ------------------------------------
mkdir -p "$OUTPUT_DIR" || die "no pude crear $OUTPUT_DIR"
STAMP="$(date '+%Y%m%d-%H%M%S')"
CSV="$OUTPUT_DIR/strike-linux-audit-$STAMP.csv"
{
    echo "strike_id,mitre,verdict,missing,partial,title"
    printf '%s' "$RESULTS_TSV" | while IFS=$'\t' read -r sid mitre verdict missing partial title; do
        [ -n "$sid" ] || continue
        [ "$missing" = "-" ] && missing=""
        [ "$partial" = "-" ] && partial=""
        printf '%s,%s,%s,"%s","%s","%s"\n' "$sid" "$mitre" "$verdict" "${missing//\"/\"\"}" "${partial//\"/\"\"}" "${title//\"/\"\"}"
    done
} > "$CSV"
log " Reporte CSV : $CSV"

# ------------------------------ HTML --------------------------------------
if [ "$NO_HTML" = "1" ]; then exit 0; fi

# logo -> data URI
if [ -z "$LOGO" ]; then
    for c in "$SCRIPT_DIR/logo.png" "$SCRIPT_DIR/../logo.png" "./logo.png"; do
        [ -f "$c" ] && { LOGO="$c"; break; }
    done
fi
LOGO_TAG="<div class='logo-fallback'>DEVEL<span>/</span>GROUP</div>"
if [ -n "$LOGO" ] && [ -f "$LOGO" ]; then
    b64=""
    if base64 --help 2>&1 | grep -q '\-w'; then b64="$(base64 -w0 "$LOGO" 2>/dev/null)"; else b64="$(base64 "$LOGO" 2>/dev/null | tr -d '\n')"; fi
    ext="${LOGO##*.}"; [ "$ext" = "jpg" ] && ext="jpeg"
    [ -n "$b64" ] && LOGO_TAG="<img class='logo' src='data:image/$ext;base64,$b64' alt='Devel Group'>"
fi

hesc() { sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g'; }
he() { printf '%s' "$1" | hesc; }
badge() { local s="$1" cls; case "$s" in OK|COVERED) cls=ok;; PARTIAL|UNKNOWN) cls=warn;; MISSING|NOT_COVERED) cls=bad;; *) cls=unk;; esac; printf "<span class='badge %s'>%s</span>" "$cls" "$s"; }

HTML="$OUTPUT_DIR/strike-linux-audit-$STAMP.html"

# filas: postura
SIG_ROWS=""
for k in AUDITD EXECVE W_IDENTITY W_SUDOERS W_CRON W_RC W_HIST W_MODULES SYSLOG_RUN SYSLOG_FWD JOURNALD EXTRA; do
    [ -n "${SIG_STATE[$k]:-}" ] || continue
    SIG_ROWS="$SIG_ROWS<tr><td>$(badge "${SIG_STATE[$k]}")</td><td>$(he "${SIG_NAME[$k]}")</td><td class='mono'>$(he "${SIG_DETAIL[$k]}")</td></tr>"
done
# filas: acciones (no-OK con remediacion)
ACT_ROWS=""
for k in AUDITD EXECVE W_IDENTITY W_SUDOERS W_CRON W_RC W_HIST W_MODULES SYSLOG_RUN SYSLOG_FWD JOURNALD EXTRA; do
    st="${SIG_STATE[$k]:-}"; [ -n "$st" ] || continue
    [ "$st" = "OK" ] && continue
    [ -n "${REM_CMD[$k]:-}" ] || continue
    ACT_ROWS="$ACT_ROWS<tr><td>$(badge "$st")</td><td><b>$(he "${SIG_NAME[$k]}")</b><div class='muted'>$(he "${REM_WHAT[$k]}")</div></td><td class='mono small cmd'>$(he "${REM_CMD[$k]}")</td></tr>"
done
[ -n "$ACT_ROWS" ] || ACT_ROWS="<tr><td colspan='3' class='muted'>Sin acciones pendientes.</td></tr>"
# filas: pasos
STEP_ROWS=""
while IFS=$'\t' read -r sid mitre verdict missing partial title; do
    [ -n "$sid" ] || continue
    gaps=""
    [ "$missing" != "-" ] && gaps="<span class='gap bad'>$(he "$missing")</span>"
    [ "$partial" != "-" ] && gaps="$gaps<span class='gap warn'>$(he "$partial")</span>"
    STEP_ROWS="$STEP_ROWS<tr data-verdict='$verdict'><td class='mono'>$(he "$sid")</td><td>$(badge "$verdict")</td><td class='mono'>$(he "$mitre")</td><td>$(he "$title")</td><td class='small'>$gaps</td></tr>"
done <<< "$(printf '%s' "$RESULTS_TSV")"

ROOT_NOTE=""
[ "$IS_ROOT" = "0" ] && ROOT_NOTE="<div class='alert'>Reporte generado SIN privilegios de root: <code>auditctl -l</code> puede venir vacio y las reglas de auditoria quedar en UNKNOWN/MISSING. Reejecutar con <code>sudo</code> para un resultado valido.</div>"

cat > "$HTML" <<HTMLEOF
<!doctype html><html lang='es'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>Certificacion iSOC - Linux - $(he "$(hostname 2>/dev/null)")</title>
<style>
 :root{--bg:#f6f7f9;--card:#fff;--fg:#1a1f29;--muted:#6b7280;--line:#e5e7eb;--ok:#15803d;--okbg:#dcfce7;--warn:#a16207;--warnbg:#fef9c3;--bad:#b91c1c;--badbg:#fee2e2;--unk:#4b5563;--unkbg:#e5e7eb;--accent:#0e7490;}
 @media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a21;--fg:#e5e7eb;--muted:#9ca3af;--line:#2a2f3a;--ok:#4ade80;--okbg:#0c2c1a;--warn:#facc15;--warnbg:#2c2410;--bad:#f87171;--badbg:#2c1416;--unk:#9ca3af;--unkbg:#232732;--accent:#22d3ee;}}
 *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;padding:0 0 24px}
 h2{font-size:16px;margin:28px 0 10px;color:var(--accent)}.wrap{max-width:1200px;margin:0 auto;padding:0 24px}.meta{color:var(--muted);font-size:13px}
 .cert{background:#0d0f13;border-bottom:3px solid #ff3a0e;color:#fff;padding:18px 24px;margin-bottom:8px}
 .cert .in{max-width:1200px;margin:0 auto;display:flex;align-items:center;gap:20px;flex-wrap:wrap}
 .cert .logo{height:52px;width:auto;display:block}.cert .logo-fallback{font-weight:800;font-size:26px;color:#fff}.cert .logo-fallback span{color:#ff3a0e}
 .cert .txt{border-left:1px solid #2a2f3a;padding-left:20px}
 .cert .t1{font-size:12px;letter-spacing:.22em;color:#9aa3b2;text-transform:uppercase;margin:0}
 .cert .t2{font-size:20px;font-weight:700;margin:2px 0 0}.cert .t3{font-size:13px;margin-top:3px;color:#ff6a43;font-weight:600}
 .cert .seal{margin-left:auto;text-align:right;font-size:11px;color:#9aa3b2}.cert .seal b{color:#fff;font-size:13px}
 .cards{display:flex;gap:14px;flex-wrap:wrap;margin:18px 0}
 .kpi{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 20px;min-width:140px;flex:1}
 .kpi .n{font-size:30px;font-weight:700}.kpi .l{color:var(--muted);font-size:12px;text-transform:uppercase}
 .kpi.ok .n{color:var(--ok)}.kpi.warn .n{color:var(--warn)}.kpi.bad .n{color:var(--bad)}
 table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}
 th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}
 th{background:rgba(127,127,127,.08);font-size:12px;text-transform:uppercase;color:var(--muted)}tr:last-child td{border-bottom:0}
 .mono{font-family:ui-monospace,Consolas,monospace;font-size:12px}.small{font-size:12px}.muted{color:var(--muted);font-size:12px;margin-top:3px}
 .cmd{white-space:pre-wrap;word-break:break-all;background:rgba(127,127,127,.07);border-radius:6px;padding:4px 6px}
 .badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700;white-space:nowrap}
 .badge.ok{background:var(--okbg);color:var(--ok)}.badge.warn{background:var(--warnbg);color:var(--warn)}.badge.bad{background:var(--badbg);color:var(--bad)}.badge.unk{background:var(--unkbg);color:var(--unk)}
 .alert{background:var(--warnbg);color:var(--warn);border:1px solid var(--warn);border-radius:10px;padding:10px 14px;margin:14px 0;font-size:13px}
 .gap{display:block}.gap.bad{color:var(--bad)}.gap.warn{color:var(--warn)}code{font-family:ui-monospace,Consolas,monospace;background:rgba(127,127,127,.12);padding:1px 4px;border-radius:4px}
 .filters{margin:10px 0}.filters button{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:999px;padding:5px 12px;cursor:pointer;font-size:12px;margin-right:6px}.filters button.active{background:var(--accent);color:#fff;border-color:var(--accent)}
 footer{color:var(--muted);font-size:12px;margin-top:30px;text-align:center}
</style></head><body>
 <div class='cert'><div class='in'>
   $LOGO_TAG
   <div class='txt'><p class='t1'>Certificacion de Fuentes de Informacion</p><p class='t2'>iSOC &mdash; Devel Group</p><p class='t3'>Metodologia STRIKE &middot; Audit de telemetria de endpoint Linux</p></div>
   <div class='seal'><b>$(he "$(hostname 2>/dev/null)")</b><br>$(date '+%Y-%m-%d %H:%M')<br>Root: $([ "$IS_ROOT" = 1 ] && echo SI || echo NO)</div>
 </div></div>
 <div class='wrap'>
 <div class='meta'>Catalogo: $(he "$(basename "$CATALOG")") &middot; $TOT pasos Linux evaluados</div>
 $ROOT_NOTE
 <div class='cards'>
   <div class='kpi ok'><div class='n'>$TOT_COV</div><div class='l'>Covered</div></div>
   <div class='kpi warn'><div class='n'>$TOT_PAR</div><div class='l'>Partial</div></div>
   <div class='kpi bad'><div class='n'>$TOT_NC</div><div class='l'>Not covered</div></div>
   <div class='kpi'><div class='n'>$TOT</div><div class='l'>Pasos Linux</div></div>
 </div>
 <h2>Acciones recomendadas (que configurar)</h2>
 <table><thead><tr><th>Estado</th><th>Fuente / que hacer</th><th>Comando (root)</th></tr></thead><tbody>$ACT_ROWS</tbody></table>
 <h2>Postura de fuentes de datos</h2>
 <table><thead><tr><th>Estado</th><th>Fuente</th><th>Detalle</th></tr></thead><tbody>$SIG_ROWS</tbody></table>
 <h2>Resultado por paso STRIKE</h2>
 <div class='filters'><button class='active' onclick='flt(this,"all")'>Todos</button><button onclick='flt(this,"NOT_COVERED")'>Not covered</button><button onclick='flt(this,"PARTIAL")'>Partial</button><button onclick='flt(this,"COVERED")'>Covered</button></div>
 <table id='steps'><thead><tr><th>ID</th><th>Veredicto</th><th>MITRE</th><th>Tecnica / paso</th><th>Telemetria faltante</th></tr></thead><tbody>$STEP_ROWS</tbody></table>
 <footer>Generado por strike_linux_posture_audit.sh &middot; Devel Security &mdash; Certificacion SOC / STRIKE</footer>
 </div>
<script>function flt(b,v){document.querySelectorAll('.filters button').forEach(function(x){x.classList.remove('active')});b.classList.add('active');document.querySelectorAll('#steps tbody tr').forEach(function(r){r.style.display=(v==='all'||r.getAttribute('data-verdict')===v)?'':'none';});}</script>
</body></html>
HTMLEOF

log " Reporte HTML: $HTML"
log ""
log " Postura Linux: COVERED=$TOT_COV PARTIAL=$TOT_PAR NOT_COVERED=$TOT_NC (de $TOT pasos)"
