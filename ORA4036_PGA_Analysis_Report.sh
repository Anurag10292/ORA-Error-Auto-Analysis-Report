#!/usr/bin/env bash
# ORA-04036 PGA diagnostic collector and emailer
# Prompts only for incident start/end time. All other values are auto-detected
# or supplied through environment variables.
set -uo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly RUN_TS="$(date '+%Y%m%d_%H%M%S')"
readonly HOST="$(hostname -s 2>/dev/null || hostname)"
readonly WORK_DIR="${WORK_DIR:-/tmp/ora04036_${RUN_TS}_$$}"
readonly RETENTION_DAYS="${RETENTION_DAYS:-7}"
readonly TOP_N="${TOP_N:-20}"
readonly LIVE_ASH_SECONDS="${LIVE_ASH_SECONDS:-3600}"
readonly MAIL_TO="${MAIL_TO:-}"
readonly MAIL_CC="${MAIL_CC:-}"
readonly MAIL_FROM="${MAIL_FROM:-oracle@${HOST}}"

cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT INT TERM
mkdir -p "$WORK_DIR" || exit 1

log() { printf '%s %s\n' "$(date '+%F %T')" "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# Only interactive inputs requested by design.
read -r -p "Enter incident start time [YYYY/MM/DD HH24:MI]: " START_TIME
read -r -p "Enter incident end time   [YYYY/MM/DD HH24:MI]: " END_TIME

[[ "$START_TIME" =~ ^[0-9]{4}/[0-9]{2}/[0-9]{2}[[:space:]][0-9]{2}:[0-9]{2}$ ]] || die "Invalid start-time format."
[[ "$END_TIME" =~ ^[0-9]{4}/[0-9]{2}/[0-9]{2}[[:space:]][0-9]{2}:[0-9]{2}$ ]] || die "Invalid end-time format."
START_EPOCH=$(date -d "${START_TIME//\//-}" +%s 2>/dev/null) || die "Invalid start time."
END_EPOCH=$(date -d "${END_TIME//\//-}" +%s 2>/dev/null) || die "Invalid end time."
(( END_EPOCH >= START_EPOCH )) || die "End time must not be earlier than start time."

# Use the database selected in the invoking Oracle environment.
[[ -n "${ORACLE_SID:-}" ]] || die "ORACLE_SID is not set. Source the target database environment first."
if [[ -z "${ORACLE_HOME:-}" ]] && command -v oraenv >/dev/null 2>&1; then
  ORAENV_ASK=NO
  export ORAENV_ASK ORACLE_SID
  # shellcheck disable=SC1091
  . "$(command -v oraenv)" >/dev/null 2>&1
fi
[[ -x "${ORACLE_HOME:-}/bin/sqlplus" ]] || die "sqlplus not found. Set ORACLE_HOME for ${ORACLE_SID}."
[[ -n "$MAIL_TO" ]] || die "MAIL_TO is not set. Example: export MAIL_TO='dba-team@example.com'"

export PATH="$ORACLE_HOME/bin:$PATH"
REPORT="$WORK_DIR/ORA04036_${ORACLE_SID}_${HOST}_${RUN_TS}.log"
SQLFILE="$WORK_DIR/ora04036_collect.sql"
TRACE_EVIDENCE="$WORK_DIR/ORA04036_trace_evidence_${RUN_TS}.txt"
ARCHIVE="$WORK_DIR/ORA04036_${ORACLE_SID}_${HOST}_${RUN_TS}.tgz"
SUBJECT="ORA-04036 PGA Analysis | DB=${ORACLE_SID} | Host=${HOST} | ${START_TIME} to ${END_TIME}"

cat > "$SQLFILE" <<SQL
whenever sqlerror continue
set echo off verify off feedback on heading on lines 300 pages 1000 trimspool on tab off
set long 1000000 longchunksize 1000000 serveroutput on size unlimited
alter session set nls_date_format='DD-MON-YYYY HH24:MI:SS';
spool ${REPORT}
prompt ================================================================================
prompt ORA-04036 PGA DIAGNOSTIC REPORT
prompt Database environment: ${ORACLE_SID}
prompt Host: ${HOST}
prompt Incident window: ${START_TIME} to ${END_TIME}
prompt Generated: ${RUN_TS}
prompt ================================================================================

prompt [1] DATABASE / INSTANCE / PDB / ROLE / VERSION
select d.name database_name,d.dbid,d.database_role,d.open_mode,d.flashback_on,
       i.instance_number,i.instance_name,i.host_name,i.version,i.startup_time,
       sys_context('USERENV','CON_NAME') current_container
from v\$database d cross join v\$instance i;
select con_id,name,open_mode,restricted from v\$pdbs order by con_id;

prompt [2] MEMORY AND PROCESS CONFIGURATION
column parameter format a35
select con_id,name parameter,
       case when name='processes' then value else to_char(round(to_number(value)/1024/1024,2)) end value_mb_or_count
from v\$system_parameter
where name in ('pga_aggregate_target','pga_aggregate_limit','memory_target','memory_max_target',
               'sga_target','sga_max_size','processes','workarea_size_policy')
order by con_id,name;

prompt [3] CURRENT PGA PRESSURE
column name format a45
select name,value,unit from v\$pgastat
where name in ('aggregate PGA target parameter','aggregate PGA auto target','total PGA inuse',
               'total PGA allocated','maximum PGA allocated','total freeable PGA memory',
               'over allocation count','extra bytes read/written','cache hit percentage')
order by name;
select round(sum(pga_max_mem)/power(1024,3),2) max_pga_gb,
       round(sum(pga_alloc_mem)/power(1024,3),2) allocated_pga_gb,
       round(sum(pga_used_mem)/power(1024,3),2) used_pga_gb,
       round(sum(pga_freeable_mem)/power(1024,3),2) freeable_pga_gb
from v\$process;

prompt [4] DYNAMIC MEMORY COMPONENTS
column component format a40
select inst_id,component,round(current_size/1024/1024) current_mb,
       round(min_size/1024/1024) min_mb,round(max_size/1024/1024) max_mb
from gv\$memory_dynamic_components where current_size<>0 order by inst_id,component;

prompt [5] TOP CURRENT PROCESSES / SESSIONS BY PGA
column username format a25
column module format a35
column program format a45
select * from (
 select p.inst_id,p.spid,s.sid,s.serial#,s.con_id,nvl(s.username,'(oracle)') username,
        s.status,s.sql_id,s.prev_sql_id,s.service_name,s.module,s.machine,s.program,
        round(p.pga_used_mem/1024/1024,2) used_mb,
        round(p.pga_alloc_mem/1024/1024,2) alloc_mb,
        round(p.pga_freeable_mem/1024/1024,2) freeable_mb,
        round(p.pga_max_mem/1024/1024,2) max_mb,s.logon_time,s.last_call_et
 from gv\$process p left join gv\$session s
   on s.inst_id=p.inst_id and s.paddr=p.addr
 order by p.pga_alloc_mem desc
) where rownum<=${TOP_N};

prompt [6] TOP LIVE ASH SQL BY POSITIVE PGA GROWTH
select sql_id,round(pga_mb,1) pga_mb,round(pct,2) percent
from (
 select sql_id,sum(delta_mb) pga_mb,
        ratio_to_report(sum(delta_mb)) over()*100 pct,
        rank() over(order by sum(delta_mb) desc) rnk
 from (
   select sql_id,greatest(pga_allocated-lag(pga_allocated) over
          (partition by session_id,session_serial# order by sample_time),0)/power(1024,2) delta_mb
   from v\$active_session_history
   where is_sqlid_current='Y' and sample_time>sysdate-${LIVE_ASH_SECONDS}/86400
 ) group by sql_id having sum(delta_mb)>0
) where rnk<=${TOP_N} order by pga_mb desc;

prompt [7] HISTORICAL PGA TREND FOR INCIDENT WINDOW - AWR LICENSE REQUIRED
select sn.instance_number,round(p.value/power(1024,3),3) pga_allocated_gb,
       sn.end_interval_time
from dba_hist_snapshot sn join dba_hist_pgastat p
  on p.dbid=sn.dbid and p.instance_number=sn.instance_number and p.snap_id=sn.snap_id
where p.name='total PGA allocated'
  and sn.end_interval_time between to_timestamp('${START_TIME}','YYYY/MM/DD HH24:MI')
                               and to_timestamp('${END_TIME}','YYYY/MM/DD HH24:MI')
order by sn.end_interval_time,sn.instance_number;

prompt [8] TOP HISTORICAL SQL BY PGA - AWR ASH
select * from (
 select h.instance_number,h.con_id,h.sql_id,
        round(max(h.pga_allocated)/power(1024,3),2) max_pga_gb,
        dbms_lob.substr(t.sql_text,1000,1) sql_text
 from dba_hist_active_sess_history h
 left join dba_hist_sqltext t on t.dbid=h.dbid and t.sql_id=h.sql_id and t.con_id=h.con_id
 where h.sample_time between to_timestamp('${START_TIME}','YYYY/MM/DD HH24:MI')
                         and to_timestamp('${END_TIME}','YYYY/MM/DD HH24:MI')
   and h.sql_id is not null
 group by h.instance_number,h.con_id,h.sql_id,dbms_lob.substr(t.sql_text,1000,1)
 order by max_pga_gb desc
) where rownum<=${TOP_N};

prompt [9] WORKAREA EFFICIENCY / TEMP SPILL
select name,value from v\$pgastat
where name like 'workarea executions%' or name in
('over allocation count','extra bytes read/written','cache hit percentage') order by name;
select sum(optimal_executions) optimal,sum(onepass_executions) onepass,
       sum(multipasses_executions) multipass from v\$sql_workarea;
select name,value execution_count,
       decode(sum(value) over(),0,0,round(value*100/sum(value) over(),2)) percentage
from v\$sysstat where name like 'workarea exec%' order by name;

prompt [10] PGA TARGET ADVICE
select round(pga_target_for_estimate/1024/1024) target_mb,pga_target_factor,
       estd_pga_cache_hit_percentage,estd_overalloc_count
from v\$pga_target_advice order by pga_target_for_estimate;

prompt [11] ALERT LOG ORA-04036 OCCURRENCES
column message_text format a180
select originating_timestamp,inst_id,con_id,message_text
from v\$diag_alert_ext
where originating_timestamp between
      from_tz(to_timestamp('${START_TIME}','YYYY/MM/DD HH24:MI'),sessiontimezone) and
      from_tz(to_timestamp('${END_TIME}','YYYY/MM/DD HH24:MI'),sessiontimezone)
  and (message_text like '%ORA-04036%' or message_text like '%PGA_AGGREGATE_LIMIT%')
order by originating_timestamp;

prompt [12] ADR LOCATIONS
select name,value from v\$diag_info
where name in ('Diag Trace','Diag Alert','Default Trace File');

prompt [13] SQL TEXT FOR SQL IDs ACTIVE IN INCIDENT WINDOW
select * from (
 select h.sql_id,max(h.pga_allocated) max_pga_bytes,
        dbms_lob.substr(t.sql_text,4000,1) sql_text
 from dba_hist_active_sess_history h
 left join dba_hist_sqltext t on t.dbid=h.dbid and t.sql_id=h.sql_id and t.con_id=h.con_id
 where h.sample_time between to_timestamp('${START_TIME}','YYYY/MM/DD HH24:MI')
                         and to_timestamp('${END_TIME}','YYYY/MM/DD HH24:MI')
   and h.sql_id is not null
 group by h.sql_id,dbms_lob.substr(t.sql_text,4000,1)
 order by max_pga_bytes desc
) where rownum<=${TOP_N};
spool off
exit
SQL

log "Running PGA diagnostic SQL against ${ORACLE_SID}..."
"$ORACLE_HOME/bin/sqlplus" -s "/ as sysdba" @"$SQLFILE"
SQL_RC=$?
[[ -s "$REPORT" ]] || die "SQL report was not generated. SQL*Plus return code: ${SQL_RC}"

# Automatically locate ADR trace directory and collect error arguments / SQL IDs.
TRACE_DIR=$("$ORACLE_HOME/bin/sqlplus" -s "/ as sysdba" <<'SQL' | sed '/^[[:space:]]*$/d' | tail -1
set heading off feedback off pages 0 verify off echo off
select value from v$diag_info where name='Diag Trace';
exit
SQL
)

{
  echo "ORA-04036 TRACE EVIDENCE"
  echo "Database: $ORACLE_SID"
  echo "Host: $HOST"
  echo "Window: $START_TIME to $END_TIME"
  echo "Trace directory: $TRACE_DIR"
  echo
} > "$TRACE_EVIDENCE"

if [[ -d "$TRACE_DIR" ]]; then
  START_FIND=$(date -d "${START_TIME//\//-}" '+%Y-%m-%d %H:%M:00')
  END_FIND=$(date -d "${END_TIME//\//-} +1 minute" '+%Y-%m-%d %H:%M:00')
  while IFS= read -r -d '' f; do
    if grep -qiE 'ORA-04036|PGA_AGGREGATE_LIMIT' "$f" 2>/dev/null; then
      echo "===== FILE: $f =====" >> "$TRACE_EVIDENCE"
      grep -niE -B 15 -A 50 'ORA-04036|PGA_AGGREGATE_LIMIT|SQL_ID|sql_id|Arguments|Current SQL' "$f" \
        >> "$TRACE_EVIDENCE" 2>/dev/null || true
      echo >> "$TRACE_EVIDENCE"
    fi
  done < <(find "$TRACE_DIR" -maxdepth 1 -type f \( -name '*.trc' -o -name 'alert_*.log' \) \
              -newermt "$START_FIND" ! -newermt "$END_FIND" -print0 2>/dev/null)
else
  echo "Trace directory is unavailable to the executing OS account." >> "$TRACE_EVIDENCE"
fi

# Preserve only distinct SQL IDs found in trace evidence, if recognizable.
{
  echo
  echo "===== DISTINCT SQL IDS EXTRACTED FROM TRACE TEXT ====="
  grep -Eio '(sql[_ ]?id[[:space:]:=]+[[:alnum:]]{13})' "$TRACE_EVIDENCE" 2>/dev/null \
    | grep -Eo '[[:alnum:]]{13}$' | sort -u || true
} >> "$TRACE_EVIDENCE"

tar -czf "$ARCHIVE" -C "$WORK_DIR" "$(basename "$REPORT")" "$(basename "$TRACE_EVIDENCE")" "$(basename "$SQLFILE")" || die "Unable to create archive."

BODY_FILE="$WORK_DIR/mail_body.txt"
cat > "$BODY_FILE" <<EOF
Hello Team,

Please find attached the automated ORA-04036/PGA diagnostic report for:

Database : ${ORACLE_SID}
Host     : ${HOST}
Window   : ${START_TIME} to ${END_TIME}
Generated: $(date '+%F %T %Z')

The archive contains the SQL report, alert/trace evidence, extracted SQL IDs, and the generated SQL used for collection.

Regards,
Oracle DBA Automation
EOF

send_email() {
  if command -v mailx >/dev/null 2>&1; then
    local cc_args=()
    [[ -n "$MAIL_CC" ]] && cc_args=(-c "$MAIL_CC")
    mailx -s "$SUBJECT" -r "$MAIL_FROM" "${cc_args[@]}" -a "$ARCHIVE" "$MAIL_TO" < "$BODY_FILE"
  elif command -v mutt >/dev/null 2>&1; then
    local cc_args=()
    [[ -n "$MAIL_CC" ]] && cc_args=(-c "$MAIL_CC")
    mutt -s "$SUBJECT" "${cc_args[@]}" -a "$ARCHIVE" -- "$MAIL_TO" < "$BODY_FILE"
  elif command -v sendmail >/dev/null 2>&1 && command -v base64 >/dev/null 2>&1; then
    local boundary="ORA04036_${RUN_TS}_$$"
    {
      echo "From: $MAIL_FROM"
      echo "To: $MAIL_TO"
      [[ -n "$MAIL_CC" ]] && echo "Cc: $MAIL_CC"
      echo "Subject: $SUBJECT"
      echo "MIME-Version: 1.0"
      echo "Content-Type: multipart/mixed; boundary=$boundary"
      echo
      echo "--$boundary"
      echo "Content-Type: text/plain; charset=UTF-8"
      echo
      cat "$BODY_FILE"
      echo
      echo "--$boundary"
      echo "Content-Type: application/gzip; name=$(basename "$ARCHIVE")"
      echo "Content-Disposition: attachment; filename=$(basename "$ARCHIVE")"
      echo "Content-Transfer-Encoding: base64"
      echo
      base64 "$ARCHIVE"
      echo "--$boundary--"
    } | sendmail -t
  else
    return 127
  fi
}

if send_email; then
  log "Report emailed to ${MAIL_TO}."
else
  rc=$?
  cp "$ARCHIVE" "${OUTPUT_DIR:-/tmp}/" 2>/dev/null || true
  die "Email failed (rc=${rc}). Archive retained in ${OUTPUT_DIR:-/tmp}/$(basename "$ARCHIVE"). Configure mailx, mutt, or sendmail."
fi

# Optional cleanup of older retained reports.
find "${OUTPUT_DIR:-/tmp}" -maxdepth 1 -type f -name "ORA04036_${ORACLE_SID}_*.tgz" \
  -mtime "+${RETENTION_DAYS}" -delete 2>/dev/null || true
exit "$SQL_RC"
