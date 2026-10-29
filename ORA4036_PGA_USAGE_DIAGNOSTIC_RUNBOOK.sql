-- ============================================================================
-- ORA-04036 / PGA USAGE DIAGNOSTIC RUNBOOK
-- Purpose : Analyze "PGA memory used by the instance or PDB exceeds
--           PGA_AGGREGATE_LIMIT" and identify the responsible session/SQL.
-- Usage   : Run as a privileged account with access to V$/GV$ and AWR views.
-- Notes   : AWR/DBA_HIST sections require the Diagnostics Pack license.
--           For RAC, run the GV$ sections and review each INST_ID separately.
-- ============================================================================

SET ECHO OFF
SET VERIFY OFF
SET FEEDBACK ON
SET LINESIZE 300
SET PAGESIZE 1000
SET LONG 100000
SET LONGCHUNKSIZE 100000
SET TRIMSPOOL ON
ALTER SESSION SET nls_date_format = 'DD-MON-YYYY HH24:MI:SS';

ACCEPT begin_timestamp CHAR PROMPT 'Incident begin time (YYYY/MM/DD HH24:MI): '
ACCEPT end_timestamp   CHAR PROMPT 'Incident end time   (YYYY/MM/DD HH24:MI): '
ACCEPT seconds         NUMBER DEFAULT 60 PROMPT 'Live ASH lookback seconds [60]: '
ACCEPT topn            NUMBER DEFAULT 10 PROMPT 'Top rows [10]: '
ACCEPT dbid            NUMBER PROMPT 'DBID: '

SPOOL ora_04036_pga_analysis.log

PROMPT ========================================================================
PROMPT STEP 1 - DATABASE, INSTANCE, CONTAINER, ROLE AND MEMORY CONFIGURATION
PROMPT ========================================================================
SELECT d.name database_name, d.dbid, d.database_role, d.open_mode,
       i.instance_number, i.instance_name, i.host_name, i.version,
       i.startup_time, SYS_CONTEXT('USERENV','CON_NAME') current_container
FROM v$database d CROSS JOIN v$instance i;

SHOW PDBS

COLUMN parameter FORMAT A35
SELECT con_id, name parameter,
       CASE WHEN name = 'processes' THEN TO_CHAR(value)
            ELSE TO_CHAR(ROUND(value/1024/1024,2)) END value_mb_or_count
FROM v$system_parameter
WHERE name IN ('pga_aggregate_target','pga_aggregate_limit','memory_target',
               'memory_max_target','sga_target','sga_max_size','processes',
               'workarea_size_policy')
ORDER BY con_id, name;

PROMPT ========================================================================
PROMPT STEP 2 - CURRENT INSTANCE-WIDE PGA PRESSURE
PROMPT ========================================================================
COLUMN name FORMAT A40
SELECT name,
       CASE WHEN unit = 'bytes' THEN TO_CHAR(ROUND(value/1024/1024,2))
            ELSE TO_CHAR(value) END value_mb_or_count,
       unit
FROM v$pgastat
WHERE name IN ('aggregate PGA target parameter','aggregate PGA auto target',
               'total PGA inuse','total PGA allocated','maximum PGA allocated',
               'total freeable PGA memory','over allocation count',
               'extra bytes read/written','cache hit percentage')
ORDER BY name;

SELECT ROUND(SUM(pga_max_mem)/POWER(1024,3),2) max_pga_gb,
       ROUND(SUM(pga_alloc_mem)/POWER(1024,3),2) allocated_pga_gb,
       ROUND(SUM(pga_used_mem)/POWER(1024,3),2) used_pga_gb,
       ROUND(SUM(pga_freeable_mem)/POWER(1024,3),2) freeable_pga_gb
FROM v$process;

PROMPT ========================================================================
PROMPT STEP 3 - MEMORY COMPONENTS AND INSTANCE/PDB SCOPE
PROMPT ========================================================================
COLUMN component FORMAT A35
SELECT inst_id, component,
       ROUND(current_size/1024/1024) current_size_mb,
       ROUND(min_size/1024/1024) min_size_mb,
       ROUND(max_size/1024/1024) max_size_mb
FROM gv$memory_dynamic_components
WHERE current_size <> 0
ORDER BY inst_id, component;

PROMPT ========================================================================
PROMPT STEP 4 - TOP CURRENT PROCESSES AND SESSIONS BY PGA
PROMPT ========================================================================
COLUMN username FORMAT A25
COLUMN program FORMAT A45
COLUMN module FORMAT A40
COLUMN machine FORMAT A30
SELECT * FROM (
  SELECT p.inst_id, p.spid, s.sid, s.serial#, s.con_id,
         NVL(s.username,'(oracle)') username, s.status,
         s.sql_id, s.prev_sql_id, s.service_name, s.module, s.machine, s.program,
         ROUND(p.pga_used_mem/1024/1024,2) pga_used_mb,
         ROUND(p.pga_alloc_mem/1024/1024,2) pga_alloc_mb,
         ROUND(p.pga_freeable_mem/1024/1024,2) pga_freeable_mb,
         ROUND(p.pga_max_mem/1024/1024,2) pga_max_mb,
         TO_CHAR(s.logon_time,'DD-MON-YYYY HH24:MI:SS') logon_time,
         s.last_call_et
  FROM gv$process p
  LEFT JOIN gv$session s
    ON s.inst_id = p.inst_id AND s.paddr = p.addr
  ORDER BY p.pga_alloc_mem DESC
)
WHERE ROWNUM <= &topn;

PROMPT -- Long-running sessions (logged on for more than one day)
SELECT p.inst_id, NVL(s.username,'(oracle)') username, s.sid, s.serial#, p.spid,
       s.sql_id, s.status, s.module, s.machine, s.program,
       ROUND(p.pga_alloc_mem/1024/1024,2) pga_alloc_mb,
       ROUND(p.pga_used_mem/1024/1024,2) pga_used_mb,
       TO_CHAR(s.logon_time,'DD-MON-YYYY HH24:MI:SS') logon_time
FROM gv$session s JOIN gv$process p
  ON s.inst_id=p.inst_id AND s.paddr=p.addr
WHERE s.logon_time < SYSDATE-1
ORDER BY p.pga_alloc_mem DESC;

PROMPT ========================================================================
PROMPT STEP 5 - TOP SQL BY LIVE ASH PGA GROWTH
PROMPT ========================================================================
COLUMN percent FORMAT 990.99
COLUMN star FORMAT A10
SELECT sql_id, ROUND(pga_mb,1) pga_mb, percent,
       RPAD('*',LEAST(10,ROUND(percent/10)),'*') star
FROM (
  SELECT sql_id, SUM(delta_pga_mb) pga_mb,
         RATIO_TO_REPORT(SUM(delta_pga_mb)) OVER ()*100 percent,
         RANK() OVER(ORDER BY SUM(delta_pga_mb) DESC) rnk
  FROM (
    SELECT session_id, session_serial#, sample_id, sql_id, sample_time,
           pga_allocated,
           GREATEST(pga_allocated - LAG(pga_allocated) OVER
             (PARTITION BY session_id, session_serial# ORDER BY sample_time),0)
             /POWER(1024,2) delta_pga_mb
    FROM v$active_session_history
    WHERE is_sqlid_current='Y'
      AND sample_time > SYSDATE-&seconds/86400
  )
  GROUP BY sql_id
  HAVING SUM(delta_pga_mb) > 0
)
WHERE rnk <= &topn
ORDER BY rnk;

PROMPT ========================================================================
PROMPT STEP 6 - SQL TEXT FOR CURRENT HIGH-PGA SESSIONS
PROMPT ========================================================================
SELECT DISTINCT s.inst_id, s.sid, s.serial#, s.sql_id,
       DBMS_LOB.SUBSTR(q.sql_fulltext,1000,1) sql_text
FROM gv$session s
JOIN gv$sql q ON q.inst_id=s.inst_id AND q.sql_id=s.sql_id
WHERE s.sql_id IS NOT NULL
  AND EXISTS (
    SELECT 1 FROM gv$process p
    WHERE p.inst_id=s.inst_id AND p.addr=s.paddr
      AND p.pga_alloc_mem > 0
  )
ORDER BY s.inst_id, s.sid;

PROMPT ========================================================================
PROMPT STEP 7 - HISTORICAL PGA TREND AROUND THE INCIDENT (AWR)
PROMPT ========================================================================
SELECT sn.instance_number,
       pga.allo pga_gb,
       sga.allo sga_gb,
       pga.allo+sga.allo total_gb,
       TRUNC(sn.end_interval_time,'MI') sample_time
FROM (SELECT snap_id, instance_number,
             ROUND(SUM(bytes)/POWER(1024,3),3) allo
      FROM dba_hist_sgastat GROUP BY snap_id,instance_number) sga
JOIN (SELECT snap_id, instance_number,
             ROUND(SUM(value)/POWER(1024,3),3) allo
      FROM dba_hist_pgastat
      WHERE name='total PGA allocated'
      GROUP BY snap_id,instance_number) pga
  ON pga.snap_id=sga.snap_id AND pga.instance_number=sga.instance_number
JOIN dba_hist_snapshot sn
  ON sn.snap_id=sga.snap_id AND sn.instance_number=sga.instance_number
WHERE sn.end_interval_time BETWEEN
      TO_TIMESTAMP('&begin_timestamp','YYYY/MM/DD HH24:MI') AND
      TO_TIMESTAMP('&end_timestamp','YYYY/MM/DD HH24:MI')
ORDER BY sample_time, sn.instance_number;

PROMPT ========================================================================
PROMPT STEP 8 - TOP HISTORICAL SQL IDs BY PGA DURING INCIDENT (AWR ASH)
PROMPT ========================================================================
SELECT * FROM (
  SELECT instance_number, sql_id, MAX(pga_sum_mb) pga_max_mb
  FROM (
    SELECT instance_number, sample_time, sql_id,
           ROUND(SUM(NVL(pga_allocated,0))/1024/1024) pga_sum_mb
    FROM dba_hist_active_sess_history
    WHERE sample_time BETWEEN
          TO_TIMESTAMP('&begin_timestamp','YYYY/MM/DD HH24:MI') AND
          TO_TIMESTAMP('&end_timestamp','YYYY/MM/DD HH24:MI')
      AND sql_id IS NOT NULL
    GROUP BY instance_number, sample_time, sql_id
  )
  GROUP BY instance_number, sql_id
  ORDER BY pga_max_mb DESC
)
WHERE ROWNUM <= &topn;

SELECT * FROM (
  SELECT h.instance_number, h.con_id, h.sql_id,
         ROUND(MAX(h.pga_allocated)/POWER(2,30),2) max_pga_gb,
         DBMS_LOB.SUBSTR(t.sql_text,1000,1) sql_text
  FROM dba_hist_active_sess_history h
  LEFT JOIN dba_hist_sqltext t
    ON t.dbid=h.dbid AND t.sql_id=h.sql_id AND t.con_id=h.con_id
  WHERE h.dbid=&dbid
    AND h.sample_time BETWEEN
        TO_TIMESTAMP('&begin_timestamp','YYYY/MM/DD HH24:MI') AND
        TO_TIMESTAMP('&end_timestamp','YYYY/MM/DD HH24:MI')
    AND h.sql_id IS NOT NULL
  GROUP BY h.instance_number,h.con_id,h.sql_id,
           DBMS_LOB.SUBSTR(t.sql_text,1000,1)
  ORDER BY max_pga_gb DESC
)
WHERE ROWNUM <= &topn;

PROMPT ========================================================================
PROMPT STEP 9 - WORKAREA EFFICIENCY AND TEMP SPILL
PROMPT ========================================================================
SELECT name, value
FROM v$pgastat
WHERE name LIKE 'workarea executions%'
   OR name IN ('over allocation count','extra bytes read/written',
               'cache hit percentage')
ORDER BY name;

SELECT SUM(optimal_executions) optimal,
       SUM(onepass_executions) onepass,
       SUM(multipasses_executions) multipass
FROM v$sql_workarea;

SELECT name workarea_profile, value execution_count,
       DECODE(SUM(value) OVER (),0,0,
              ROUND(value*100/SUM(value) OVER (),2)) percentage
FROM v$sysstat
WHERE name LIKE 'workarea exec%'
ORDER BY name;

PROMPT ========================================================================
PROMPT STEP 10 - PGA TARGET ADVICE AND CAPACITY CHECK
PROMPT ========================================================================
SELECT ROUND(pga_target_for_estimate/1024/1024) target_mb,
       pga_target_factor,
       estd_pga_cache_hit_percentage cache_hit_percent,
       estd_overalloc_count
FROM v$pga_target_advice
ORDER BY pga_target_for_estimate;

WITH max_pga AS
 (SELECT ROUND(value/1024/1024,1) max_pga_mb
  FROM v$pgastat WHERE name='maximum PGA allocated'),
 mga_curr AS
 (SELECT ROUND(value/1024/1024,1) mga_curr_mb
  FROM v$pgastat WHERE name='MGA allocated (under PGA)'),
 max_util AS
 (SELECT max_utilization max_processes
  FROM v$resource_limit WHERE resource_name='processes')
SELECT a.max_pga_mb, NVL(b.mga_curr_mb,0) current_mga_mb,
       c.max_processes,
       ROUND(((a.max_pga_mb-NVL(b.mga_curr_mb,0))+(c.max_processes*5))*1.1,1)
         calculated_limit_mb
FROM max_pga a CROSS JOIN mga_curr b CROSS JOIN max_util c;

PROMPT ========================================================================
PROMPT STEP 11 - FINAL INCIDENT EVIDENCE: ALERT LOG OCCURRENCE
PROMPT ========================================================================
PROMPT -- ADR alert-log rows for ORA-04036 inside the supplied incident window.
COLUMN message_text FORMAT A180
SELECT originating_timestamp, inst_id, con_id, message_text
FROM v$diag_alert_ext
WHERE originating_timestamp BETWEEN
      FROM_TZ(TO_TIMESTAMP('&begin_timestamp','YYYY/MM/DD HH24:MI'),SESSIONTIMEZONE) AND
      FROM_TZ(TO_TIMESTAMP('&end_timestamp','YYYY/MM/DD HH24:MI'),SESSIONTIMEZONE)
  AND (message_text LIKE '%ORA-04036%'
       OR message_text LIKE '%PGA_AGGREGATE_LIMIT%')
ORDER BY originating_timestamp;

PROMPT ========================================================================
PROMPT STEP 12 - FINAL INCIDENT EVIDENCE: ARGUMENTS AND SQL_ID FROM TRACE
PROMPT ========================================================================
PROMPT 1) Obtain ADR locations:
SELECT name, value FROM v$diag_info
WHERE name IN ('Diag Trace','Diag Alert','Default Trace File');

PROMPT 2) At OS level, search the alert log and trace files near the timestamp:
PROMPT grep -n -B 10 -A 30 "ORA-04036" alert_<ORACLE_SID>.log
PROMPT grep -RniE -B 10 -A 40 "ORA-04036|PGA_AGGREGATE_LIMIT|SQL_ID|sql_id|Arguments" <Diag_Trace_Path>/*.trc

PROMPT 3) In the matching trace file, capture these exact fields in the incident record:
PROMPT    Error timestamp  : <from alert log>
PROMPT    Error text       : ORA-04036 ...
PROMPT    Trace file       : <full trace filename>
PROMPT    Process/session  : <SPID, SID,SERIAL#, INST_ID, CON_ID if present>
PROMPT    Error arguments  : <all arguments printed by the trace>
PROMPT    Current SQL_ID   : <SQL ID printed in trace>
PROMPT    SQL text         : <SQL text printed in trace or fetched below>

PROMPT 4) After obtaining the SQL_ID from trace, execute:
ACCEPT trace_sql_id CHAR PROMPT 'SQL_ID found in trace (enter NONE to skip lookup): '
SELECT inst_id, sql_id, child_number, plan_hash_value,
       executions, parsing_schema_name, module,
       DBMS_LOB.SUBSTR(sql_fulltext,4000,1) sql_text
FROM gv$sql
WHERE sql_id='&trace_sql_id'
ORDER BY inst_id, child_number;

SELECT dbid, con_id, sql_id,
       DBMS_LOB.SUBSTR(sql_text,4000,1) historical_sql_text
FROM dba_hist_sqltext
WHERE dbid=&dbid AND sql_id='&trace_sql_id';

PROMPT ========================================================================
PROMPT INTERPRETATION ORDER
PROMPT ========================================================================
PROMPT A. Confirm whether the limit was instance-level or PDB-level.
PROMPT B. Compare total/maximum PGA against PGA_AGGREGATE_LIMIT.
PROMPT C. Identify top process/session, then map it to SQL_ID and SQL text.
PROMPT D. Correlate AWR/ASH peak time with the alert-log timestamp.
PROMPT E. Review workarea spill and over-allocation indicators.
PROMPT F. Preserve alert entry, trace arguments and trace SQL_ID as evidence.
PROMPT G. Change PGA settings only after validating OS memory headroom,
PROMPT    concurrency, Resource Manager/PDB constraints and workload behavior.

SPOOL OFF
SET VERIFY ON
-- End of runbook
