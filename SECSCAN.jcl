//SECSCAN  JOB (ACCTNO),'DAVE-SECSCAN',CLASS=A,MSGCLASS=A,
//         NOTIFY=&SYSUID,REGION=0M,TIME=1440
//*-------------------------------------------------------------------
//* Runs the SECSCAN REXX exec in batch (via IKJEFT01/TSO) to sweep
//* every ONLINE (non-migrated) dataset under a target HLQ looking
//* for hardcoded PASSWORD / USER= / KEY / SECRET (etc) strings.
//*
//* IRX0408E "Exec member name must not be specified..." means the
//* SYSEXEC DD is pointing at a plain SEQUENTIAL dataset while you
//* invoked it as "%SECSCAN" (member-style call) - a flat sequential
//* dataset has no members, so TSO can't resolve "member SECSCAN"
//* inside it. Pick ONE of the two setups below, matching however
//* you actually staged SECSCAN.rexx on the mainframe:
//*
//*   OPTION A - SECSCAN.rexx copied into a PDS/PDSE member named
//*              SECSCAN (recommended - lets you keep other execs in
//*              the same library and call them the normal way):
//*     - point SYSEXEC at that PDS/PDSE (DISP=SHR)
//*     - SYSTSIN card stays "%SECSCAN TARGET.HLQ" (member-style call)
//*     - this is the ACTIVE setup below
//*
//*   OPTION B - SECSCAN.rexx left as a standalone SEQUENTIAL dataset
//*              (e.g. you just uploaded/REPRO'd the flat file as-is,
//*              no PDS involved):
//*     - drop the SYSEXEC DD entirely, it's not needed
//*     - call it by fully-qualified dataset name instead of %member:
//*         EXEC 'YOUR.REXX.SEQ.DATASET' 'TARGET.HLQ' EXEC
//*       (see the commented SYSTSIN card below - swap it in instead
//*       of the %SECSCAN one, and delete/comment the SYSEXEC DD)
//*
//* OTHER NOTES:
//*   - Change TARGET.HLQ to the HLQ you're actually sweeping.
//*   - Optionally override the search string list, e.g.:
//*        %SECSCAN TARGET.HLQ 'PASSWORD SECRET PIN CVV ACCTNUM'
//*     (same override works with the EXEC 'dsn' ... form too - just
//*     add the extra quoted string as a second argument)
//*   - REGION=0M below asks for max region since large PDSs get
//*     EXECIO'd entirely into memory member-by-member; tighten it
//*     if your site caps 0M.
//*   - This will ALLOCATE (open) every non-migrated dataset under
//*     the HLQ with SHR - if you don't have READ access to some of
//*     them, expect RACF violations logged against your userid.
//*     Loop in your point of contact before running this broadly.
//*-------------------------------------------------------------------
//SCAN     EXEC PGM=IKJEFT01,DYNAMNBR=250
//*        --- OPTION A: SECSCAN is a PDS/PDSE member - keep this DD,
//*        --- some shops use SYSPROC instead of SYSEXEC, either
//*        --- works, just rename the DD if your site expects SYSPROC
//SYSEXEC  DD DSN=YOUR.REXX.EXEC.LIBRARY,DISP=SHR
//SYSTSPRT DD SYSOUT=*
//*        --- to keep a permanent copy of the results instead of/
//*        --- in addition to SYSOUT, comment the line above out and
//*        --- uncomment this one (adjust space as needed):
//*SYSTSPRT DD DSN=YOUR.HLQ.SECSCAN.REPORT,DISP=(NEW,CATLG,DELETE),
//*            SPACE=(CYL,(5,5),RLSE),DSORG=PS,RECFM=FBA,LRECL=133,
//*            UNIT=SYSDA
//SYSTSIN  DD *
  %SECSCAN TARGET.HLQ
//*        --- OPTION B: SECSCAN is a standalone sequential dataset -
//*        --- comment out the %SECSCAN card above, remove/comment
//*        --- the SYSEXEC DD above, and uncomment this card instead:
//*  EXEC 'YOUR.REXX.SEQ.DATASET' 'TARGET.HLQ' EXEC
/*
