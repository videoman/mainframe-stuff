/* REXX ***************************************************************
 * SECSCAN - walk every ONLINE (non-migrated) dataset under a given
 *           HLQ and grep each record for hardcoded secrets:
 *           PASSWORD, USER=, KEY, SECRET, PASSWD, PWD, APIKEY, TOKEN
 *           (case-insensitive substring match, override with parm 2)
 *
 * INVOCATION
 *   From TSO/ISPF READY prompt or via IKJEFT01 in batch:
 *      SECSCAN hlq
 *      SECSCAN hlq  'STRING1 STRING2 STRING3'
 *
 *   Example:
 *      SECSCAN PAYROLL.PROD
 *      SECSCAN PAYROLL.PROD 'PASSWORD SECRET PIN CVV ACCTNUM'
 *
 * WHAT IT DOES
 *   1. LISTCAT LEVEL(hlq) ALL  -> enumerate every catalog entry at or
 *      below the HLQ, pull out the NON-VSAM dataset names.
 *   2. LISTDSI(dsn NORECALL) on each one - the built-in TSO/E REXX
 *      function for dataset attributes (no text-scraping needed).
 *      SYSDSORG comes back as MIGRAT if it's migrated/offline (and
 *      NORECALL stops LISTDSI from silently recalling it for us) -
 *      those get skipped. Otherwise SYSDSORG tells us PS vs PO.
 *        PS -> read it directly
 *        PO -> LISTDS ... MEMBERS, then read every member
 *   3. Each record is uppercased and scanned for every search string.
 *      Hits are written to SYSTSPRT as: dsn, member, line#, text.
 *
 * WHAT IT DELIBERATELY SKIPS
 *   - VSAM clusters/AIX/paths (catalog entry type VSAM, not NONVSAM).
 *     Reading those needs REPRO to a flat file first - not done here.
 *   - Migrated (offline) datasets - by design, per your ask. Recall
 *     them first (HRECALL) if you want them included, then rerun.
 *   - Anything you don't have READ access to (ALLOCATE just fails and
 *     it's skipped/logged) - expect RACF violations to be logged
 *     against your userid for every dataset you can't read, so loop
 *     the client/point of contact in before you fire this at a whole
 *     production HLQ.
 *
 * CAVEAT
 *   Every matching dataset gets EXECIO'd entirely into a REXX stem
 *   in memory. Fine for normal PDS members/sequential files; if the
 *   HLQ has genuinely huge sequential datasets, bump REGION in the
 *   JCL and expect it to take a while.
 *********************************************************************/

arg hlq patlist

hlq = strip(strip(hlq),'B',"'")

if hlq = '' then do
  say 'SECSCAN: usage -> SECSCAN hlq  [optional ''STRING1 STRING2..'']'
  exit 8
end

if patlist = '' then
  patlist = 'PASSWORD USER= KEY SECRET PASSWD PWD APIKEY TOKEN'

patcount = words(patlist)

hitcount  = 0
dsncount  = 0
skipcount = 0
ddctr     = 0

say '*******************************************************************'
say '* SECSCAN starting'
say '* HLQ            :' hlq
say '* Search strings  :' patlist
say '* Start           :' date() time()
say '*******************************************************************'

/* ---- pull every catalog entry at/below the HLQ ------------------- */
x = outtrap('cat.')
address TSO "LISTCAT LEVEL('"hlq"') ALL"
lcrc = rc
x = outtrap('OFF')

if lcrc > 4 then do
  say 'SECSCAN: LISTCAT LEVEL('hlq') failed, RC='lcrc' - nothing to do.'
  exit 8
end

/* ---- pull out NONVSAM entries --------------------------------------*/
n = 0
drop dsn.
do i = 1 to cat.0
  line = cat.i
  if word(line,1) = 'NONVSAM' then do
    /* dsname is always the last token on the NONVSAM line, e.g.
       "NONVSAM ------- HLQ.DATASET.NAME" - grabbing the last word
       is more robust than parsing on '-' since IDCAMS pads with a
       variable number of dashes */
    dsname = word(line, words(line))
    n = n + 1
    dsn.n = strip(strip(dsname),'B',"'")
  end
end
dsn.0 = n

say 'SECSCAN: found' n 'non-VSAM catalog entries under' hlq

/* ---- walk each dataset -------------------------------------------- */
do d = 1 to dsn.0
  thisdsn = dsn.d

  /* LISTDSI populates SYSDSORG/SYSREASON/etc as plain REXX vars.
     NORECALL means a migrated dataset is NOT recalled for us - it
     just reports back SYSDSORG='MIGRAT' so we can skip it cleanly. */
  ldsirc = listdsi("'"thisdsn"' NORECALL")

  if sysdsorg = 'MIGRAT' then do
    say '  SKIP (migrated/offline)              : ' thisdsn
    skipcount = skipcount + 1
    iterate
  end

  if ldsirc > 4 then do
    say '  SKIP (LISTDSI rc='ldsirc' reason='sysreason')      : ' thisdsn
    skipcount = skipcount + 1
    iterate
  end

  dsorg = sysdsorg

  dsncount = dsncount + 1

  select
    when pos('PO',dsorg) > 0 then
      call scanpds thisdsn
    when pos('PS',dsorg) > 0 then
      call scanseq thisdsn, ''
    otherwise do
      say '  SKIP (DSORG='dsorg')                   : ' thisdsn
      skipcount = skipcount + 1
      dsncount = dsncount - 1
    end
  end
end

say '*******************************************************************'
say '* SECSCAN complete'
say '* Datasets scanned  :' dsncount
say '* Datasets skipped  :' skipcount
say '* Hits found        :' hitcount
say '* End               :' date() time()
say '*******************************************************************'
exit 0

/* ===================================================================
   SCANPDS - list members of a PDS/PDSE, scan each one
   =================================================================== */
scanpds: procedure expose patlist patcount hitcount ddctr
  parse arg pds

  x = outtrap('mem.')
  address TSO "LISTDS '"pds"' MEMBERS"
  mrc = rc
  x = outtrap('OFF')

  if mrc > 0 then do
    say '  SKIP (cannot list members, rc='mrc') : ' pds
    return
  end

  start = 0
  do i = 1 to mem.0
    if start = 1 then do
      m = strip(mem.i)
      if m \= '' then
        call scanseq pds, m
    end
    if pos('--MEMBERS',mem.i) > 0 then
      start = 1
  end
return

/* ===================================================================
   SCANSEQ - allocate + read one sequential dataset (or one PDS
             member), scan every record for the target strings
   =================================================================== */
scanseq: procedure expose patlist patcount hitcount ddctr
  parse arg dsn, member

  if member = '' then
    fulldsn = dsn
  else
    fulldsn = dsn'('member')'

  ddctr = ddctr + 1
  ddn = 'SC'right(ddctr,6,0)

  address TSO "ALLOCATE FILE("ddn") DSN('"fulldsn"') SHR REUSE"
  arc = rc
  if arc \= 0 then do
    say '  SKIP (alloc rc='arc')          : ' fulldsn
    return
  end

  drop rec.
  "EXECIO * DISKR" ddn "(STEM rec. FINIS"
  rrc = rc

  address TSO "FREE FILE("ddn")"

  if rrc > 4 then do
    say '  SKIP (read rc='rrc')           : ' fulldsn
    return
  end

  do i = 1 to rec.0
    line = rec.i
    upline = translate(line)
    do p = 1 to patcount
      pat = translate(word(patlist,p))
      if pos(pat,upline) > 0 then do
        hitcount = hitcount + 1
        say '  HIT ['pat'] ' fulldsn ' line' i ': ' strip(line)
      end
    end
  end
return
