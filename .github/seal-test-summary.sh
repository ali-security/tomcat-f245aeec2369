#!/usr/bin/env bash
# Seal Security: summarise the Ant JUnit plain-formatter reports so the job log
# states how many tests ran, passed, failed and were skipped, and names every
# skipped test with its reason. Exits non-zero when no report exists or any
# test failed / errored.
set -u
dir="${1:-output/build/logs}"
shopt -s nullglob
files=("$dir"/TEST-*.txt)
if [ "${#files[@]}" -eq 0 ]; then
  echo "SEAL TEST SUMMARY: no JUnit reports found in $dir"
  exit 1
fi
jdk="$(java -version 2>&1 | head -n 1)"
LC_ALL=C awk -v jdk="$jdk" '
function flush() {
  if (file == "") return
  if (!hdr) {
    # The plain formatter occasionally omits the Tests run header; derive counts.
    r = cases; f = fcount; e = ecount; s = scount
    note = " (derived from Testcase markers; header absent)"
  } else { note = "" }
  suites++; tr += r; tf += f; te += e; ts += s
  printf "SUITE %s: run=%d failures=%d errors=%d skipped=%d%s\n", suite, r, f, e, s, note
}
FNR == 1 {
  flush()
  file = FILENAME; suite = FILENAME; sub(/.*\/TEST-/, "", suite); sub(/\.txt$/, "", suite)
  hdr = 0; cases = 0; fcount = 0; ecount = 0; scount = 0; tc = ""
}
/^Tests run: [0-9]+, Failures: [0-9]+, Errors: [0-9]+, Skipped: [0-9]+/ && !hdr {
  line = $0
  gsub(/[^0-9,]/, "", line); split(line, n, ",")
  r = n[1] + 0; f = n[2] + 0; e = n[3] + 0; s = n[4] + 0; hdr = 1
}
/^Testcase: / { cases++; tc = $0; sub(/^Testcase: /, "", tc); sub(/ took [0-9.]+ sec.*$/, "", tc) }
/^[ \t]+FAILED/ { fcount++; failed[++nf] = suite " :: " tc }
/^[ \t]+Caused an ERROR/ { ecount++; failed[++nf] = suite " :: " tc " (error)" }
/^[ \t]+SKIPPED/ {
  scount++
  reason = $0; sub(/^[ \t]+SKIPPED:? ?/, "", reason)
  if (reason == "") reason = "(no message; JUnit Assume/@Ignore without text)"
  if (reason ~ /^got: <(true|false)>, expected: is <(true|false)>/) {
    # Bare JUnit Assume messages: name the condition the test source checks.
    if (suite ~ /TestMessageBytesPerformance/)
      reason = reason " [cause: assumeFalse(JreCompat.isJre16Available()) - this performance comparison only applies to JRE < 16]"
    else if (tc ~ /OpenSSL-FFM|panama/ || suite ~ /TestAprLifecycleListener/)
      reason = reason " [cause: OpenSSL FFM (panama) variant - TesterSupport.configureSSLImplementation assumes OpenSSLLifecycleListener.isAvailable() and TestAprLifecycleListener assumes JreCompat.isJre22Available(); FFM needs JRE 22+ and this leg runs JDK " jdk ", the JDK that reproduces the published jar (which ships no FFM classes). The JNI OpenSSL and JSSE variants of the same test ran]"
    else if (tc ~ /OpenSSL/)
      reason = reason " [cause: tomcat-native JNI OpenSSL variant - TesterSupport.configureSSLImplementation assumes AprLifecycleListener.isAprAvailable(), tomcat-native could not be loaded]"
    else
      reason = reason " [bare JUnit assumption; see the test source]"
  }
  if (suite ~ /TestServerInfo/ && reason ~ /^APR not available/)
    reason = reason " [cause: AprLifecycleListener.isAprAvailable() only initialises tomcat-native once an AprLifecycleListener instance exists in the JVM (AprStatus.isInstanceCreated()); TestServerInfo never creates one, so this skips even though tomcat-native is installed and its JNI OpenSSL tests pass in this job]"
  skipped[++nsk] = "SKIPPED " suite " :: " tc " -- reason: " reason
  base = suite; sub(/\.NIO2?$/, "", base)
  key = base " -- " reason
  if (!(key in gcount)) gorder[++ng] = key
  gcount[key]++
}
END {
  flush()
  print "================ SKIPPED TESTS (" nsk ") ================"
  for (i = 1; i <= nsk; i++) print skipped[i]
  if (nf > 0) {
    print "================ FAILED TESTS (" nf ") ================"
    for (i = 1; i <= nf; i++) print "FAILED " failed[i]
  }
  print "================ SKIP REASONS GROUPED BY SUITE (" ng " groups, " nsk " skipped tests, NIO+NIO2 combined) ================"
  for (i = 1; i <= ng; i++) printf "SKIP-GROUP %4d x %s\n", gcount[gorder[i]], gorder[i]
  print "================================================================"
  printf "SEAL TEST TOTALS: suites=%d tests=%d passed=%d failures=%d errors=%d skipped=%d\n", suites, tr, tr - tf - te - ts, tf, te, ts
  print "================================================================"
  exit (tf + te > 0) ? 1 : 0
}
' "${files[@]}"
