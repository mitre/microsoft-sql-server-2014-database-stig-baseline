| Check          | Sub-check                                                                         | Who | Completion Date | Issue #'s |
|----------------|-----------------------------------------------------------------------------------|-----|-----------------|-----------|
|Logical checks| Proper profile directory structure							|*|*|*|
||JSON output review (e.g., pass/fail on ,<br>hardened, not hardened, edge cases, etc.)|*|*|*|
||InSpec syntax checker|*|*|*|
||Local commands focused on target not the runner|Alicia Sturtevant|11/2/2018|n/a|
|Quality checks|Alignment (including tagging) to original<br> standard (i.e. STIG, CIS Benchmark, NIST Tags)|Alicia Sturtevant|*|*|
||Descriptive output for findings details|*|*|*|
|Docs|Documentation quality (i.e. README)<br> novice level instructions including prerequisites|Yarick Tsagoyko|10/31/2018|n/a|
||Consistency across other profile conventions |Alicia Sturtevant|11/2/2018|n/a|
||Spelling grammar|Alicia Sturtevant|11/2/2018|n/a|
||Removing debugging documentation and code|*|*|*|
| Error handling |“Profile Error” containment: “null” responses <br>should only happen if InSpec is run with incorrect privileges|*|*|*|
||Slowing the target (e.g. filling up disk, CPU spikes)|*|*|*|
||Check for risky commands (e.g. rm, del, purge, etc.)|Alicia Sturtevant|11/2/2018|n/a|
||Check for “stuck” situations (e.g., profile goes on forever)|*|*|*|
