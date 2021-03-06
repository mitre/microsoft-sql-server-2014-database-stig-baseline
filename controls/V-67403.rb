control 'V-67403' do
  title "When supporting applications that require security labeling of data,
SQL Server must associate organization-defined types of security labels having
organization-defined security label values with information in process."
  desc  "Without the association of security labels to information, there is no
basis for the DBMS to make security-related access-control decisions.

    Security labels are abstractions representing the basic properties or
characteristics of an entity (e.g., subjects and objects) with respect to
safeguarding information.

    These labels are typically associated with internal data structures (e.g.,
tables, rows) within the database and are used to enable the implementation of
access control and flow control policies, reflect special dissemination,
handling or distribution instructions, or support other aspects of the
information security policy.

    One example includes marking data as classified or FOUO. These security
labels may be assigned manually or during data processing, but, either way, it
is imperative these assignments are maintained while the data is in storage. If
the security labels are lost when the data is stored, there is the risk of a
data compromise.

    SQL Server does not include security labeling as a standard or licensable
feature. Earlier releases of this STIG suggested using the SQL Server Label
Security Toolkit, from codeplex.com.  However, codeplex.com has been shut down,
and it is unclear whether the Toolkit is still supported.  If the organization
does have access to the Toolkit, it may still be used, provided the
organization accepts responsibility for its support.  Other implementations may
also exist. Custom application code is also a viable way to implement a
solution.
  "
  if attribute('security_labeling_required')
    impact 0.5
  else
    impact 0.0
    desc 'Security labeling is stated as `not required` in the attributes file,
    this control is not applicable'
  end

  tag "gtitle": 'SRG-APP-000313-DB-000309'
  tag "gid": 'V-67403'
  tag "rid": 'SV-81893r2_rule'
  tag "stig_id": 'SQL4-00-032000'
  tag "fix_id": 'F-73515r2_fix'
  tag "cci": ['CCI-002263']
  tag "nist": ['AC-16 a', 'Rev_4']
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "If security labeling is not required, this is not a finding.

If security labeling requirements have been specified, but the security
labeling is not implemented or does not reliably maintain labels on information
in process, this is a finding."
  tag "fix": "Develop SQL or application code or acquire a third party tool to
perform data labeling."

  describe 'This test currently has no automated tests, you must check manually' do
    skip 'This check must be preformed manually'
  end
end
