control 'SV-213784' do
  title 'When supporting applications that require security labeling of data, SQL Server must associate organization-defined types of security labels having organization-defined security label values with information in storage.'
  desc 'Without the association of security labels to information, there is no basis for the DBMS to make security-related access-control decisions.

Security labels are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information.

These labels are typically associated with internal data structures (e.g., tables, rows) within the database and are used to enable the implementation of access control and flow control policies, reflect special dissemination, handling or distribution instructions, or support other aspects of the information security policy.

One example includes marking data as classified or FOUO. These security labels may be assigned manually or during data processing, but, either way, it is imperative these assignments are maintained while the data is in storage. If the security labels are lost when the data is stored, there is the risk of a data compromise.


SQL Server does not include security labeling as a standard or licensable feature. Earlier releases of this STIG suggested using the SQL Server Label Security Toolkit, from codeplex.com.  However, codeplex.com has been shut down, and it is unclear whether the Toolkit is still supported.  If the organization does have access to the Toolkit, it may still be used, provided the organization accepts responsibility for its support.  Other implementations may also exist. Custom application code is also a viable way to implement a solution.'
  desc 'check', 'If security labeling is not required, this is not a finding.

If security labeling requirements have been specified, but the security labeling is not implemented or does not reliably maintain labels on information in storage, this is a finding.'
  desc 'fix', 'Develop SQL or application code or acquire a third party tool to perform data labeling.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Database'
  tag check_id: 'C-15004r312430_chk'
  tag severity: 'medium'
  tag gid: 'V-213784'
  tag rid: 'SV-213784r961269_rule'
  tag stig_id: 'SQL4-00-031900'
  tag gtitle: 'SRG-APP-000311-DB-000308'
  tag fix_id: 'F-15002r312431_fix'
  tag 'documentable'
  tag legacy: ['SV-81891', 'V-67401']
  tag cci: ['CCI-002262']
  tag nist: ['AC-16 a']

  if input('security_labeling_required')
    impact 0.5
  else
    impact 0.0
    desc 'Security labeling is stated as `not required` in the attributes file,
    this control is not applicable'
  end

  describe 'Test has no automation procedure, checks must be performed manually' do
    skip 'This check must be performed manually'
  end
end
