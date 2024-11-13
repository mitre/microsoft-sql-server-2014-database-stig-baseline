control 'SV-213777' do
  title 'The DBMS and associated applications must provide non-privileged users with error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  desc %q(Any DBMS or associated application providing too much information in error messages on the screen or printout risks compromising the data and security of the system. The structure and content of error messages need to be carefully considered by the organization and development team.

Databases can inadvertently provide a wealth of information to an attacker through improperly handled error messages. In addition to sensitive business or personal information, database errors can provide host names, IP addresses, user names, and other system information not required for end-user troubleshooting but very useful to someone targeting the system.

Carefully consider the structure/content of error messages. The extent to which information systems are able to identify and handle error conditions is guided by organizational policy and operational requirements. Information that could be exploited by adversaries includes, for example, logon attempts with passwords entered by mistake as the username, mission/business information that can be derived from (if not stated explicitly by) information recorded, and personal information, such as account numbers, social security numbers, and credit card numbers.

It is important that detailed error messages be visible only to those who are authorized to view them; that general users receive only generalized acknowledgment that errors have occurred; and that these generalized messages appear only when relevant to the user's task. For example, a message along the lines of, "An error has occurred. Unable to save your changes. If this problem persists, please contact your help desk" would be relevant. A message such as "Warning: your transaction generated a large number of page splits" would likely not be relevant. "ABGQ is not a valid widget code" would be appropriate; but "The INSERT statement conflicted with the FOREIGN KEY constraint "WidgetTransactionFK". The conflict occurred in database "DB7", table "dbo.WidgetMaster", column 'WidgetCode'" would not, as it reveals too much about the database structure.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed and must document what has been discovered.)
  desc 'check', 'Review application behavior and custom database code (stored procedures; triggers),  to determine whether  error messages contain information beyond what is needed for explaining the issue to general users.

If database error messages contain PII data, sensitive business data, or information useful for identifying the host system or database structure, this is a finding.'
  desc 'fix', 'Configure DBMS settings, custom database code, and associated application code not to divulge sensitive information or information useful for system identification in error messages that are displayed to general users.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Database'
  tag check_id: 'C-14997r312409_chk'
  tag severity: 'medium'
  tag gid: 'V-213777'
  tag rid: 'SV-213777r961167_rule'
  tag stig_id: 'SQL4-00-022800'
  tag gtitle: 'SRG-APP-000266-DB-000162'
  tag fix_id: 'F-14995r312410_fix'
  tag 'documentable'
  tag legacy: ['SV-81887', 'V-67397']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  # The below query was taken from 2016 MSSQL STIG

  query = %{
    DBCC
      TRACESTATUS (3625, -1)
    GO
    }

  sql_session = mssql_session(user: attribute('user'),
                              password: attribute('password'),
                              host: attribute('host'),
                              instance: attribute('instance'),
                              port: attribute('port'),
                              db_name: attribute('db_name'))

  describe 'TRACEFLAG 3625' do
    subject { sql_session.query(query).rows[0] }
    its('status') { should cmp 1 }
    its('global') { should cmp 1 }
  end
end
