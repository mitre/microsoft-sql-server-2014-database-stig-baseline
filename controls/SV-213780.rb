control 'SV-213780' do
  title 'Database Master Key passwords must not be stored in credentials within the database.'
  desc 'Storage of the Database Master Key password in a database credential allows decryption of sensitive data by privileged users who may not have a need-to-know requirement to access the data.'
  desc 'check', 'From the query prompt:
SELECT COUNT(credential_id)
FROM [master].sys.master_key_passwords

If count is not 0, this is a finding.'
  desc 'fix', "Use the stored procedure sp_control_dbmasterkey_password to remove any credentials that
store Database Master Key passwords.
From the query prompt:
EXEC SP_CONTROL_DBMASTERKEY_PASSWORD @db_name = '<database name>', @action
= N'drop'"
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Database'
  tag check_id: 'C-15000r312418_chk'
  tag severity: 'medium'
  tag gid: 'V-213780'
  tag rid: 'SV-213780r961128_rule'
  tag stig_id: 'SQL4-00-024200'
  tag gtitle: 'SRG-APP-000231-DB-000154'
  tag fix_id: 'F-14998r312419_fix'
  tag 'documentable'
  tag legacy: ['SV-81873', 'V-67383']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']

  query = %{
    SELECT
          COUNT(credential_id) AS count_of_ids
    FROM
          [master].sys.master_key_passwords
  }

  sql_session = mssql_session(user: input('user'),
                              password: input('password'),
                              host: input('host'),
                              instance: input('instance'),
                              port: input('port'),
                              db_name: input('db_name'))

  describe 'Count of `Database Master Key passwords` stored in credentials within the database' do
    subject { sql_session.query(query).row(0).column('count_of_ids') }
    its('value') { should cmp 0 }
  end
end
