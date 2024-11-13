control 'SV-213781' do
  title 'Symmetric keys (other than the database master key) must use a DoD certificate to encrypt the key.'
  desc 'Data within the database is protected by use of encryption. The symmetric keys are critical for this process. If the symmetric keys were to be compromised the data could be disclosed to unauthorized personnel.

The database master key is exempt, as a password must be supplied when creating it.'
  desc 'check', "In a query tool:
USE <database name>;
GO
SELECT s.name, k.crypt_type_desc
FROM sys.symmetric_keys s, sys.key_encryptions k
WHERE s.symmetric_key_id = k.key_id
AND s.name <> '##MS_DatabaseMasterKey##'
AND k.crypt_type IN ('ESKP', 'ESKS')
ORDER BY s.name, k.crypt_type_desc;
GO

Review any symmetric keys that have been defined against the System Security Plan.

If any keys are defined that are not documented in the System Security Plan, this is a finding.

Review the System Security Plan to review the encryption mechanism specified for each symmetric key. If the method does not indicate use of certificates, this is a finding.

If the certificate specified is not a DoD PKI certificate, this is a finding."
  desc 'fix', 'Configure or alter symmetric keys to encrypt keys with certificates or authorized asymmetric keys.
In a query tool:
     ALTER SYMMETRIC KEY <key name> ADD ENCRYPTION BY CERTIFICATE <certificate name>;
     ALTER SYMMETRIC KEY <key name> DROP ENCRYPTION BY <password, symmetric key or asymmetric key>;

The symmetric key must specify a certificate or asymmetric key for encryption.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Database'
  tag check_id: 'C-15001r312421_chk'
  tag severity: 'medium'
  tag gid: 'V-213781'
  tag rid: 'SV-213781r961128_rule'
  tag stig_id: 'SQL4-00-024300'
  tag gtitle: 'SRG-APP-000231-DB-000154'
  tag fix_id: 'F-14999r312422_fix'
  tag 'documentable'
  tag legacy: ['SV-81875', 'V-67385']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']

  # review

  query = %{
    SELECT
        s.name, k.crypt_type_desc
    FROM
        sys.symmetric_keys s, sys.key_encryptions k
    WHERE
        s.symmetric_key_id = k.key_id
    AND
        s.name <> '##MS_DatabaseMasterKey##'
    AND
        k.crypt_type IN ('ESKS', 'ESKP','ESP2','ESP3')
    ORDER
        BY s.name, k.crypt_type_desc
    }

  sql_session = mssql_session(user: attribute('user'),
                              password: attribute('password'),
                              host: attribute('host'),
                              instance: attribute('instance'),
                              port: attribute('port'),
                              db_name: attribute('db_name'))

  if !sql_session.query(query).column('name').empty?
    describe "List of Symmetric keys in DB: #{attribute('db_name')} not encrypted\
    by DoD certificate" do
      subject { sql_session.query(query).column('name') }
      it { should be_empty }
    end
  end

  describe 'The following checks must be performed manually' do
    skip "The following checks must be performed manually:
    Review any symmetric keys that have been defined against the System Security
    Plan.

    If any keys are defined that are not documented in the System Security Plan,
    this is a finding.

    Review the System Security Plan to review the encryption mechanism specified
    for each symmetric key. If the method does not indicate use of certificates,
    this is a finding.

    If the certificate specified is not a DoD PKI certificate, this is a finding."
  end
end
