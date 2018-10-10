control "V-67383" do
  title "Database Master Key passwords must not be stored in credentials within
the database."
  desc  "Storage of the Database Master Key password in a database credential
allows decryption of sensitive data by privileged users who may not have a
need-to-know requirement to access the data."
  impact 0.7
  tag "gtitle": "SRG-APP-000231-DB-000154"
  tag "gid": "V-67383"
  tag "rid": "SV-81873r1_rule"
  tag "stig_id": "SQL4-00-024200"
  tag "fix_id": "F-73495r1_fix"
  tag "cci": ["CCI-001199"]
  tag "nist": ["SC-28", "Rev_4"]
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
  tag "check": "From the query prompt:
SELECT COUNT(credential_id)
FROM [master].sys.master_key_passwords

If count is not 0, this is a finding."
  tag "fix": "Use the stored procedure sp_control_dbmasterkey_password to
remove any credentials that
store Database Master Key passwords.
From the query prompt:
EXEC SP_CONTROL_DBMASTERKEY_PASSWORD @db_name = '<database name>', @action
= N'drop'"

  query= %(
    SELECT
          COUNT(credential_id) AS count_of_ids
    FROM
          [master].sys.master_key_passwords
  )

  sql = mssql_session(port: 49371) if sql.nil?

  describe "Count Database Master Key passwords stored in credentials within the database" do
    subject { sql.query(query).row(0).column('count_of_ids') }
    its('value') { should cmp 0 }
  end
end
