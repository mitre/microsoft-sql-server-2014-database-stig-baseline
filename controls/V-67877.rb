control "V-67877" do
  title "SQL Server must protect data at rest and ensure confidentiality and
integrity of data."
  desc  "This control is intended to address the confidentiality and integrity
of information at rest in non-mobile devices and covers user information and
system information.  Information at rest refers to the state of information
when it is located on a secondary storage device (e.g., disk drive, tape drive)
within an organizational information system. Applications and application users
generate information throughout the course of their application use.

    User-generated data, as well as, application-specific configuration data,
needs to be protected. Configurations and/or rule sets for firewalls, gateways,
intrusion detection/prevention systems, filtering routers, and authenticator
content are examples of system information likely requiring protection.
Organizations may choose to employ different mechanisms to achieve
confidentiality and integrity protections, as appropriate.

    If the confidentiality and integrity of SQL Server data is not protected,
the data will be open to compromise and unauthorized modification.

    Protective measures include encryption, physical security of the facility
where the storage devices reside, operating system file permissions, and
organizational controls.  Each of these should be applied as necessary and
appropriate.
  "
  impact 0.7
  tag "gtitle": "SRG-APP-000231-DB-000154"
  tag "gid": "V-67877"
  tag "rid": "SV-82367r3_rule"
  tag "stig_id": "SQL4-00-021300"
  tag "fix_id": "F-73993r1_fix"
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
  tag "check": "If the application owner and Authorizing Official have
determined that encryption of data at rest is NOT required, this is not a
finding.

If the application owner and Authorizing Official have determined that
encryption of data at rest is required, ensure the data on secondary devices is
encrypted.

If full-disk encryption is being used, this is not a finding.

If DBMS data encryption is required, ensure the data is encrypted before being
put on the secondary device by executing:

SELECT
      d.name AS [Database Name],
      CASE e.encryption_state
            WHEN 0 THEN 'No database encryption key present, no encryption'
            WHEN 1 THEN 'Unencrypted'
            WHEN 2 THEN 'Encryption in progress'
            WHEN 3 THEN 'Encrypted'
            WHEN 4 THEN 'Key change in progress'
            WHEN 5 THEN 'Decryption in progress'
            WHEN 6 THEN 'Protection change in progress'
      END AS [Encryption State]
FROM sys.dm_database_encryption_keys e
RIGHT JOIN sys.databases d ON DB_NAME(e.database_id) = d.name
WHERE d.name NOT IN ('master','model','msdb')
ORDER BY 1;

For each user database where encryption is required, verify that encryption is
in effect. If not, this is a finding.

Verify that there are physical security measures, operating system access
control lists and organizational controls appropriate to the sensitivity level
of the data in the database(s). If not, this is a finding."
  tag "fix": "Apply appropriate controls to protect the confidentiality and
integrity of data on a secondary device.

Where encryption is required, this can be done by full-disk encryption or by
database encryption. To enable database encryption, create a master key, create
a database encryption key, and protect it by using mechanisms tied to the
master key, and then set encryption on.

Implement physical security measures, operating system access control lists and
organizational controls appropriate to the sensitivity level of the data in the
database(s)."


  encrypted_databases = attribute('encrypted_databases')
  data_at_rest_encryption_required = attribute('data_at_rest_encryption_required')
  full_disk_encryption_inplace = attribute('full_disk_encryption_inplace')

  query = %(
    SELECT
          d.name AS [Database Name],
          CASE e.encryption_state
                WHEN 0 THEN 'No database encryption key present, no encryption'
                WHEN 1 THEN 'Unencrypted'
                WHEN 2 THEN 'Encryption in progress'
                WHEN 3 THEN 'Encrypted'
                WHEN 4 THEN 'Key change in progress'
                WHEN 5 THEN 'Decryption in progress'
                WHEN 6 THEN 'Protection change in progress'
          END AS [Encryption State]
    FROM sys.dm_database_encryption_keys e
    RIGHT JOIN sys.databases d ON DB_NAME(e.database_id) = d.name
    WHERE d.name IN ('#{encrypted_databases.join("', '")}')
  )

  sql_session = mssql_session(port: 49789) if sql_session.nil?

  unless data_at_rest_encryption_required
    impact 0.0
    desc 'If the application owner and Authorizing Official have
    determined that encryption of data at rest is NOT required, this is not a
    finding.'

    describe 'Encryption of data at rest' do
      subject { data_at_rest_encryption_required }
      it { should be false }
    end
  end

  if full_disk_encryption_inplace
    impact 0.0
    desc 'If full-disk encryption is being used, this is not a finding.'

    describe 'Encryption of data at rest' do
      subject { full_disk_encryption_inplace }
      it { should be true }
    end
  end

  if encrypted_databases.empty?
    impact 0.0
    desc 'If no databases are required to encrypted, this is not a finding.'

    describe 'Databases are required to encrypted' do
      subject { encrypted_databases }
      it { should be_empty }
    end
  end

  unless encrypted_databases.empty?
    describe 'Databases found from the query' do
      subject { sql_session.query(query) }
      it { should_not be_empty }
    end

    sql_session.query(query).rows.each do |row|
      describe "Database: #{row['database name']} encryption state" do
        subject { row['encryption state'] }
        it { should cmp 'Encrypted'}
      end
    end
  end
end