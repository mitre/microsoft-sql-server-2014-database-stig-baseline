control 'SV-213768' do
  title 'SQL Server must be monitored to discover unauthorized changes to triggers.'
  desc 'When dealing with change control issues, it should be noted, any changes to the hardware, software, and/or firmware components of SQL Server and/or application can potentially have significant effects on the overall security of the system.

If SQL Server were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement is contingent upon the language in which the application is programmed, as many application architectures in use today incorporate their software libraries into, and make them inseparable from, their compiled distributions, rendering them static and version-dependent. However, this requirement does apply to applications with software libraries accessible and configurable, as in the case of interpreted languages.

Accordingly, only qualified and authorized individuals shall be allowed to obtain access to SQL Server components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the SQL Server software libraries or configuration, such as Triggers, can lead to unauthorized or compromised installations.'
  desc 'check', "Check the SQL Server configuration for the timed job that automatically checks all system and user-defined Triggers for being modified by running the following SQL Server query:
EXEC msdb.dbo.sp_help_job @job_name = '<enter . . . job name>';

(Alternatively, in SQL Server Management Studio, navigate to SQL Server Agent and examine the job from there.)

If such a job, or an alternative method of monitoring triggers for modification, does not exist, this is a finding"
  desc 'fix', 'Configure a SQL Server timed job that automatically checks all system and user-defined Triggers for modification.

(The supplemental file Track.sql, provided with this STIG, can be used to establish a monitoring job.  This should be supplemented with a process for informing the appropriate personnel.  Other techniques for achieving the same ends, such as the use of DDL triggers, are acceptable.)'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Database'
  tag check_id: 'C-14988r312382_chk'
  tag severity: 'medium'
  tag gid: 'V-213768'
  tag rid: 'SV-213768r960960_rule'
  tag stig_id: 'SQL4-00-015100'
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag fix_id: 'F-14986r312383_fix'
  tag 'documentable'
  tag legacy: ['SV-81857', 'V-67367']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  query = %(
    SELECT enabled
    FROM   msdb.dbo.sysjobs
    WHERE  [name] = '%<job_name>s'
  )

  job_name = attribute('track_triggers_changes_job_name')

  sql_session = mssql_session(user: attribute('user'),
                              password: attribute('password'),
                              host: attribute('host'),
                              instance: attribute('instance'),
                              port: attribute('port'),
                              db_name: attribute('db_name'))

  describe "Scheduled job: #{job_name} enabled status" do
    subject { sql_session.query(format(query, job_name: job_name)).column('enabled') }
    it { should cmp 1 }
  end
end
