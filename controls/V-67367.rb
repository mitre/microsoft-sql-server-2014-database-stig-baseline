control "V-67367" do
  title "SQL Server must be monitored to discover unauthorized changes to
triggers."
  desc  "When dealing with change control issues, it should be noted, any
changes to the hardware, software, and/or firmware components of SQL Server
and/or application can potentially have significant effects on the overall
security of the system.

    If SQL Server were to allow any user to make changes to software libraries,
then those changes might be implemented without undergoing the appropriate
testing and approvals that are part of a robust change management process.

    This requirement is contingent upon the language in which the application
is programmed, as many application architectures in use today incorporate their
software libraries into, and make them inseparable from, their compiled
distributions, rendering them static and version-dependent. However, this
requirement does apply to applications with software libraries accessible and
configurable, as in the case of interpreted languages.

    Accordingly, only qualified and authorized individuals shall be allowed to
obtain access to SQL Server components for purposes of initiating changes,
including upgrades and modifications.

    Unmanaged changes that occur to the SQL Server software libraries or
configuration, such as Triggers, can lead to unauthorized or compromised
installations.
  "
  impact 0.7
  tag "gtitle": "SRG-APP-000133-DB-000179"
  tag "gid": "V-67367"
  tag "rid": "SV-81857r2_rule"
  tag "stig_id": "SQL4-00-015100"
  tag "fix_id": "F-73479r2_fix"
  tag "cci": ["CCI-001499"]
  tag "nist": ["CM-5 (6)", "Rev_4"]
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
  tag "check": "Check the SQL Server configuration for the timed job that
automatically checks all system and user-defined Triggers for being modified by
running the following SQL Server query:
EXEC msdb.dbo.sp_help_job @job_name = '<enter . . . job name>';

(Alternatively, in SQL Server Management Studio, navigate to SQL Server Agent
and examine the job from there.)

If such a job, or an alternative method of monitoring triggers for
modification, does not exist, this is a finding"
  tag "fix": "Configure a SQL Server timed job that automatically checks all
system and user-defined Triggers for modification.

(The supplemental file Track.sql, provided with this STIG, can be used to
establish a monitoring job.  This should be supplemented with a process for
informing the appropriate personnel.  Other techniques for achieving the same
ends, such as the use of DDL triggers, are acceptable.)"

  query = %(
    SELECT enabled
    FROM   msdb.dbo.sysjobs
    WHERE  [name] = '%<job_name>s'
  )

  job_name = 'STIG_database_object_tracking'

  sql_session = mssql_session(port: 497_89) if sql_session.nil?

  describe "Scheduled job: #{job_name} enabled status" do
    subject { sql_session.query(format(query, job_name: job_name)).column('enabled') }
    it { should cmp 1 }
  end
end
