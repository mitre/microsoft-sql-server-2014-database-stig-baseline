control 'SV-213796' do
  title 'Trace or Audit records must be generated when categorized information (e.g., classification levels/security levels) is created.'
  desc 'Changes in categorized information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.

For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems.

Use of SQL Server Audit is recommended.  All features of SQL Server Audit are available in the Enterprise and Developer editions of SQL Server 2014.  It is not available at the database level in other editions.  For this or legacy reasons, the instance may be using SQL Server Trace for auditing, which remains an acceptable solution for the time being.  Note, however, that Microsoft intends to remove most aspects of Trace at some point after SQL Server 2016.

Since Trace does not provide for tracking SELECT statements, it is necessary to provide that part of the tracking at the application level.  Because of this, it may also be appropriate to audit INSERT actions at the application level.  However, to capture all INSERTs, whether they come from the application or bypass it, the Trace must be configured to cover them.'
  desc 'check', %q(Review the system documentation to determine whether it is required to track categories of information, such as classification or sensitivity level.  If it is not, this is not applicable (NA).

If neither SQL Server Audit nor SQL Server Trace is in use for audit purposes, this is a finding.

If SQL Server Trace is in use for audit purposes, review the Trace settings, and the triggers on the tables holding categorized information, to determine whether all INSERT actions on these tables are traced, including failed attempts.  If not, this is a finding.

Check to see that all required event classes are being audited.  From the query prompt:
SELECT * FROM sys.traces;

All currently defined traces for the SQL server instance will be listed. If no traces are returned, this is a finding.

Determine the trace(s) being used for the auditing requirement.
In the following, replace # with a trace ID being used for the auditing requirements.
From the query prompt:
SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#);

The following required event IDs should be among those listed; if not, this is a finding:

82-91  -- User-defined Event (at least one of these, matching the triggers; 90 is used in the supplied script)
162 -- User error message


If SQL Server Audit is in use, proceed as follows.

The basic SQL Server Audit configuration provided in the supplemental file Audit.sql uses the broad, server-level audit action group SCHEMA_OBJECT_ACCESS_GROUP for this purpose.  SQL Server Audit's flexibility makes other techniques possible.  If an alternative technique is in use and demonstrated effective, this is not a finding.

Determine the name(s) of the server audit specification(s) in use.

To look at audits and audit specifications, in Management Studio's object explorer, expand
<server name> >> Security >> Audits
and
<server name> >> Security >> Server Audit Specifications.
Also,
<server name> >> Databases >> <database name> >> Security >> Database Audit Specifications.

Alternatively, review the contents of the system views with "audit" in their names.

Run the following to verify that all SELECT, INSERT, UPDATE, and DELETE actions on tables and views are being audited:
USE [master];
GO
SELECT * FROM sys.server_audit_specification_details WHERE server_specification_id =
(SELECT server_specification_id FROM sys.server_audit_specifications WHERE [name] = '<server_audit_specification_name>')
AND audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP';

If no row is returned, this is a finding.

If the audited_result column is not "SUCCESS" or "SUCCESS AND FAILURE", this is a finding.)
  desc 'fix', 'Where SQL Server Trace is in use, create triggers to raise a custom event for INSERTs on each table holding categorized information.  The examples provided in the supplemental file CustomTraceEvents.sql can serve as the basis for these.

Add a block of code to the supplemental file Trace.sql for each custom event class (integers in the range 82-91; the same event class may be used for all such triggers) used in these triggers.  Execute Trace.sql.

If SQL Server Audit is in use, design and deploy an Audit that captures all auditable events and data items.  The script provided in the supplemental file Audit.sql can be used as the basis for this.  Supplement the standard audit data as necessary, using Extended Events and/or triggers.

Alternatively, to add the necessary data capture to an existing server audit specification, run the script:
USE [master];
GO
ALTER SERVER AUDIT SPECIFICATION <server_audit_specification_name> WITH (STATE = OFF);
GO
ALTER SERVER AUDIT SPECIFICATION <server_audit_specification_name> ADD (SCHEMA_OBJECT_ACCESS_GROUP);
GO
ALTER SERVER AUDIT SPECIFICATION <server_audit_specification_name> WITH (STATE = ON);
GO'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Database'
  tag check_id: 'C-15016r312466_chk'
  tag severity: 'medium'
  tag gid: 'V-213796'
  tag rid: 'SV-213796r961809_rule'
  tag stig_id: 'SQL4-00-036600'
  tag gtitle: 'SRG-APP-000498-DB-000346'
  tag fix_id: 'F-15014r312467_fix'
  tag 'documentable'
  tag legacy: ['SV-81927', 'V-67437']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  if input('server_trace_or_audit_required')
    impact 0.5
  else
    impact 0.0
    desc 'Inspec attributes has specified that is not required to track categories
    of information, such as classification or sensitivity level on the target'
  end

  query_traces = %(
    SELECT * FROM sys.traces
  )
  query_trace_eventinfo = %{
    SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(%<trace_id>s);
  }

  query_audits = %(
    SELECT server_specification_id,
           audit_action_name,
           audited_result
    FROM   sys.server_audit_specification_details
    WHERE  audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP';
  )

  server_trace_implemented = input('server_trace_implemented')
  server_audit_implemented = input('server_audit_implemented')

  sql_session = mssql_session(user: input('user'),
                              password: input('password'),
                              host: input('host'),
                              instance: input('instance'),
                              port: input('port'),
                              db_name: input('db_name'))

  describe.one do
    describe 'SQL Server Trace is in use for audit purposes' do
      subject { server_trace_implemented }
      it { should be true }
    end

    describe 'SQL Server Audit is in use for audit purposes' do
      subject { server_audit_implemented }
      it { should be true }
    end
  end

  if server_trace_implemented
    describe 'List defined traces for the SQL server instance' do
      subject { sql_session.query(query_traces) }
      it { should_not be_empty }
    end

    trace_ids = sql_session.query(query_traces).column('id')
    describe.one do
      trace_ids.each do |trace_id|
        found_events = sql_session.query(format(query_trace_eventinfo, trace_id: trace_id)).column('eventid')
        describe "EventsIDs in Trace ID:#{trace_id}" do
          subject { found_events }
          its('to_s') { should match(/"82"|"83"|"84"|"85"|"86"|"87"|"88"|"89"|"90"|"91"/) }
          it { should include '162' }
        end
      end
    end
  end

  if server_audit_implemented
    describe 'SQL Server Audit:' do
      describe 'Defined Audits with Audit Action SCHEMA_OBJECT_ACCESS_GROUP' do
        subject { sql_session.query(query_audits) }
        it { should_not be_empty }
      end
      describe 'Audited Result for Defined Audit Actions' do
        subject { sql_session.query(query_audits).column('audited_result').uniq.to_s }
        it { should match(/SUCCESS AND FAILURE|SUCCESS/) }
      end
    end
  end
end
