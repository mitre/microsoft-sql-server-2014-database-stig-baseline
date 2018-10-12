control "V-67425" do
  title "SQL Server must generate Trace or Audit records when successful
accesses to designated objects occur."
  desc  "Without tracking all or selected types of access to all or selected
objects (tables, views, procedures, functions, etc.), it would be difficult to
establish, correlate, and investigate the events relating to an incident, or
identify those responsible for one.

    Types of access include, but are not necessarily limited to:
    SELECT
    INSERT
    UPDATE
    DELETE
    EXECUTE

    Use of SQL Server Audit is recommended.  All features of SQL Server Audit
are available in the Enterprise and Developer editions of SQL Server 2014.  It
is not available at the database level in other editions.  For this or legacy
reasons, the instance may be using SQL Server Trace for auditing, which remains
an acceptable solution for the time being.  Note, however, that Microsoft
intends to remove most aspects of Trace at some point after SQL Server 2016.

    Trace does not offer tracking of SELECT operations, so where this is
required it must be implemented at the application level.
  "
  impact 0.7
  tag "gtitle": "SRG-APP-000507-DB-000356"
  tag "gid": "V-67425"
  tag "rid": "SV-81915r3_rule"
  tag "stig_id": "SQL4-00-038100"
  tag "fix_id": "F-73539r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
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
  tag "check": "If neither SQL Server Audit nor SQL Server Trace is in use for
audit purposes, this is a finding.

Obtain the list of objects (tables and stored procedures) where tracking of
SELECT, INSERT, UPDATE, DELETE, or EXECUTE actions is required.  If there are
none, this is not a finding.

If SQL Server Trace is in use for audit purposes, review the application(s)
using the database to verify that all SELECT actions on categorized data are
being audited, and that the tracking records are written to the SQL Server
Trace used for audit purposes.  If not, this is a finding.

Review the designated tables for the existence of triggers to raise a custom
event on each Insert-Update-Delete operation.

If such triggers are not present, this is a finding.

Check to see that all required event classes are being audited.  From the query
prompt:
SELECT * FROM sys.traces;

All currently defined traces for the SQL server instance will be listed. If no
traces are returned, this is a finding.

Determine the trace(s) being used for the auditing requirement.
In the following, replace # with a trace ID being used for the auditing
requirements.
From the query prompt:
SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#);

The following required event IDs should be among those listed; if not, this is
a finding:

42  -- SP:Starting
43  -- SP:Completed
82-91  -- User-defined Event (at least one of these; 90 is used in the supplied
script)
162 -- User error message

If SQL Server Audit is in use, verify that execution of all SELECT, INSERT,
UPDATE, DELETE, or EXECUTE actions on the designated objects, is audited,.

If any such actions are not audited, this is a finding.

If SQL Server Audit is in use, proceed as follows.

The basic SQL Server Audit configuration provided in the supplemental file
Audit.sql uses the server-level audit action group SCHEMA_OBJECT_ACCESS_GROUP
for this purpose.  SQL Server Audit's flexibility makes other techniques
possible.  If an alternative technique is in use and demonstrated effective,
this is not a finding.

Determine the name(s) of the server audit specification(s) in use.

To look at audits and audit specifications, in Management Studio's object
explorer, expand
<server name> >> Security >> Audits
and
<server name> >> Security >> Server Audit Specifications.
Also,
<server name> >> Databases >> <database name> >> Security >> Database Audit
Specifications.

Alternatively, review the contents of the system views with \"audit\" in their
names.

Run the following to verify that all logons and connections are being audited:
USE [master];
GO
SELECT * FROM sys.server_audit_specification_details WHERE
server_specification_id =
(SELECT server_specification_id FROM sys.server_audit_specifications WHERE
[name] = '<server_audit_specification_name>')
AND audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP';
GO

If no row is returned, this is a finding.

If the audited_result column is not \"SUCCESS\" or \"SUCCESS AND FAILURE\",
this is a finding."
  tag "fix": "Where SQL Server Trace is in use, implement tracking of SELECTs
on designated tables at the application level, using the system stored
procedure sp_trace_generateevent to write the tracking records to the Trace
used for audit purposes.

Create triggers to raise a custom event on each table that requires tracking of
Insert-Update-Delete operations.  The examples provided in the supplemental
file CustomTraceEvents.sql can serve as the basis for these.

Add a block of code to the supplemental file Trace.sql for each custom event
class (integers in the range 82-91; the same event class may be used for all
such triggers) used in these triggers.

Ensure that Trace.sql includes blocks of code for event classes 42, 43, and 162.

Execute Trace.sql.

If SQL Server Audit is in use, design and deploy an Audit that captures all
auditable events and data items.  The script provided in the supplemental file
Audit.sql can be used as the basis for this.  Supplement the standard audit
data as necessary, using Extended Events and/or triggers.

Alternatively, to add the necessary data capture to an existing server audit
specification, run the script:
USE [master];
GO
ALTER SERVER AUDIT SPECIFICATION <server_audit_specification_name> WITH (STATE
= OFF);
GO
ALTER SERVER AUDIT SPECIFICATION <server_audit_specification_name> ADD
(SCHEMA_OBJECT_ACCESS_GROUP);
GO
ALTER SERVER AUDIT SPECIFICATION <server_audit_specification_name> WITH (STATE
= ON);
GO"

  query_traces = %(
    SELECT * FROM sys.traces
  )
  query_trace_eventinfo = %(
    SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(%<trace_id>s);
  )

  server_audit_specification_name = attribute('server_audit_specification_name')

  query_audits = %(
    SELECT audit_action_name,
           audited_result
    FROM   sys.server_audit_specification_details
    WHERE  server_specification_id =
           (SELECT server_specification_id
            FROM   sys.server_audit_specifications
            WHERE  [name] = '#{server_audit_specification_name}')
           AND audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP';
  )

  server_trace = attribute('server_trace')
  server_audit = attribute('server_audit')

  sql_session = mssql_session(port: 49789) if sql_session.nil?

  describe.one do
    describe 'SQL Server Trace is in use for audit purposes' do
      subject { server_trace }
      it { should be true }
    end

    describe 'SQL Server Audit is in use for audit purposes' do
      subject { server_audit }
      it { should be true }
    end
  end

  if server_trace
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
          it { should include '42' }
          it { should include '43' }
          it { should include '90' }
          it { should include '162' }
        end
      end
    end
  end

  if server_audit
    describe 'SQL Server Audit:' do
      describe 'Defined Audits with Audit Action SCHEMA_OBJECT_ACCESS_GROUP' do
        subject { sql_session.query(query_audits) }
        it { should_not be_empty }
      end
      describe 'Audited Result for Defined Audit Actions' do
        subject { sql_session.query(query_audits).column('audited_result').uniq.to_s }
        it { should match /SUCCESS AND FAILURE|SUCCESS/ }
      end
    end
  end
end