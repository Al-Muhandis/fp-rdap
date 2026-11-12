program rdap_demo;

{$mode objfpc}{$H+}

uses
  SysUtils, Classes, rdapclient;

procedure PrintResult(C: TRDAPClient; const aQuery, aCaption: string);
begin
  Writeln('Queried ', Format(aCaption, [aQuery]));
  Writeln('  URL:    ', C.LastURL);
  if C.LastStatus = rqsNotFound then
    WriteLn('  Object not found')
  else if C.LastStatus = rqsOK then
  begin
    Writeln('  Title: ', C.GetObjectTitle);
    Writeln('  Type:  ', C.GetObjectType);
    Writeln('  Size:  ', Length(C.LastRawJSON));
  end;
  WriteLn('  Status: ', C.LastStatus);
  if C.LastErrorCode <> 0 then
    WriteLn('  Error ', C.LastErrorCode, ': ', C.LastErrorTitle);
  if Length(C.LastRawJSON) > 0 then
    Writeln('  Preview: ', Copy(C.LastRawJSON, 1, 200));
  Writeln;

  if C.LastRawJSON <> '' then
    with TStringList.Create do
    try
      Text := C.LastRawJSON;
      SaveToFile(Format('rdap_example_%s.json', [aQuery]));
    finally
      Free;
    end;
end;

procedure RunQuery(C: TRDAPClient; const aQuery, aCaption: string; aIsIP: Boolean);
begin
  try
    if aIsIP then
      C.QueryIP(aQuery)
    else
      C.QueryDomain(aQuery);
  except
    on E: ERDAPError do
      Writeln('  Query failed: ', E.Message);
  end;
  PrintResult(C, aQuery, aCaption);
end;

procedure RunDemos;
var
  C: TRDAPClient;
  B: TRDAPBootstrap;
  BootstrapOK: Boolean;
begin
  Writeln('RDAP DEMO');

  B := TRDAPBootstrap.Create;
  BootstrapOK := False;
  try
    try
      B.LoadFromLocalFiles('dns.json', 'ipv4.json', 'ipv6.json');
      BootstrapOK := True;
      Writeln('Bootstrap loaded from local files');
    except
      on E: ERDAPError do
      begin
        Writeln('Local bootstrap files unavailable: ', E.Message);
        Writeln('Get dns.json / ipv4.json / ipv6.json from https://data.iana.org/rdap/');
        Writeln('Falling back to https://rdap.org/');
      end;
    end;

    C := TRDAPClient.Create;
    try
      if BootstrapOK then
        C.Bootstrap := B
      else
        C.BaseURL := 'https://rdap.org/';

      RunQuery(C, 'example.com', '1. %s (domain)', False);
      RunQuery(C, 'wikipedia.org', '2. %s (domain)', False);
      RunQuery(C, '8.8.8.8', '3. %s (IP)', True);
      RunQuery(C, 'nonexistent123456.com', '4. %s (domain)', False);

      Writeln('Saved to rdap_example_XXX.json');
    finally
      C.Free;
    end;
  finally
    B.Free;
  end;
end;

begin
  try
    RunDemos;
  except
    on E: Exception do
      Writeln('ERROR: ', E.Message);
  end;
  Writeln('COMPLETE!');
  ReadLn;
end.
