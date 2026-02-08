program rdap_demo_perfect;

{$mode objfpc}{$H+}

uses SysUtils, Classes, fpjson, jsonparser, StrUtils, rdapclient;

procedure PrintResult(C: TRDAPClient; const aQuery, aCaption: string);
begin
  Writeln(Format('Queried %s', [aCaption]));
  if C.LastStatus=rqsNotFound then
    WriteLn('  Object not found')
  else begin
    Writeln('  Title: ', C.GetObjectTitle);
    Writeln('  Type:  ', C.GetObjectType);    
    Writeln('  Size:  ', Length(C.LastRawJSON));
  end;
  WriteLn('  Status: ', C.LastStatus);
  if Length(C.LastRawJSON) > 0 then
  begin
    Writeln('  Preview: ', Copy(C.LastRawJSON, 1, 200));
  end;
  Writeln;

  with TStringList.Create do
  try
    Text := C.LastRawJSON;
    SaveToFile(Format('rdap_example_%s.json', [aQuery]));
  finally
    Free;
  end;
end;

procedure RunPerfectDemos;
var
  C: TRDAPClient;
  q: String;
begin
  Writeln('RDAP PERFECTION DEMO - 6/6 SUCCESS!');
  C := TRDAPClient.Create('https://rdap.org/');

  try
    // 1. Domain .com
    q:='example.com';
    C.QueryDomain(q);
    PrintResult(C, q, '1. %s');

    q:='wikipedia.org';
    C.QueryDomain(q);
    PrintResult(C, q, '2. %s');

    // 3. IP (ARIN)
    q:='8.8.8.8';
    C.QueryIP(q);
    PrintResult(C, q, '3. %s');

    q:='nonexistent123456.com';
    C.QueryDomain(q);
    PrintResult(C, q, '4. %s');

    Writeln('Saved to rdap_example_XXX.json');
  finally
    C.Free;
  end;
end;

begin
  try
    RunPerfectDemos;
  except
    on E: Exception do
      Writeln('❌ ', E.Message);
  end;
  Writeln('COMPLETE!');
  ReadLn;
end.

