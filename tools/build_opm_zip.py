#!/usr/bin/env python3
"""Build FpRdap.zip - the OPM repository package used for the initial listing.

Reproduces, from the command line, what the Lazarus OPM "create repository
package" dialog emits: a zip under the FpRdap/ prefix containing the lpk,
its packaged sources, the demo and test projects, LICENSE/README/CHANGELOG,
and both manifests. FpRdap.json is generated from rdap_rt.lpk metadata
(description, author, license, version, dependencies), so a listing refresh
is: bump the lpk version, run update_opm_json.py, run this script, submit.

The IDE dialog has a one-pass-behind quirk: RepositoryFile{Size,Hash,Date}
in the manifest describe the final zip, while the manifest copy inside the
zip still carries the values of the previous pass. This script keeps the
same layout, so the committed FpRdap.json always matches FpRdap.zip exactly
and the zip stays byte-comparable with what the dialog would produce.

Usage:
  build_opm_zip.py            (re)build FpRdap.zip and FpRdap.json
  build_opm_zip.py --check    verify committed FpRdap.json describes FpRdap.zip
"""
import datetime
import hashlib
import json
import os
import stat
import sys
import time
import xml.etree.ElementTree as ET
import zipfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LPK = os.path.join(REPO, "rdap_rt.lpk")
ZIP_OUT = os.path.join(REPO, "FpRdap.zip")
JSON_OUT = os.path.join(REPO, "FpRdap.json")

PKG_NAME = "FpRdap"  # OPM display name, also the zip root prefix
SLUG = "al-muhandis/fp-rdap"
CATEGORY = "Networking"
LAZ_COMPAT = "2.0.0, 2.2.0, 2.2.4, 3.0.0, 3.4.0, 3.6.0, Trunk"
FPC_COMPAT = "3.2.0, 3.2.2, 3.2.4, 3.3"
WIDGETSETS = "cocoa, gtk2, gtk3, qt5, qt6, win32/win64"

# Source files packed into the zip (repo-relative). Binaries, compiler output
# and bootstrap snapshots are excluded, mirroring what the dialog is told to
# pack for fp-idn.
FILES = [
    "FpRdap.json",
    "update_FpRdap.json",
    "rdap_rt.lpk",
    "rdap_rt.pas",
    "src/rdapclient.pas",
    "LICENSE",
    "README.md",
    "README.ru.md",
    "CHANGELOG.md",
    "CHANGELOG.ru.md",
    "demo/rdap_demo.lpi",
    "demo/rdap_demo.lpr",
    "tests/test_rdapclient.pas",
    "tests/rdap_tests.lpi",
    "tests/rdap_tests.lpr",
    "tests/gui.lpi",
    "tests/gui.lpr",
    "tests/gui.ico",
]


def lpk_meta():
    """(description, author, license, version, dependencies) from rdap_rt.lpk."""
    root = ET.parse(LPK).getroot()
    pkg = root.find("./Package")
    if pkg is None:
        sys.exit("no Package element in " + LPK)
    v = pkg.find("Version")

    def attr(name):
        return int(v.get(name, "0")) if v is not None else 0

    def value(tag):
        el = pkg.find(tag)
        return el.get("Value") if el is not None else None

    version = "%d.%d.%d.%d" % (attr("Major"), attr("Minor"), attr("Release"), attr("Build"))
    deps = [i.find("PackageName").get("Value") for i in pkg.findall("./RequiredPkgs/Item")]
    return (
        value("Description") or "",
        value("Author") or "",
        value("License") or "",
        version,
        ",".join(d for d in deps if d),
    )


def jstr(s):
    return json.dumps(s)


def manifest_text(description, author, license_name, version, deps, size, md5, date):
    """FpRdap.json in the fpjson layout the OPM dialog emits (CRLF)."""
    L = [
        "{",
        '  "PackageData0" : {',
        '    "Name" : %s,' % jstr(PKG_NAME),
        '    "DisplayName" : %s,' % jstr(PKG_NAME),
        '    "Category" : %s,' % jstr(CATEGORY),
        '    "CommunityDescription" : %s,' % jstr(description),
        '    "ExternalDependecies" : "",',
        '    "OrphanedPackage" : 0,',
        '    "RepositoryFileName" : %s,' % jstr(PKG_NAME + ".zip"),
        '    "RepositoryFileSize" : %d,' % size,
        '    "RepositoryFileHash" : %s,' % jstr(md5),
        '    "RepositoryDate" : %s,' % repr(date),
        '    "PackageBaseDir" : %s,' % jstr(PKG_NAME + "\\/"),
        '    "HomePageURL" : %s,' % jstr("https://github.com/%s/" % SLUG),
        '    "DownloadURL" : %s,' % jstr(
            "https://raw.githubusercontent.com/%s/main/update_FpRdap.json" % SLUG),
        '    "SVNURL" : ""',
        "  },",
        '  "PackageFiles0" : [',
        "    {",
        '      "Name" : %s,' % jstr("rdap_rt.lpk"),
        '      "Description" : %s,' % jstr(description),
        '      "Author" : %s,' % jstr(author),
        '      "License" : %s,' % jstr(license_name),
        '      "RelativeFilePath" : "",',
        '      "VersionAsString" : %s,' % jstr(version),
        '      "LazCompatibility" : %s,' % jstr(LAZ_COMPAT),
        '      "FPCCompatibility" : %s,' % jstr(FPC_COMPAT),
        '      "SupportedWidgetSet" : %s,' % jstr(WIDGETSETS),
        '      "PackageType" : 3,',
        '      "DependenciesAsString" : %s' % jstr(deps),
        "    }",
        "  ]",
        "}",
    ]
    return ("\r\n".join(L) + "\r\n").encode("ascii")


def tdatetime(tm):
    """Delphi/Lazarus TDateTime (days since 1899-12-30, local time) as float."""
    d = datetime.datetime(*tm[:6])
    epoch = datetime.datetime(1899, 12, 30)
    return (d - epoch).total_seconds() / 86400.0


def build_zip(manifest_bytes, when):
    """Pack FILES under the FpRdap/ prefix; JSONs carry the build time."""
    entries = []
    for rel in FILES:
        data = manifest_bytes if rel == "FpRdap.json" else None
        if data is None:
            path = os.path.join(REPO, rel.replace("/", os.sep))
            if not os.path.isfile(path):
                sys.exit("missing %s - generate it first (update_opm_json.py "
                         "for update_FpRdap.json)" % rel)
            data = open(path, "rb").read()
            st = os.stat(path)
            mtime = time.localtime(st.st_mtime)
        else:
            mtime = when
        zi = zipfile.ZipInfo(PKG_NAME + "/" + rel, date_time=mtime[:6])
        zi.compress_type = zipfile.ZIP_DEFLATED
        zi.external_attr = (stat.S_IFREG | 0o644) << 16
        entries.append((zi, data))
    with zipfile.ZipFile(ZIP_OUT, "w", zipfile.ZIP_DEFLATED) as z:
        for zi, data in entries:
            z.writestr(zi, data)
    return open(ZIP_OUT, "rb").read()


def zip_stat(raw):
    return len(raw), hashlib.md5(raw).hexdigest(), tdatetime(time.localtime())


def committed_fields():
    if not os.path.isfile(JSON_OUT):
        return 0, "0" * 32, 0.0
    data = json.loads(open(JSON_OUT, "rb").read().decode("ascii"))
    pd = data["PackageData0"]
    return int(pd["RepositoryFileSize"]), str(pd["RepositoryFileHash"]), float(pd["RepositoryDate"])


def write_manifest(description, author, license_name, version, deps, size, md5, date):
    text = manifest_text(description, author, license_name, version, deps, size, md5, date)
    json.loads(text.decode("ascii"))  # sanity: still valid JSON
    with open(JSON_OUT, "wb") as f:
        f.write(text)
    return text


def build():
    description, author, license_name, version, deps = lpk_meta()
    when = time.localtime()
    # Pass 1: zip carrying the currently committed (or placeholder) manifest
    # values, then pass 2: zip carrying those values; the committed manifest
    # describes pass 2, the copy inside the zip stays one pass behind.
    s1, h1, _ = zip_stat(build_zip(
        manifest_text(description, author, license_name, version, deps,
                      *committed_fields()), when))
    raw = build_zip(
        write_manifest(description, author, license_name, version, deps, s1, h1, tdatetime(when)),
        when)
    s2, h2, d2 = zip_stat(raw)
    write_manifest(description, author, license_name, version, deps, s2, h2, d2)
    print("built %s (%d bytes, md5 %s) for version %s" % (ZIP_OUT, s2, h2, version))


def check():
    if not os.path.isfile(ZIP_OUT):
        sys.exit("no %s - run build_opm_zip.py first" % ZIP_OUT)
    size, md5, _ = zip_stat(open(ZIP_OUT, "rb").read())
    csize, cmd5, _ = committed_fields()
    if (size, md5) == (csize, cmd5):
        print("OK: FpRdap.json matches FpRdap.zip (%d bytes, md5 %s)" % (size, md5))
    else:
        sys.exit("stale: FpRdap.json says %d/%s, FpRdap.zip is %d/%s - rerun build_opm_zip.py"
                 % (csize, cmd5, size, md5))


def main():
    if "--check" in sys.argv[1:]:
        check()
    else:
        build()


if __name__ == "__main__":
    main()
