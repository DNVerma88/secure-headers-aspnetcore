"""
fix_snupkg.py  –  strips net10.0 artefacts from a .snupkg before re-upload.

Usage:
    python3 fix_snupkg.py <path-to-snupkg>

Changes made to the snupkg (zip archive):
  1. Removes  lib/net10.0/SecureHeaders.AspNetCore.pdb
  2. Strips   <group targetFramework="net10.0"> elements from <dependencies>
              and <frameworkReferences> inside the embedded .nuspec

This is needed because the published 1.1.0 .nupkg only contains
lib/net8.0/SecureHeaders.AspNetCore.dll. NuGet.org validates every
<frameworkReferences> group in the snupkg's nuspec against the DLLs in
the nupkg, so any net10.0 reference causes the symbols package to be
rejected with "pdb(s) for dll(s) not found in the nuget package".
"""

import sys
import os
import zipfile
import xml.etree.ElementTree as ET

PDB_ENTRY = "lib/net10.0/SecureHeaders.AspNetCore.pdb"
NUSPEC    = "SecureHeaders.AspNetCore.nuspec"
NET10     = "net10.0"
NS        = "http://schemas.microsoft.com/packaging/2012/06/nuspec.xsd"


def strip_net10_from_nuspec(xml_bytes: bytes) -> bytes:
    ET.register_namespace("", NS)
    root = ET.fromstring(xml_bytes.decode("utf-8-sig"))
    metadata = root.find(f"{{{NS}}}metadata")
    for tag in ("dependencies", "frameworkReferences"):
        container = metadata.find(f"{{{NS}}}{tag}")
        if container is None:
            continue
        for group in list(container.findall(f"{{{NS}}}group")):
            if group.get("targetFramework", "").lower() == NET10:
                print(f"  nuspec: removing <{tag}><group targetFramework='{group.get('targetFramework')}'>")
                container.remove(group)
    xml_str = ET.tostring(root, encoding="unicode")
    return ('<?xml version="1.0" encoding="utf-8"?>\n' + xml_str).encode("utf-8")


def fix(src: str) -> None:
    tmp = src + ".tmp"
    with zipfile.ZipFile(src, "r") as zin, \
         zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            if item.filename == PDB_ENTRY:
                print(f"Removing PDB:  {item.filename}")
                continue
            data = zin.read(item.filename)
            if item.filename == NUSPEC:
                print(f"Patching:      {item.filename}")
                data = strip_net10_from_nuspec(data)
            zout.writestr(item, data)
    os.replace(tmp, src)

    print("\nVerifying remaining entries:")
    with zipfile.ZipFile(src, "r") as z:
        for e in z.infolist():
            print(f"  {e.filename}  ({e.file_size} bytes)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(f"Usage: {sys.argv[0]} <path-to-snupkg>")
    fix(sys.argv[1])
