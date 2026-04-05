import sys
import re
import os
import uuid

WXS_OUT = "monitoring-agent.wxs"
NSI_IN = "wazuh-installer.nsi"

def main():
    lines = open(NSI_IN).read().splitlines()
    files = []
    
    re_oname = re.compile(r'^\s*File\s+/oname=([^\s]+)\s+(.+)$', re.IGNORECASE)
    re_file = re.compile(r'^\s*File\s+([^\s]+)$', re.IGNORECASE)
    
    for line in lines:
        line = line.split(';')[0].strip()
        m = re_oname.match(line)
        if m:
            files.append((m.group(1).strip('"\''), m.group(2).strip('"\'')))
            continue
        m = re_file.match(line)
        if m:
            src = m.group(1).strip('"\'')
            files.append((os.path.basename(src), src))
            
    filtered = []
    for d, s in files:
        if 'suricata' in d.lower() or 'suricata' in s.lower():
            continue
        filtered.append((d.replace('\\', '/'), s.replace('\\', '/')))
        
    directories_needed = set()
    for line in lines:
        line = line.split(';')[0].strip()
        if line.lower().startswith('createdirectory'):
            d = line.split(maxsplit=1)[1].strip('"\'').replace('$INSTDIR\\', '').replace('\\', '/')
            if 'suricata' in d.lower() or '$' in d: # skip $SMPROGRAMS
                continue
            directories_needed.add(d)

    dir_tree = {}
    for d, s in filtered:
        dirname = os.path.dirname(d)
        if dirname == "": dirname = "."
        if dirname not in dir_tree: dir_tree[dirname] = []
        dir_tree[dirname].append((os.path.basename(d), s))
        parts = dirname.split('/')
        if dirname != ".":
            cur = ""
            for p in parts:
                if not p: continue
                cur = cur + ("/" if cur else "") + p
                directories_needed.add(cur)
            
    for d in directories_needed:
        if d not in dir_tree: dir_tree[d] = []

    class Node:
        def __init__(self, name, full_path, dir_id):
            self.name = name
            self.full_path = full_path
            self.dir_id = dir_id
            self.children = {}
            self.files = []
    
    root = Node("monitoring-agent", ".", "INSTALLFOLDER")
    
    def get_or_create_node(path):
        if path == ".": return root
        parts = path.split('/')
        current = root
        current_path = ""
        for p in parts:
            if not p: continue
            current_path = current_path + ("/" if current_path else "") + p
            if p not in current.children:
                safe_id = "DIR_" + current_path.replace('/', '_').replace('-', '_')
                current.children[p] = Node(p, current_path, safe_id)
            current = current.children[p]
        return current
        
    for d, files_in_dir in dir_tree.items():
        node = get_or_create_node(d)
        node.files.extend(files_in_dir)
        
    for d in directories_needed:
        get_or_create_node(d)
        
    wxs = []
    wxs.append('<?xml version="1.0" encoding="UTF-8"?>')
    wxs.append('<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">')
    wxs.append('    <Product Id="*" Name="Monitoring Agent" Language="1033" Version="4.13.1.0" Manufacturer="Monitoring Solutions Inc." UpgradeCode="6B641C89-5360-4927-A85B-7EFAD322E7F3">')
    wxs.append('        <Package InstallerVersion="200" Compressed="yes" InstallScope="perMachine" />')
    wxs.append('        <MajorUpgrade DowngradeErrorMessage="A newer version of [ProductName] is already installed." />')
    wxs.append('        <MediaTemplate EmbedCab="yes" />')
    
    wxs.append('        <!-- Allows the user to easily find and uninstall the product from settings -->')
    wxs.append('        <Property Id="ARPHELPLINK" Value="https://monitoring-solutions.com" />')
    wxs.append('        <Property Id="ARPURLINFOABOUT" Value="https://monitoring-solutions.com" />')
    
    wxs.append('        <Feature Id="ProductFeature" Title="MonitoringAgent" Level="1">')
    wxs.append('            <ComponentGroupRef Id="ProductComponents" />')
    wxs.append('        </Feature>')
    
    wxs.append('        <Directory Id="TARGETDIR" Name="SourceDir">')
    wxs.append('            <Directory Id="ProgramFilesFolder">')

    comp_id = 1
    
    def write_node(node, indent_level):
        nonlocal comp_id
        indent = '    ' * indent_level
        wxs.append(f'{indent}<Directory Id="{node.dir_id}" Name="{node.name}">')
        
        if node.files:
            for fname, src in node.files:
                safe_fname = fname.replace('+', '_').replace('-', '_')
                file_id = f"file_{comp_id}_{safe_fname}"
                guid = str(uuid.uuid4()).upper()
                wxs.append(f'{indent}    <Component Id="cmp{comp_id}" Guid="{guid}">')
                wxs.append(f'{indent}        <File Id="{file_id}" Name="{fname}" Source="{src}" KeyPath="yes" />')
                # wixl needs explicit service registration instead of CA
                if fname == "monitoring-agent.exe":
                    wxs.append(f'{indent}        <ServiceInstall Id="ServiceInstall1" Name="MonitoringSvc" DisplayName="Monitoring Agent" Type="ownProcess" Start="auto" ErrorControl="normal" />')
                    wxs.append(f'{indent}        <ServiceControl Id="ServiceControl1" Name="MonitoringSvc" Start="install" Stop="both" Remove="uninstall" Wait="yes" />')
                wxs.append(f'{indent}    </Component>')
                comp_id += 1
        else:
            guid = str(uuid.uuid4()).upper()
            wxs.append(f'{indent}    <Component Id="cmpEmpty{node.dir_id}" Guid="{guid}">')
            wxs.append(f'{indent}        <CreateFolder />')
            wxs.append(f'{indent}    </Component>')
            
        if node.dir_id == "INSTALLFOLDER":
            guid = str(uuid.uuid4()).upper()
            wxs.append(f'{indent}    <Component Id="RegistryEntries" Guid="{guid}">')
            wxs.append(f'{indent}        <RegistryValue Root="HKLM" Key="SOFTWARE\\MonitoringAgent" Name="Install_Dir" Type="string" Value="[INSTALLFOLDER]" KeyPath="yes" />')
            wxs.append(f'{indent}        <!-- Create uninstall.exe shortcut in the installation folder itself -->')
            wxs.append(f'{indent}        <Shortcut Id="FolderUninstallProduct" Name="uninstall.exe" Description="Uninstalls The Monitoring Agent" Target="[SystemFolder]msiexec.exe" Arguments="/x [ProductCode]"/>')
            wxs.append(f'{indent}    </Component>')
        
        for child_name in sorted(node.children.keys()):
            write_node(node.children[child_name], indent_level + 1)
            
        wxs.append(f'{indent}</Directory>')

    write_node(root, 4)
    wxs.append('            </Directory>')
    
    # ProgramMenuFolder
    wxs.append('            <Directory Id="ProgramMenuFolder">')
    wxs.append('                <Directory Id="ApplicationProgramsFolder" Name="Monitoring Agent">')
    guid = str(uuid.uuid4()).upper()
    wxs.append(f'                    <Component Id="ApplicationShortcut" Guid="{guid}">')
    wxs.append('                        <Shortcut Id="ShortcutWin32UI" Name="Manage Agent" Description="Manage Monitoring Agent" Target="[INSTALLFOLDER]win32ui.exe" WorkingDirectory="INSTALLFOLDER"/>')
    wxs.append('                        <Shortcut Id="ShortcutClamAV" Name="ClamAV Manager" Description="ClamAV Manager" Target="[INSTALLFOLDER]clamav_ui.exe" WorkingDirectory="INSTALLFOLDER"/>')
    wxs.append('                        <!-- Uninstaller Shortcut in Start Menu -->')
    wxs.append('                        <Shortcut Id="UninstallProduct" Name="Uninstall Monitoring Agent" Description="Uninstalls The Monitoring Agent" Target="[SystemFolder]msiexec.exe" Arguments="/x [ProductCode]"/>')
    wxs.append('                        <RemoveFolder Id="ApplicationProgramsFolder" On="uninstall"/>')
    wxs.append('                        <RegistryValue Root="HKCU" Key="Software\\MonitoringAgent" Name="installed" Type="integer" Value="1" KeyPath="yes"/>')
    wxs.append('                    </Component>')
    wxs.append('                </Directory>')
    wxs.append('            </Directory>')
    wxs.append('        </Directory>')
    
    wxs.append('        <ComponentGroup Id="ProductComponents">')
    # Use a copy of wxs so we don't iterate over inserted items
    for l in list(wxs):
        m = re.search(r'<Component Id="([^"]+)"', l)
        if m:
            wxs.append(f'            <ComponentRef Id="{m.group(1)}" />')
    wxs.append('        </ComponentGroup>')
    
    wxs.append('    </Product>')
    wxs.append('</Wix>')
    
    with open(WXS_OUT, 'w') as f:
        f.write('\n'.join(wxs))
        
    print("Successfully generated WXS!")

if __name__ == "__main__":
    main()
