#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Run custody/provisioning in an owned UID0 root; real clients stay outside.

Only copied owned binaries/public shared libraries enter the root. No host
mounts or device substitutes. Native UID/RPK channels cross the chroot using
normal Unix sockets. The TUI retains its real host PTY in the human domain.
Run inside the documented subordinate-UID user/mount namespace and Cargo lock.
"""
import importlib
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile


def main():
    assert os.getuid()==0
    assert pathlib.Path('/proc/self/uid_map').read_text().split()[1] != '0'
    mode=sys.argv[1];assert mode in ('registry','adapter','admission','reconciliation')
    binaries=[pathlib.Path(p).resolve(strict=True) for p in sys.argv[2:]]
    root=pathlib.Path(tempfile.mkdtemp(prefix='chef-runtime-owned-root-'))
    def copy_file(source,target):
        dest=root/str(target).lstrip('/');dest.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(pathlib.Path(source).resolve(strict=True),dest)
        shutil.copymode(source,dest);return dest
    def executable(source,target):
        dest=copy_file(source,target)
        for path in re.findall(r'(/[^\s()]+)',subprocess.check_output(['ldd',str(source)],text=True)):
            if pathlib.Path(path).is_file():copy_file(path,path)
        return dest
    try:
        root.chmod(0o755);(root/'tmp').mkdir();(root/'tmp').chmod(0o1777)
        (root/'chef-owned-root.marker').write_text('synthetic private root filesystem\n')
        copied=[executable(binary,'/bin/'+binary.name) for binary in binaries]
        executable(binaries[0].parent/'examples/chef_runtime_open_channel','/bin/examples/chef_runtime_open_channel')
        import linux_lab
        original_run,original_start=linux_lab.as_uid,linux_lab.start_as
        def scoped(uid,command,*,check=True,input=None,stdin=None,start=False):
            command=list(command)
            installed=(len(command)>1 and pathlib.Path(command[0]).name=='pm-custody' and
                command[1] in ('serve-vault','migrate-agent-registry','provision-adapters'))
            if not installed:
                return original_start(uid,command,stdin=stdin) if start else original_run(uid,command,check=check,input=input)
            def inner_path(value):
                value=str(value)
                return '/'+value[len(str(root))+1:] if value.startswith(str(root)+'/') else value
            command=[inner_path(value) for value in command]
            def enter():
                os.chroot(root);os.chdir('/');os.setgroups([]);os.setgid(uid);os.setuid(uid)
            if start:return subprocess.Popen(command,stdin=stdin,stdout=subprocess.PIPE,stderr=subprocess.PIPE,preexec_fn=enter)
            return subprocess.run(command,input=input,check=check,capture_output=True,preexec_fn=enter,timeout=15)
        linux_lab.as_uid=lambda uid,command,**kwargs:scoped(uid,command,**kwargs)
        linux_lab.start_as=lambda uid,command,**kwargs:scoped(uid,command,start=True,**kwargs)
        import tui_access_lab
        tui_access_lab.LAB_PARENT=root/'tmp'
        tempfile.tempdir=str(root/'tmp')
        os.environ['CHEF_RUNTIME_ROOT']=str(root)
        fixture=importlib.import_module('chef_runtime_'+mode)
        if mode in ('adapter','reconciliation'):
            common=fixture.common if mode=='adapter' else fixture.adapter.common
            original_common_run=common.run_uid
            original_common_start=common.start_uid
            def is_installed(command):
                return (len(command)>1 and pathlib.Path(command[0]).name=='pm-custody' and
                    command[1] in ('serve-vault','migrate-agent-registry','provision-adapters'))
            def common_run(uid,command,**kwargs):
                return scoped(uid,command,**kwargs) if is_installed(command) else original_common_run(uid,command,**kwargs)
            def common_start(uid,command,**kwargs):
                return scoped(uid,command,start=True,**kwargs) if is_installed(command) else original_common_start(uid,command,**kwargs)
            common.run_uid=common_run;common.start_uid=common_start
        sys.argv=[fixture.__file__,*map(str,copied if mode in ('adapter','reconciliation') else copied[:2])]
        fixture.main()
    finally:
        # Exact owned root only; all child resources must already be stopped by
        # the fixture. Do not suppress failed cleanup or follow any symlink.
        for directory,dirs,files in os.walk(root,topdown=False):
            for name in files+dirs:os.lchown(pathlib.Path(directory)/name,0,0)
            os.chown(directory,0,0)
        shutil.rmtree(root);assert not root.exists()
    print('PASS owned-root custody=chroot clients=native host-mounts=none cleanup=verified',flush=True)


if __name__=='__main__':main()
