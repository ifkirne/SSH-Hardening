# SSH-Hardening
Some basic fabric/python scripts to harden sshd.

### The ssh_hardening.py contains scripts that can be used to perform the following tasks:
```

  . Change default ssh port (to 2222 by default)
  . Add a user for sys admin tasks
  . Disable ssh root access
  .	Enable public key based authentication
  . Disable password based authentication

```

## Usage:
```
Usage: ssh_hardening.py [options]

Options:
  -h, --help            show this help message and exit
  -H HOSTS, --Hosts=HOSTS
                        Hosts to execute tasks on
  -u USERNAME, --username=USERNAME
                        User's username
  -p PASSWORD, --password=PASSWORD
                        User's password
  -P PORT, --Port=PORT  The new ssh port
```

## Hosts:

```
  'backup' : ['bk1', 'bk2']
  'cpanel': ['cp1', 'cp2', 'cp13','cp42', 'cp128', 'cp112']
  'test': ['192.168.56.100']
```

Testing the script:

```
$ python ssh_hardening.py -H test -u adminn -p pass -P 123
[192.168.56.100] Executing task 'add_sudo_user'
[192.168.56.100] sudo: echo adminn:pass > /tmp/hFIP0aLL.txt
[192.168.56.100] out: sudo password:
[192.168.56.100] out:
[192.168.56.100] sudo: useradd -m -s /bin/bash adminn
[192.168.56.100] out: sudo password:
[192.168.56.100] out:
[192.168.56.100] sudo: chpasswd -c SHA512 < /tmp/hFIP0aLL.txt
[192.168.56.100] out: sudo password:
[192.168.56.100] out:
[192.168.56.100] sudo: rm -rf /tmp/hFIP0aLL.txt
[192.168.56.100] out: sudo password:
[192.168.56.100] out:
[192.168.56.100] sudo: cp -f /etc/sudoers /tmp/sudoers.bk
[192.168.56.100] out: sudo password:
[192.168.56.100] out:
[192.168.56.100] sudo: echo 'adminn ALL=(ALL) ALL' >> "$(echo /tmp/sudoers.bk)"
[192.168.56.100] out: sudo password:
[192.168.56.100] out:
[192.168.56.100] sudo: visudo -c -f /tmp/sudoers.bk
[192.168.56.100] out: sudo password:
[192.168.56.100] out: /tmp/sudoers.bk: parsed OK
[192.168.56.100] out: /etc/sudoers.d/README: parsed OK
[192.168.56.100] out:

[192.168.56.100] sudo: cp -f /tmp/sudoers.bk /etc/sudoers
[192.168.56.100] out: sudo password:
[192.168.56.100] out:
[192.168.56.100] sudo: rm -rf /tmp/sudoers.bk
[192.168.56.100] out: sudo password:
[192.168.56.100] out:
[192.168.56.100] sudo: mkdir .ssh
[192.168.56.100] out: sudo password:
[192.168.56.100] out:
[192.168.56.100] sudo: echo "" > /home/adminn/.ssh/id_rsa.pub
[192.168.56.100] out: sudo password:
[192.168.56.100] out:
[192.168.56.100] sudo: chmod 644 /home/adminn/.ssh/id_rsa.pub
[192.168.56.100] out: sudo password:
[...]

```

Check if we can login to the server with the new user.

```
$ ssh adminn@192.168.56.100 -p 123
Welcome to Ubuntu 14.04.2 LTS (GNU/Linux 3.16.0-30-generic x86_64)

* Documentation:  https://help.ubuntu.com/

  System information as of Fri Jul 24 16:27:55 WEST 2015

  System load:  0.0               Processes:           92
  Usage of /:   23.3% of 6.76GB   Users logged in:     1
  Memory usage: 18%               IP address for eth0: 192.168.56.100
  Swap usage:   0%

  Graph this data and manage this system at:
    https://landscape.canonical.com/

82 packages can be updated.
49 updates are security updates.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

adminn@MysqlServer:~$
```
