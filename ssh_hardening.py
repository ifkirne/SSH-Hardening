
__author__ = "IFKIRNE Soufiane"
__email__ = "s.ifkirne@linux.com"

"""

For security reasons we should:

    [1] Change default ssh ports (to 12345)
    [2] Add a user for sys admin tasks
    [3] Disable ssh root access
    [4] Enable public key based authentication
    [5] Disable password based authentication

"""


class COLORS:

    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def csf_install():
    "Check if CSF is installed, if not install it and disable TESTING mode"

    # CSF relies on perl, is it installed?
    perl = sudo('perl --version')
    if perl.failed:
        sudo('yum install perl -y')
    csf = sudo('perl /usr/local/csf/bin/csftest.pl|grep "csf should function"')

    if csf.failed:
        # CSF doesn't seem to be installed
        # http://download.configserver.com/csf/install.txt
        sudo('rm -fv csf.tgz*')
        sudo('wget https://download.configserver.com/csf.tgz')
        sudo('tar -xzf csf.tgz')
        sudo('cd csf && sh install.sh')
        sed('/etc/csf/csf.conf', r'TESTING = "1"', 'TESTING = "0"',
            use_sudo=True, backup='.bak')
        sudo('/usr/sbin/csf -r')

    elif csf.succeeded and exists('/etc/csf/csf.conf', use_sudo=True):
        # CSF is installed, is it in testing mode?
        testing = sudo('grep \'TESTING = "1"\' /etc/csf/csf.conf')
        if testing.succeeded:
            sed('/etc/csf/csf.conf', r'TESTING = "1"', 'TESTING = "0"',
                use_sudo=True, backup='.bak')
            sudo('csf -r')
        else:
            sys.stdout.write('CSF is installed and enabled.\n')
    else:
        sys.stdout.write('CSF is installed and enabled.\n')


def setup_iptables(port=12345):
    "Setup basic iptables/csf rules for ssh login: open port 12345"

    sed('/etc/csf/csf.conf', r'(^TCP_IN.*)"$', r'\1,%d"' %
        port, use_sudo=True, backup='.bak')

    sudo('/usr/sbin/csf -r')


def change_ssh_port(port=12345):
    """
    For security, change the default ssh port.
    """
    print "Changing ssh port to: %d on %s" % (port, env.host)
    sed('/etc/ssh/sshd_config', r"^(#?)Port.*", 'Port %d'
        % port, use_sudo=True, backup='.bak')

    setup_iptables(port)


def gen_rsa_keys(key_len=2048):
    commands.getoutput("echo -e  'y\n'|ssh-keygen -q -t rsa -N '' -f frsa")
    public = commands.getoutput('cat frsa.pub')
    private = commands.getoutput('cat frsa')
    commands.getoutput('rm -f frsa.pub frsa')

    return private, public


def ssh_copy_id(user):
    """
        mkdir /home/user/.ssh
        copy pub and private keys -----> .ssh
        add the admin pub key to the authorized keys file
    """

    from fabric.api import local

    with cd('/home/%s' % user):
        sudo('mkdir .ssh')

    with quiet():
        # This step assumes we are running fabric from the control server
        id_rsa = local('sudo cat /home/%s/.ssh/id_rsa' % user, capture=True)
        id_rsa_pub = local('sudo cat /home/%s/.ssh/id_rsa.pub' %
                           user, capture=True)

        if id_rsa.failed or id_rsa_pub.failed:
            id_rsa, id_rsa_pub = gen_rsa_keys()
            id_rsa_pub = id_rsa_pub.replace('jenkins', user)

        sudo('echo "%s" > /home/%s/.ssh/id_rsa.pub' % (id_rsa_pub, user))
        sudo('chmod 644 /home/%s/.ssh/id_rsa.pub' % user)
        sudo('chown %s:%s /home/%s/.ssh/id_rsa.pub' % (user, user, user))

        sudo('echo "%s" > /home/%s/.ssh/id_rsa' % (id_rsa, user))
        sudo('chmod 400 /home/%s/.ssh/id_rsa' % user)
        sudo('chown %s:%s /home/%s/.ssh/id_rsa' % (user, user, user))

        add_to_authorized(user)


def add_to_authorized(user):
    pub = sudo('cat /home/%s/.ssh/id_rsa.pub' % user)
    # TODO: Idempotence: check if the key is already added, do not add it twice
    sudo('echo "%s" >> /home/%s/.ssh/authorized_keys' % (pub, user))
    sudo('chown %s:%s /home/%s/.ssh/authorized_keys' % (user, user, user))


def disable_ssh_root_access():
    sed('/etc/ssh/sshd_config', r'^(#?)PermitRootLogin.*',
        'PermitRootLogin no', use_sudo=True, backup='.bak')


def disable_password_based_authentication():
    sed('/etc/ssh/sshd_config', r'^(#?)PasswordAuthentication yes',
        'PasswordAuthentication no', use_sudo=True, backup='.bak')


def add_user(user, passd):
    "Add user for system administration tasks."

    import random
    import string

    f = lambda i: ''.join(
        random.choice(string.ascii_letters + string.digits) for _ in xrange(i))

    sudo('useradd -m -s /bin/bash %s' % user)
    # jenkins and backup users don't need a valid password set
    if user not in ['backup', 'jenkins']:
        file_ = '/tmp/%s.txt' % f(8)
        sudo('echo %s:%s > %s' % (user, passd, file_))
        sudo('chpasswd -c SHA512 < %s' % file_)
        sudo('rm -rf %s' % file_)


def add_sudo_user(username, password):
    "Create a new sudo user and disable root."

    add_user(username, password)

    sudo('cp -f /etc/sudoers /tmp/sudoers.bk')
    # Grant NOPASSWD:ALL privileges to jenkins. This will simplify automation
    # tasks
    if username == 'jenkins':
        append('/tmp/sudoers.bk', "%s ALL=(ALL) NOPASSWD:ALL" %
               username, use_sudo=True)
    else:
        append('/tmp/sudoers.bk', "%s ALL=(ALL) ALL" % username, use_sudo=True)

    # Set ACLs for the backup user on /pdc and/or /backups
    if username == 'backup':
        sudo('setfacl -R -m d:u:backup:rwx /backups')
        sudo('setfacl -R -m u:backup:rwx /backups')

    # Check sudoers.bk for syntax errors
    sudo('visudo -c -f /tmp/sudoers.bk')
    sudo('cp -f /tmp/sudoers.bk /etc/sudoers')
    sudo('rm -rf /tmp/sudoers.bk')

    ssh_copy_id(username)


def reload_ssh_daemon():
    sudo('service sshd reload')


if __name__ == '__main__':

    import sys
    import commands
    from optparse import OptionParser

    try:

        from fabric.contrib.files import exists, contains, sed, append
        from fabric.api import *
        from fabric.tasks import execute

    except ImportError as e:
        sys.stdout.write(
            COLORS.FAIL + '[!] Error: %s. Fabric may not be installed\n' % str(e) + COLORS.ENDC)

        command = "pip install fabric\n"

        sys.stdout.write(
            COLORS.OKBLUE + '[?] You can install it by trying the following as root user: \n' + command + COLORS.ENDC)
        sys.exit(1)

    except Exception as e:
        sys.stdout.write(COLORS.FAIL + '[!] Error: %s' % str(e) + COLORS.ENDC)
        sys.exit(2)

    env.roledefs = {
        'backup': ['bk1', 'bk2'],
        'cpanel': ['cp1', 'cp2','cp9'],
        'test': ['192.168.15.123']
    }

    parser = OptionParser()

    parser.add_option("-H", "--Hosts", default='test',
                            help="Hosts to execute tasks on")
    parser.add_option("-u", "--username", default='admin',
                            help="User's username")
    parser.add_option("-p", "--password", default='Password1',
                            help="User's password")
    parser.add_option("-P", "--Port", type="int", default='12345',
                            help="The new ssh port")

    (options, args) = parser.parse_args()

    env.use_ssh_config = True
    # To provision a new server, we usually want to login as root initially
    env.user = 'root'

    # env.user = 'dba'
    # env.password = '123'
    # env.port = '22'

    env.warn_only = True

    with hide('stdout', 'stderr'):
        execute(csf_install, hosts=env.roledefs[options.Hosts])
        usernames = [x.strip(' ') for x in options.username.split(',')]
        for username in usernames:
            sys.stdout.write(
                COLORS.OKBLUE + '[!] Adding username = %s\n' % str(username) + COLORS.ENDC)
            execute(add_sudo_user, username, options.password,
                    hosts=env.roledefs[options.Hosts])
        execute(disable_ssh_root_access, hosts=env.roledefs[options.Hosts])
        execute(disable_password_based_authentication,
                hosts=env.roledefs[options.Hosts])
        execute(change_ssh_port,  options.Port,
                hosts=env.roledefs[options.Hosts])
        execute(reload_ssh_daemon,  hosts=env.roledefs[options.Hosts])
