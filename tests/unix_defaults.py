"""Default configuration files of common systems, for tests/test_persistence_unix.py.

PAM: comment and blank lines are removed, every other line is byte for byte as shipped.

* DEBIAN_UBUNTU: Ubuntu 24.04 copied from /etc/pam.d (common-*, login, other, su, sudo, runuser); sshd and su-l come from
  Debian 12's openssh-server and util-linux source packages (sources.debian.org).
* ARCH: Arch Linux packaging repositories (pambase, openssh, sudo, util-linux), the files as packaged. system-services is
  there as a counter-example: it is not a login service and has `auth sufficient pam_permit.so`.
* FEDORA_AUTHSELECT_*: Fedora's authselect `sssd` profile (system-auth, password-auth, postlogin) expanded for no feature
  and for a workstation feature set, plus the openssh, util-linux, sudo and pam packages' own files (RHEL 8/9 are the same).
* DEBIAN_SSSD / DEBIAN_FPRINTD: common-auth as pam-auth-update writes it when libpam-sss resp. fprintd are installed.
* MACOS: the stock sudo, su, login and sshd stacks of macOS (transcribed, not fetched).

Scripts: UBUNTU_MOTD is /etc/update-motd.d of an Ubuntu 24.04 install, PERIODIC_STOCK the FreeBSD originals of the periodic
scripts macOS ships adapted copies of (110.clean-tmps, 130.clean-msgs, 999.local); both are verbatim.
"""

DEBIAN_UBUNTU = {
    "common-auth": """auth	[success=1 default=ignore]	pam_unix.so nullok
auth	requisite			pam_deny.so
auth	required			pam_permit.so
""",
    "common-account": """account	[success=1 new_authtok_reqd=done default=ignore]	pam_unix.so 
account	requisite			pam_deny.so
account	required			pam_permit.so
""",
    "common-password": """password	[success=1 default=ignore]	pam_unix.so obscure yescrypt
password	requisite			pam_deny.so
password	required			pam_permit.so
""",
    "common-session": """session	[default=1]			pam_permit.so
session	requisite			pam_deny.so
session	required			pam_permit.so
session optional			pam_umask.so
session	required	pam_unix.so 
session	optional	pam_systemd.so 
""",
    "common-session-noninteractive": """session	[default=1]			pam_permit.so
session	requisite			pam_deny.so
session	required			pam_permit.so
session optional			pam_umask.so
session	required	pam_unix.so 
""",
    "login": """auth       optional   pam_faildelay.so  delay=3000000
auth       requisite  pam_nologin.so
session [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so close
session    required     pam_loginuid.so
session    optional   pam_motd.so motd=/run/motd.dynamic
session    optional   pam_motd.so noupdate
session [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so open
session       required   pam_env.so readenv=1
session       required   pam_env.so readenv=1 envfile=/etc/default/locale
@include common-auth
auth       optional   pam_group.so
session    required   pam_limits.so
session    optional   pam_lastlog.so
session    optional   pam_mail.so standard
session    optional   pam_keyinit.so force revoke
@include common-account
@include common-session
@include common-password
""",
    "other": """@include common-auth
@include common-account
@include common-password
@include common-session
""",
    "su": """auth       sufficient pam_rootok.so
session       required   pam_env.so readenv=1
session       required   pam_env.so readenv=1 envfile=/etc/default/locale
session    optional   pam_mail.so nopen
session    required   pam_limits.so
@include common-auth
@include common-account
@include common-session
""",
    "sudo": """session    required   pam_limits.so
session    required   pam_env.so readenv=1 user_readenv=0
session    required   pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0
@include common-auth
@include common-account
@include common-session-noninteractive
""",
    "sudo-i": """session    required   pam_limits.so
session    required   pam_env.so readenv=1 user_readenv=0
session    required   pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0
@include common-auth
@include common-account
@include common-session
""",
    "runuser": """auth		sufficient	pam_rootok.so
session		optional	pam_keyinit.so revoke
session		required	pam_limits.so
session		required	pam_unix.so
""",
    "runuser-l": """auth		include		runuser
session		optional	pam_keyinit.so force revoke
-session	optional	pam_systemd.so
session		include		runuser
""",
    "su-l": """auth		include		su
account		include		su
password	include		su
session		optional	pam_keyinit.so force revoke
session		include		su
""",
    "sshd": """@include common-auth
account    required     pam_nologin.so
@include common-account
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so close
session    required     pam_loginuid.so
session    optional     pam_keyinit.so force revoke
@include common-session
session    optional     pam_motd.so  motd=/run/motd.dynamic
session    optional     pam_motd.so noupdate
session    optional     pam_mail.so standard noenv # [1]
session    required     pam_limits.so
session    required     pam_env.so # [1]
session    required     pam_env.so user_readenv=1 envfile=/etc/default/locale
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so open
@include common-password
""",
}

ARCH = {
    "system-auth": """auth       required                    pam_faillock.so      preauth
-auth      [success=2 default=ignore]  pam_systemd_home.so
auth       [success=1 default=bad]     pam_unix.so          try_first_pass nullok
auth       [default=die]               pam_faillock.so      authfail
auth       optional                    pam_permit.so
auth       required                    pam_env.so
auth       required                    pam_faillock.so      authsucc
-account   [success=1 default=ignore]  pam_systemd_home.so
account    required                    pam_unix.so
account    optional                    pam_permit.so
account    required                    pam_time.so
-password  [success=1 default=ignore]  pam_systemd_home.so
password   required                    pam_unix.so          try_first_pass nullok shadow
password   optional                    pam_permit.so
-session   optional                    pam_systemd_home.so
session    required                    pam_limits.so
session    required                    pam_unix.so
session    optional                    pam_permit.so
""",
    "system-login": """auth       required   pam_shells.so
auth       requisite  pam_nologin.so
auth       include    system-auth
account    required   pam_access.so
account    required   pam_nologin.so
account    include    system-auth
password   include    system-auth
session    optional   pam_loginuid.so
session    optional   pam_keyinit.so       force revoke
session    include    system-auth
session    optional   pam_lastlog2.so      silent
session    optional   pam_motd.so
session    optional   pam_mail.so          dir=/var/spool/mail standard quiet
session    optional   pam_umask.so
-session   optional   pam_systemd.so
session    required   pam_env.so
""",
    "system-local-login": """auth      include   system-login
account   include   system-login
password  include   system-login
session   include   system-login
""",
    "system-remote-login": """auth      include   system-login
account   include   system-login
password  include   system-login
session   include   system-login
""",
    "other": """auth      required   pam_deny.so
auth      required   pam_warn.so
account   required   pam_deny.so
account   required   pam_warn.so
password  required   pam_deny.so
password  required   pam_warn.so
session   required   pam_deny.so
session   required   pam_warn.so
""",
    "system-services": """auth      sufficient  pam_permit.so
account   include     system-auth
session   optional    pam_loginuid.so
session   required    pam_limits.so
session   required    pam_unix.so
session   optional    pam_permit.so
session   required    pam_env.so
""",
    "sshd": """auth      include   system-remote-login
account   include   system-remote-login
password  include   system-remote-login
session   include   system-remote-login
""",
    "sudo": """auth		include		system-auth
account		include		system-auth
session		include		system-auth
session		optional	pam_systemd.so class=none
""",
    "login": """auth       requisite    pam_nologin.so
auth       include      system-local-login
account    include      system-local-login
session    include      system-local-login
password   include      system-local-login
""",
    "remote": """auth       required     pam_securetty.so
auth       requisite    pam_nologin.so
auth       include      system-remote-login
account    include      system-remote-login
session    include      system-remote-login
password   include      system-remote-login
""",
    "su": """auth            sufficient      pam_rootok.so
auth            required        pam_unix.so
account         required        pam_unix.so
session         required        pam_unix.so
session         required        pam_limits.so
password        include         system-auth
""",
    "runuser": """auth    sufficient      pam_rootok.so
session include         system-login
""",
}

FEDORA_AUTHSELECT_DEFAULT = {
    "system-auth": """auth        required                                     pam_env.so
auth        required                                     pam_faildelay.so delay=2000000
auth        [default=1 ignore=ignore success=ok]         pam_usertype.so isregular
auth        [default=1 ignore=ignore success=ok]         pam_localuser.so
auth        sufficient                                   pam_unix.so nullok
auth        [default=1 ignore=ignore success=ok]         pam_usertype.so isregular
auth        sufficient                                   pam_sss.so forward_pass
auth        required                                     pam_deny.so
account     required                                     pam_unix.so
account     sufficient                                   pam_localuser.so
account     sufficient                                   pam_usertype.so issystem
account     [default=bad success=ok user_unknown=ignore] pam_sss.so
account     required                                     pam_permit.so
password    requisite                                    pam_pwquality.so local_users_only
password    sufficient                                   pam_unix.so yescrypt shadow nullok use_authtok
password    [success=1 default=ignore]                   pam_localuser.so
password    sufficient                                   pam_sss.so use_authtok
password    required                                     pam_deny.so
session     optional                                     pam_keyinit.so revoke
session     required                                     pam_limits.so
-session    optional                                     pam_systemd.so
session     [success=1 default=ignore]                   pam_succeed_if.so service in crond quiet use_uid
session     required                                     pam_unix.so
session     optional                                     pam_sss.so
""",
    "password-auth": """auth        required                                     pam_env.so
auth        required                                     pam_faildelay.so delay=2000000
auth        [default=1 ignore=ignore success=ok]         pam_usertype.so isregular
auth        [default=1 ignore=ignore success=ok]         pam_localuser.so
auth        sufficient                                   pam_unix.so nullok
auth        [default=1 ignore=ignore success=ok]         pam_usertype.so isregular
auth        sufficient                                   pam_sss.so forward_pass
auth        required                                     pam_deny.so
account     required                                     pam_unix.so
account     sufficient                                   pam_localuser.so
account     sufficient                                   pam_usertype.so issystem
account     [default=bad success=ok user_unknown=ignore] pam_sss.so
account     required                                     pam_permit.so
password    requisite                                    pam_pwquality.so local_users_only
password    sufficient                                   pam_unix.so yescrypt shadow nullok use_authtok
password    [success=1 default=ignore]                   pam_localuser.so
password    sufficient                                   pam_sss.so use_authtok
password    required                                     pam_deny.so
session     optional                                     pam_keyinit.so revoke
session     required                                     pam_limits.so
-session    optional                                     pam_systemd.so
session     [success=1 default=ignore]                   pam_succeed_if.so service in crond quiet use_uid
session     required                                     pam_unix.so
session     optional                                     pam_sss.so
""",
    "postlogin": """session     optional                   pam_umask.so silent
session     [success=1 default=ignore] pam_succeed_if.so service !~ gdm* service !~ su* quiet
session     [default=1]                pam_lastlog2.so
session     optional                   pam_lastlog2.so silent
""",
    "sshd": """auth       substack     password-auth
auth       include      postlogin
account    required     pam_sepermit.so
account    required     pam_nologin.so
account    include      password-auth
password   include      password-auth
session    required     pam_selinux.so close
session    required     pam_loginuid.so
session    required     pam_selinux.so open env_params
session    required     pam_namespace.so
session    optional     pam_keyinit.so force revoke
session    optional     pam_motd.so
session    include      password-auth
session    include      postlogin
""",
    "login": """auth       substack     system-auth
auth       include      postlogin
account    required     pam_nologin.so
account    include      system-auth
password   include      system-auth
session    required     pam_selinux.so close
session    required     pam_loginuid.so
session    required     pam_selinux.so open
session    required     pam_namespace.so
session    optional     pam_keyinit.so force revoke
session    include      system-auth
session    include      postlogin
-session   optional     pam_ck_connector.so
""",
    "su": """auth		required	pam_env.so
auth		sufficient	pam_rootok.so
auth		substack	system-auth
auth		include		postlogin
account		sufficient	pam_succeed_if.so uid = 0 use_uid quiet
account		include		system-auth
password	include		system-auth
session		include		system-auth
session		include		postlogin
session		optional	pam_xauth.so
""",
    "su-l": """auth		include		su
account		include		su
password	include		su
session		optional	pam_keyinit.so force revoke
session		include		su
""",
    "runuser": """auth		sufficient	pam_rootok.so
session		optional	pam_keyinit.so revoke
session		required	pam_limits.so
session		required	pam_unix.so
""",
    "other": """auth     required       pam_deny.so
account  required       pam_deny.so
password required       pam_deny.so
session  required       pam_deny.so
""",
    "sudo": """auth       include      system-auth
account    include      system-auth
password   include      system-auth
session    optional     pam_keyinit.so revoke
session    required     pam_limits.so
session    include      system-auth
""",
    "sudo-i": """auth       include      sudo
account    include      sudo
password   include      sudo
session    optional     pam_keyinit.so force revoke
session    include      sudo
""",
}

FEDORA_AUTHSELECT_WORKSTATION = {
    "system-auth": """auth        required                                     pam_env.so
auth        required                                     pam_faildelay.so delay=2000000
auth        required                                     pam_faillock.so preauth silent
auth        sufficient                                   pam_fprintd.so
auth        [default=1 ignore=ignore success=ok]         pam_usertype.so isregular
auth        [default=1 ignore=ignore success=ok]         pam_localuser.so
auth        sufficient                                   pam_unix.so nullok
auth        [default=1 ignore=ignore success=ok]         pam_usertype.so isregular
auth        sufficient                                   pam_sss.so forward_pass
auth        required                                     pam_faillock.so authfail
auth        optional                                     pam_gnome_keyring.so only_if=login auto_start
auth        required                                     pam_deny.so
account     required                                     pam_faillock.so
account     required                                     pam_unix.so
account     sufficient                                   pam_localuser.so
account     sufficient                                   pam_usertype.so issystem
account     [default=bad success=ok user_unknown=ignore] pam_sss.so
account     required                                     pam_permit.so
password    requisite                                    pam_pwquality.so local_users_only
password    sufficient                                   pam_unix.so yescrypt shadow nullok use_authtok
password    [success=1 default=ignore]                   pam_localuser.so
password    sufficient                                   pam_sss.so use_authtok
password    required                                     pam_deny.so
session     optional                                     pam_keyinit.so revoke
session     required                                     pam_limits.so
-session    optional                                     pam_systemd.so
session     optional                                     pam_oddjob_mkhomedir.so
session     [success=1 default=ignore]                   pam_succeed_if.so service in crond quiet use_uid
session     required                                     pam_unix.so
session     optional                                     pam_sss.so
session     optional                                     pam_gnome_keyring.so only_if=login auto_start
""",
    "password-auth": """auth        required                                     pam_env.so
auth        required                                     pam_faildelay.so delay=2000000
auth        required                                     pam_faillock.so preauth silent
auth        [default=1 ignore=ignore success=ok]         pam_usertype.so isregular
auth        [default=1 ignore=ignore success=ok]         pam_localuser.so
auth        sufficient                                   pam_unix.so nullok
auth        [default=1 ignore=ignore success=ok]         pam_usertype.so isregular
auth        sufficient                                   pam_sss.so forward_pass
auth        required                                     pam_faillock.so authfail
auth        optional                                     pam_gnome_keyring.so auto_start
auth        required                                     pam_deny.so
account     required                                     pam_faillock.so
account     required                                     pam_unix.so
account     sufficient                                   pam_localuser.so
account     sufficient                                   pam_usertype.so issystem
account     [default=bad success=ok user_unknown=ignore] pam_sss.so
account     required                                     pam_permit.so
password    requisite                                    pam_pwquality.so local_users_only
password    sufficient                                   pam_unix.so yescrypt shadow nullok use_authtok
password    [success=1 default=ignore]                   pam_localuser.so
password    sufficient                                   pam_sss.so use_authtok
password    required                                     pam_deny.so
session     optional                                     pam_keyinit.so revoke
session     required                                     pam_limits.so
-session    optional                                     pam_systemd.so
session     optional                                     pam_oddjob_mkhomedir.so
session     [success=1 default=ignore]                   pam_succeed_if.so service in crond quiet use_uid
session     required                                     pam_unix.so
session     optional                                     pam_sss.so
session     optional                                     pam_gnome_keyring.so auto_start
""",
    "postlogin": """session     optional                   pam_umask.so silent
session     [success=1 default=ignore] pam_succeed_if.so service !~ gdm* service !~ su* quiet
session     [default=1]                pam_lastlog2.so silent
session     optional                   pam_lastlog2.so silent
""",
    "sshd": """auth       substack     password-auth
auth       include      postlogin
account    required     pam_sepermit.so
account    required     pam_nologin.so
account    include      password-auth
password   include      password-auth
session    required     pam_selinux.so close
session    required     pam_loginuid.so
session    required     pam_selinux.so open env_params
session    required     pam_namespace.so
session    optional     pam_keyinit.so force revoke
session    optional     pam_motd.so
session    include      password-auth
session    include      postlogin
""",
    "login": """auth       substack     system-auth
auth       include      postlogin
account    required     pam_nologin.so
account    include      system-auth
password   include      system-auth
session    required     pam_selinux.so close
session    required     pam_loginuid.so
session    required     pam_selinux.so open
session    required     pam_namespace.so
session    optional     pam_keyinit.so force revoke
session    include      system-auth
session    include      postlogin
-session   optional     pam_ck_connector.so
""",
    "su": """auth		required	pam_env.so
auth		sufficient	pam_rootok.so
auth		substack	system-auth
auth		include		postlogin
account		sufficient	pam_succeed_if.so uid = 0 use_uid quiet
account		include		system-auth
password	include		system-auth
session		include		system-auth
session		include		postlogin
session		optional	pam_xauth.so
""",
    "su-l": """auth		include		su
account		include		su
password	include		su
session		optional	pam_keyinit.so force revoke
session		include		su
""",
    "runuser": """auth		sufficient	pam_rootok.so
session		optional	pam_keyinit.so revoke
session		required	pam_limits.so
session		required	pam_unix.so
""",
    "other": """auth     required       pam_deny.so
account  required       pam_deny.so
password required       pam_deny.so
session  required       pam_deny.so
""",
    "sudo": """auth       include      system-auth
account    include      system-auth
password   include      system-auth
session    optional     pam_keyinit.so revoke
session    required     pam_limits.so
session    include      system-auth
""",
    "sudo-i": """auth       include      sudo
account    include      sudo
password   include      sudo
session    optional     pam_keyinit.so force revoke
session    include      sudo
""",
}

UBUNTU_MOTD = {
    "00-header": r"""#!/bin/sh
#
#    00-header - create the header of the MOTD
#    Copyright (C) 2009-2010 Canonical Ltd.
#
#    Authors: Dustin Kirkland <kirkland@canonical.com>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

[ -r /etc/lsb-release ] && . /etc/lsb-release

if [ -z "$DISTRIB_DESCRIPTION" ] && [ -x /usr/bin/lsb_release ]; then
	# Fall back to using the very slow lsb_release utility
	DISTRIB_DESCRIPTION=$(lsb_release -s -d)
fi

printf "Welcome to %s (%s %s %s)\n" "$DISTRIB_DESCRIPTION" "$(uname -o)" "$(uname -r)" "$(uname -m)"
""",
    "10-help-text": r"""#!/bin/sh
#
#    10-help-text - print the help text associated with the distro
#    Copyright (C) 2009-2010 Canonical Ltd.
#
#    Authors: Dustin Kirkland <kirkland@canonical.com>,
#             Brian Murray <brian@canonical.com>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

printf "\n"
printf " * Documentation:  https://help.ubuntu.com\n"
printf " * Management:     https://landscape.canonical.com\n"
printf " * Support:        https://ubuntu.com/pro\n"
""",
    "50-motd-news": r"""#!/bin/sh
#
#    50-motd-news - print the live news from the Ubuntu wire
#    Copyright (C) 2016-2020 Canonical Ltd.
#    Copyright (C) 2016-2017 Dustin Kirkland
#
#    Authors: Dustin Kirkland <kirkland@canonical.com>
#             Steve Langasek <steve.langasek@canonical.com>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

##############################################################################
# This program could be rewritten in C or Golang for faster performance.
# Or it could be rewritten in Python or another higher level language
# for more modularity.
# However, I've insisted on shell here for transparency!
#                                                                     - Dustin
##############################################################################

# Source the local configuration
[ -r /etc/default/motd-news ] && . /etc/default/motd-news

# Exit immediately, unless we're enabled
# This makes this script very easy to disable in /etc/default/motd-news configuration
[ "$ENABLED" = "1" ] || exit 0

# Ensure sane defaults
[ -n "$URLS" ] || URLS="https://motd.ubuntu.com"
[ -n "$WAIT" ] || WAIT=5
[ -n "$CACHE" ] || CACHE="/var/cache/motd-news"
[ "$1" = "--force" ] && FORCED=1

# Ensure we print safely, maximum of the first 10 lines,
# maximum of the first 80 chars per line, no control chars
safe_print() {
	cat "$1" | head -n 10 | tr -d '\000-\011\013\014\016-\037' | cut -c -80
}


# If we're not forcing an update, and we have a cached motd-news file,
# then just print it and exit as quickly as possible, for login performance.
# Note that systemd should keep this cache file up to date, asynchronously
if [ "$FORCED" != "1" ]; then
  	if [ -r $CACHE ]; then
		echo
		safe_print $CACHE
	elif [ "$(id -u)" -eq 0 ]; then
		: > $CACHE
	fi
	exit 0
fi

# If we've made it here, we've been given the --force argument,
# probably from the systemd motd-news.service.  Let's update...

# Abort early if wget is missing
[ -x /usr/bin/wget ] || exit 0

# Generate our temp files, clean up when done
NEWS=$(mktemp) || exit 1
ERR=$(mktemp) || exit 1
CLOUD=$(mktemp) || exit 1
trap "rm -f $NEWS $ERR $CLOUD" HUP INT QUIT ILL TRAP KILL BUS TERM

# Construct a user agent, similar to Firefox/Chrome/Safari/IE to
# ensure a proper, tailored, accurate message of the day

# wget browser version, for debug purposes
wget_ver="$(dpkg -l wget | awk '$1 == "ii" { print($3); exit(0); }')"

# Distribution version, for messages releated to this Ubuntu release
. /etc/lsb-release
lsb=$(echo "$DISTRIB_DESCRIPTION" | sed -e "s/ /\//g")
codename="$DISTRIB_CODENAME"

# Kernel version and CPU type, for messages related to a particular revision or hardware
platform="$(uname -o)/$(uname -r)/$(uname -m)"
arch="$(uname -m)"
cpu="$(grep -m1 "^model name" /proc/cpuinfo | sed -e "s/.*: //" -e "s:\s\+:/:g")"
cloud_id="unknown"
if [ -x /usr/bin/cloud-id ]; then
    /usr/bin/cloud-id > "$CLOUD" 2>/dev/null
    if [ "$?" -eq "0" ]; then
        # sanitize it a bit, just in case
        cloud_id=$(cut -c -40 "${CLOUD}" | tr -c -d '[:alnum:]')
        if [ -z "${cloud_id}" ]; then
            cloud_id="unknown"
        fi
    fi
fi

# Piece together the user agent
USER_AGENT="wget/$wget_ver $lsb $platform $cpu cloud_id/$cloud_id"

# Loop over any configured URLs
for u in $URLS; do
	# Ensure https:// protocol, for security reasons
	case $u in
		https://*)
			true
		;;
		https://motd.ubuntu.com)
			u="$u/$codename/$arch"
		;;
		*)
			continue
		;;
	esac
	# If we're forced, set the wait to much higher (1 minute)
	[ "$FORCED" = "1" ] && WAIT=60
	# Fetch and print the news motd
	result=0
	not_found_is_ok=0
	wget --timeout "$WAIT" -U "$USER_AGENT" -O- --content-on-error "$u" >"$NEWS" 2>"$ERR" || result=$?
	# from wget's manpage: 8   Server issued an error response.
	if [ $result -eq 8 ]; then
		if grep -q "ERROR 404" "$ERR"; then
			# The server's 404 document is the generic, non cloud-specific, motd-news
			# content present in the index.txt file
			not_found_is_ok=1
		fi
	fi
	if [ $result -eq 0 ] || [ $not_found_is_ok -eq 1 ]; then
		echo
		# At most, 10 lines of text, remove control characters, print at most 80 characters per line
		safe_print "$NEWS"
		# Try to update the cache
		safe_print "$NEWS" 2>/dev/null >$CACHE || true
	else
		: > "$CACHE"
 	fi
done
rm -f "$NEWS" "$ERR" "$CLOUD"
exit 0
""",
    "60-unminimize": r"""#!/bin/sh
#
# This file is not managed by a package.  If you no longer want to
# see this message you can safely remove the file.
echo ""
echo "This system has been minimized by removing packages and content that are"
echo "not required on a system that users do not log into."
echo ""
echo "To restore this content, you can run the 'unminimize' command."
""",
}

PERIODIC_STOCK = {
    "110.clean-tmps": r"""#!/bin/sh
#
#
# Perform temporary directory cleaning so that long-lived systems
# don't end up with excessively old files there.
#

# If there is a global system configuration file, suck it in.
#
if [ -r /etc/defaults/periodic.conf ]
then
    . /etc/defaults/periodic.conf
    source_periodic_confs
fi

case "$daily_clean_tmps_enable" in
    [Yy][Ee][Ss])
	if [ -z "$daily_clean_tmps_days" ]
	then
	    echo '$daily_clean_tmps_enable is set but' \
		'$daily_clean_tmps_days is not'
	    rc=2
	else
	    echo ""
	    echo "Removing old temporary files:"

	    set -f noglob
	    args="-atime +$daily_clean_tmps_days -mtime +$daily_clean_tmps_days"
	    args="${args} -ctime +$daily_clean_tmps_days"
	    dargs="-empty -mtime +$daily_clean_tmps_days"
	    [ -n "$daily_clean_tmps_ignore" ] && {
		args="$args "`echo " ${daily_clean_tmps_ignore% }" |
		    sed 's/[ 	][ 	]*/ ! -name /g'`
		dargs="$dargs "`echo " ${daily_clean_tmps_ignore% }" |
		    sed 's/[ 	][ 	]*/ ! -name /g'`
	    }
	    case "$daily_clean_tmps_verbose" in
		[Yy][Ee][Ss])
		    print=-print;;
		*)
		    print=;;
	    esac

	    rc=$(for dir in $daily_clean_tmps_dirs
		do
		    [ ."${dir#/}" != ."$dir" -a -d $dir ] && cd $dir && {
			find -x -d . -type f $args -delete $print
			find -x -d . ! -name . -type d $dargs -delete $print
		    } | sed "s,^\\.,  $dir,"
		done | tee /dev/stderr | wc -l)
	    [ -z "$print" ] && rc=0
	    [ $rc -gt 1 ] && rc=1
	    set -f glob
	fi;;

    *)  rc=0;;
esac

exit $rc
""",
    "130.clean-msgs": r"""#!/bin/sh
#
#
# Remove system	messages
#

# If there is a global system configuration file, suck it in.
#
if [ -r /etc/defaults/periodic.conf ]
then
    . /etc/defaults/periodic.conf
    source_periodic_confs
fi

case "$daily_clean_msgs_enable" in
    [Yy][Ee][Ss])
	if [ ! -d /var/msgs ]
	then
	    echo '$daily_clean_msgs_enable is set but /var/msgs' \
		"doesn't exist"
	    rc=2
	else
	    echo ""
	    echo "Cleaning out old system announcements:"

	    [ -n "$daily_clean_msgs_days" ] &&
		arg=-${daily_clean_msgs_days#-} || arg=
	    msgs -c $arg && rc=0 || rc=3
	fi;;

    *)  rc=0;;
esac

exit $rc
""",
    "999.local": r"""#!/bin/sh
#
#
# Run the old /etc/daily.local script.  This is really for backwards
# compatibility more than anything else.
#

# If there is a global system configuration file, suck it in.
#
if [ -r /etc/defaults/periodic.conf ]
then
    . /etc/defaults/periodic.conf
    source_periodic_confs
fi

rc=0
for script in $daily_local
do
    echo ''
    case "$script" in
	/*)
	    if [ -x "$script" ]
	    then
		echo "Running $script:"

		$script || rc=3
	    elif [ -f "$script" ]
	    then
		echo "Running $script:"

		sh $script || rc=3
	    else
		echo "$script: No such file"
		[ $rc -lt 2 ] && rc=2
	    fi;;
	*)
	    echo "$script: Not an absolute path"
	    [ $rc -lt 2 ] && rc=2;;
    esac
done

exit $rc
""",
}

DEBIAN_SSSD = {
    "common-auth": (
        "auth\t[success=2 default=ignore]\tpam_unix.so nullok\n"
        "auth\t[success=1 default=ignore]\tpam_sss.so use_first_pass\n"
        "auth\trequisite\t\t\tpam_deny.so\n"
        "auth\trequired\t\t\tpam_permit.so\n"
        "auth\toptional\t\t\tpam_cap.so\n"),
}

DEBIAN_FPRINTD = {
    "common-auth": (
        "auth\t[success=3 default=ignore]\tpam_unix.so nullok\n"
        "auth\t[success=2 default=ignore]\tpam_sss.so use_first_pass\n"
        "auth\t[success=1 default=ignore]\tpam_fprintd.so max-tries=1 timeout=10\n"
        "auth\trequisite\t\t\tpam_deny.so\n"
        "auth\trequired\t\t\tpam_permit.so\n"
        "auth\toptional\t\t\tpam_cap.so\n"),
}

MACOS = {
    "sudo": (
        "auth       include        sudo_local\n"
        "auth       sufficient     pam_smartcard.so\n"
        "auth       required       pam_opendirectory.so\n"
        "account    required       pam_permit.so\n"
        "password   required       pam_deny.so\n"
        "session    required       pam_permit.so\n"),
    "su": (
        "auth       sufficient     pam_rootok.so\n"
        "auth       required       pam_opendirectory.so\n"
        "account    required       pam_group.so no_warn group=admin,wheel ruser root_only fail_safe\n"
        "account    required       pam_opendirectory.so no_check_shell\n"
        "password   required       pam_opendirectory.so\n"
        "session    required       pam_launchd.so\n"),
    "login": (
        "auth       optional       pam_krb5.so use_kcminit\n"
        "auth       optional       pam_ntlm.so try_first_pass\n"
        "auth       optional       pam_mount.so try_first_pass\n"
        "auth       required       pam_opendirectory.so try_first_pass\n"
        "account    required       pam_nologin.so\n"
        "account    required       pam_opendirectory.so\n"
        "password   required       pam_opendirectory.so\n"
        "session    required       pam_launchd.so\n"
        "session    required       pam_uwtmp.so\n"
        "session    optional       pam_mount.so\n"),
    "sshd": (
        "auth       required       pam_opendirectory.so\n"
        "account    required       pam_nologin.so\n"
        "account    required       pam_sacl.so sacl_service=ssh\n"
        "account    required       pam_opendirectory.so\n"
        "password   required       pam_opendirectory.so\n"
        "session    required       pam_launchd.so\n"
        "session    optional       pam_mount.so\n"),
}

ALL_DEFAULTS = {
    "debian-ubuntu": DEBIAN_UBUNTU,
    "debian-sssd": {**DEBIAN_UBUNTU, **DEBIAN_SSSD},
    "debian-fprintd": {**DEBIAN_UBUNTU, **DEBIAN_FPRINTD},
    "arch": ARCH,
    "fedora-default": FEDORA_AUTHSELECT_DEFAULT,
    "fedora-workstation": FEDORA_AUTHSELECT_WORKSTATION,
    "macos": MACOS,
}
