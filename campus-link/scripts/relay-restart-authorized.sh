#!/bin/bash -p
set -euo pipefail
umask 077
ulimit -S -c 0
ulimit -H -c 0
[[ $(ulimit -S -c) == 0 && $(ulimit -H -c) == 0 ]]

[[ $- == *p* ]]
[[ -z ${BASH_ENV+x} && -z ${ENV+x} ]]
[[ -z ${LD_PRELOAD+x} && -z ${LD_LIBRARY_PATH+x} && -z ${LD_AUDIT+x} ]]
[[ -z ${OPENSSL_CONF+x} && -z ${OPENSSL_MODULES+x} && -z ${OPENSSL_ENGINES+x} ]]

readonly original=${SSH_ORIGINAL_COMMAND:-}

sanitize_environment() {
  local name
  while IFS= read -r name; do
    case ${name} in
      BASHOPTS|BASHPID|EUID|PPID|SHELLOPTS|UID) ;;
      *) unset "${name}" ;;
    esac
  done < <(compgen -e)
  PATH=/usr/sbin:/usr/bin:/sbin:/bin
  LC_ALL=C
  HOME=/nonexistent
  IFS=$' \t\n'
  readonly PATH LC_ALL HOME IFS
  export PATH LC_ALL HOME
}
sanitize_environment

# sshd invokes this root-owned wrapper through the dedicated account's
# /bin/sh.  The two literal actions are the complete remote-command surface;
# every authorization value is carried by bounded stdin to a zero-argv helper.
[[ $# -eq 0 ]]
case ${original} in
  permit)
    exec /usr/bin/sudo -n -- /usr/local/libexec/campus-link-relay-restart-permit-authorize
    ;;
  restart)
    exec /usr/bin/sudo -n -- /usr/local/libexec/campus-link-relay-restart-actuator
    ;;
  *) exit 64 ;;
esac
