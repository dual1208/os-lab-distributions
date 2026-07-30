#!/usr/bin/env bash
set -euo pipefail

readonly RELAY_USER=campus-link

[[ ${EUID} -eq 0 ]]
if ! getent group "${RELAY_USER}" >/dev/null; then
  groupadd --system "${RELAY_USER}"
fi
if ! getent passwd "${RELAY_USER}" >/dev/null; then
  useradd --system --gid "${RELAY_USER}" --home-dir /nonexistent \
    --no-create-home --shell /usr/sbin/nologin "${RELAY_USER}"
fi

passwd_record=$(getent passwd "${RELAY_USER}") || exit 1
group_record=$(getent group "${RELAY_USER}") || exit 1
[[ ${passwd_record} != *$'\n'* && ${group_record} != *$'\n'* ]]
IFS=: read -r passwd_name _ passwd_uid passwd_gid _ passwd_home passwd_shell \
  <<< "${passwd_record}" || exit 1
IFS=: read -r group_name _ group_gid group_members <<< "${group_record}" || exit 1
[[ ${passwd_name} == "${RELAY_USER}" && ${group_name} == "${RELAY_USER}" ]]
[[ ${passwd_uid} =~ ^[0-9]+$ && ${passwd_uid} != 0 ]]
[[ ${passwd_gid} =~ ^[0-9]+$ && ${passwd_gid} == "${group_gid}" ]]
[[ ${passwd_home} == /nonexistent ]]
[[ ${passwd_shell} == /usr/sbin/nologin || ${passwd_shell} == /sbin/nologin ]]
[[ -z ${group_members} ]]
relay_groups=$(id -G "${RELAY_USER}") || exit 1
[[ ${relay_groups} == "${passwd_gid}" ]]
