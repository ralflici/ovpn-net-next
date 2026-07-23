#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2026 OpenVPN, Inc.
#
#  Author:	Ralf Lici <ralf@mandelbit.com>

set -eE

OVPN_NUM_PEERS=3

source ./common.sh

ovpn_test_finished=0

ovpn_test_exit() {
	ovpn_cleanup
	modprobe -r ovpn || true

	if [ "${ovpn_test_finished}" -eq 0 ]; then
		ktap_print_totals
	fi
}

ovpn_prepare_network() {
	local p

	for p in $(seq 0 "${OVPN_NUM_PEERS}"); do
		ovpn_cmd_ok "create namespace peer${p}" ovpn_create_ns "${p}"
	done

	for p in $(seq 0 "${OVPN_NUM_PEERS}"); do
		ovpn_cmd_ok "configure peer${p} namespace" ovpn_setup_ns \
			"${p}" 5.5.5.$((p + 1))/24
	done
}

ovpn_start_persistent_cli() {
	local peer="$1"
	shift
	local response

	coproc OVPN_PERSISTENT_CLI {
		OVPN_CLI_PERSISTENT=1 ip netns exec "ovpn_peer${peer}" \
			"${OVPN_CLI}" "$@"
	}

	if ! read -r -t 5 response <&"${OVPN_PERSISTENT_CLI[0]}"; then
		printf '%s\n' "persistent ovpn-cli did not become ready"
		return 1
	fi
	if [ "${response}" != "READY" ]; then
		printf '%s\n' "expected READY, got ${response}"
		return 1
	fi

	OVPN_PERSISTENT_CLI_IN="${OVPN_PERSISTENT_CLI[1]}"
	OVPN_PERSISTENT_CLI_OUT="${OVPN_PERSISTENT_CLI[0]}"
	# Bash creates this variable dynamically for a named coprocess.
	# shellcheck disable=SC2153
	OVPN_PERSISTENT_CLI_PROCESS="${OVPN_PERSISTENT_CLI_PID}"
}

ovpn_persistent_command() {
	local command="$1"
	local response

	printf '%s\n' "${command}" >&"${OVPN_PERSISTENT_CLI_IN}"
	if ! read -r -t 5 response <&"${OVPN_PERSISTENT_CLI_OUT}"; then
		printf '%s\n' "persistent ovpn-cli did not answer ${command}"
		return 1
	fi
	if [ "${response}" != "OK" ]; then
		printf '%s\n' "${command} failed: ${response}"
		return 1
	fi
}

ovpn_stop_persistent_cli() {
	kill -TERM "${OVPN_PERSISTENT_CLI_PROCESS}"
	wait "${OVPN_PERSISTENT_CLI_PROCESS}" || true
}

ovpn_add_key() {
	ovpn_cmd_ok "add key for peer $1" \
		ip netns exec "ovpn_peer${1}" "${OVPN_CLI}" new_key "tun${1}" \
		"$2" 1 0 "${OVPN_ALG}" 1 data64.key
}

ovpn_check_peer_deleted() {
	sleep 1
	ovpn_cmd_fail "peer $2 deleted after transport error" \
		ip netns exec "ovpn_peer${1}" "${OVPN_CLI}" get_peer \
		"tun${1}" "$2"
}

ovpn_test_disconnect() {
	local capture_pid
	local capture_rc
	local capture_file

	ovpn_start_persistent_cli 1 new_peer tun1 10 1 0 10.10.1.1 1
	ovpn_add_key 1 10
	ovpn_persistent_command DISCONNECT

	capture_file=$(mktemp)
	timeout 3 ip netns exec ovpn_peer1 tcpdump -qnli veth1 \
		"udp and src port 0" >"${capture_file}" 2>&1 &
	capture_pid=$!
	sleep 1
	ovpn_cmd_mayfail "send traffic through unbound UDP socket" \
		ip netns exec ovpn_peer1 ping -qfc 1 -w 1 5.5.5.1
	wait "${capture_pid}" || capture_rc=$?
	if [ "${capture_rc:-0}" -ne 124 ]; then
		cat "${capture_file}"
		return 1
	fi
	rm -f "${capture_file}"
	ovpn_stop_persistent_cli
}

ovpn_test_v6only() {
	ovpn_start_persistent_cli 2 new_peer tun2 20 1 0 10.10.2.1 1
	ovpn_add_key 2 20
	ovpn_persistent_command V6ONLY

	ovpn_cmd_mayfail "trigger IPv4 transmit on IPv6-only socket" \
		ip netns exec ovpn_peer2 ping -qfc 1 -w 1 5.5.5.1
	ovpn_check_peer_deleted 2 20
	ovpn_stop_persistent_cli
}

ovpn_test_addrform() {
	ovpn_cmd_ok "bring up peer 3 loopback" \
		ip -n ovpn_peer3 link set lo up
	ovpn_start_persistent_cli 3 new_peer tun3 30 1 0 fd00:0:0:3::1 1
	ovpn_add_key 3 30
	ovpn_persistent_command ADDRFORM

	ovpn_cmd_mayfail "trigger IPv6 transmit on IPv4 socket" \
		ip netns exec ovpn_peer3 ping -qfc 1 -w 1 5.5.5.1
	ovpn_check_peer_deleted 3 30
	ovpn_stop_persistent_cli
}

trap ovpn_test_exit EXIT
trap ovpn_stage_err ERR

ktap_print_header
ktap_set_plan 4

ovpn_cleanup
modprobe -q ovpn || true

ovpn_run_stage "setup network topology" ovpn_prepare_network
ovpn_run_stage "drop traffic after disconnect" ovpn_test_disconnect
ovpn_run_stage "delete peer after enabling IPV6_V6ONLY" ovpn_test_v6only
ovpn_run_stage "delete peer after IPV6_ADDRFORM" ovpn_test_addrform

ovpn_test_finished=1
ktap_finished
