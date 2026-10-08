#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2026 OpenVPN, Inc.
#
#	Author: Ralf Lici <ralf@mandelbit.com>

OVPN_KEY_TYPE="epoch"
OVPN_EPOCH_TX_LANE_BITS=2
OVPN_EPOCH_RX_LANE_BITS=2
OVPN_SPORT_ENTROPY_TX_MIN=40000
OVPN_SPORT_ENTROPY_TX_MAX=40003

source test.sh
