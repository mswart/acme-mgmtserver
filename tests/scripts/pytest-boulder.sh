#!/bin/bash
set -e

export FAKE_DNS=$(ip addr show docker0 | awk 'match($0, /([0-9.]+)\/[0-9]+/, a) { print a[1] }')

py.test --tb=short -k boulder
