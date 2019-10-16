#!/bin/bash
set -e

py.test --tb=short -k 'not boulder and not pebble'
