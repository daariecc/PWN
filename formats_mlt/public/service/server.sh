#!/usr/bin/env bash

socat tcp-l:1337,fork,reuseaddr exec:"sudo -E -u nobody /task/binary"
