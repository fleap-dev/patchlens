#!/usr/bin/env bash

FLAG=$(cat)

cd simpbdd && echo "$FLAG" | ./gradlew run -q 2>/dev/null
