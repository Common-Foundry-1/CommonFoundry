#!/usr/bin/env bash

# Project-local Android build environment. Source this file from any shell:
#   source ./scripts/android-env.sh

_cmfd_script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
_cmfd_project_dir="$(cd -- "${_cmfd_script_dir}/.." && pwd)"

export CMFD_ANDROID_DEV_ROOT="${CMFD_ANDROID_DEV_ROOT:-${_cmfd_project_dir}/.android-dev}"
export JAVA_HOME="${CMFD_ANDROID_DEV_ROOT}/jdk"
export ANDROID_HOME="${CMFD_ANDROID_DEV_ROOT}/android-sdk"
export ANDROID_SDK_ROOT="${ANDROID_HOME}"
export ANDROID_AVD_HOME="${CMFD_ANDROID_DEV_ROOT}/avd"
export NDK_HOME="${ANDROID_HOME}/ndk/30.0.16248370"
export RUSTUP_HOME="${CMFD_ANDROID_DEV_ROOT}/rustup"
export CARGO_HOME="${CMFD_ANDROID_DEV_ROOT}/cargo"
export GRADLE_USER_HOME="${CMFD_ANDROID_DEV_ROOT}/gradle-home"

export PATH="${CARGO_HOME}/bin:${JAVA_HOME}/bin:${ANDROID_HOME}/cmdline-tools/latest/bin:${ANDROID_HOME}/platform-tools:${ANDROID_HOME}/emulator:${PATH}"

unset _cmfd_script_dir
unset _cmfd_project_dir
