#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf '%s\n' \
        'Usage (live): qualify-exchange-custody-acl.sh --node /absolute/cmfd-node --config /absolute/config.json --output /absolute/evidence.json' \
        'Usage (fixture): qualify-exchange-custody-acl.sh --node /absolute/cmfd-node --fixture /absolute/fixture.json --output /absolute/evidence.json' >&2
    exit 64
}

node=''
config=''
fixture=''
output=''
while (($#)); do
    case "$1" in
        --node) (($# >= 2)) || usage; node=$2; shift 2 ;;
        --config) (($# >= 2)) || usage; config=$2; shift 2 ;;
        --fixture) (($# >= 2)) || usage; fixture=$2; shift 2 ;;
        --output) (($# >= 2)) || usage; output=$2; shift 2 ;;
        *) usage ;;
    esac
done

[[ $node = /* && -f $node && ! -L $node && -x $node ]] || {
    printf '%s\n' 'The node must be an absolute direct executable file.' >&2
    exit 66
}
[[ $output = /* && ! -e $output && ! -L $output ]] || {
    printf '%s\n' 'The output must be an absent absolute create-new path.' >&2
    exit 73
}

if [[ -n $config && -z $fixture ]]; then
    [[ $config = /* && -f $config && ! -L $config ]] || {
        printf '%s\n' 'The config must be an absolute direct regular file.' >&2
        exit 66
    }
    # The binary verifies that this process is the configured non-root service
    # identity and that it is running from the configured installed package.
    exec "$node" exchange-v3-acl-qualify --config "$config" --output "$output"
elif [[ -n $fixture && -z $config ]]; then
    [[ $fixture = /* && -f $fixture && ! -L $fixture ]] || {
        printf '%s\n' 'The fixture must be an absolute direct regular file.' >&2
        exit 66
    }
    # A successful fixture result remains fixture_qualified, never host_qualified.
    exec "$node" exchange-v3-acl-fixture-qualify --fixture "$fixture" --output "$output"
else
    usage
fi
