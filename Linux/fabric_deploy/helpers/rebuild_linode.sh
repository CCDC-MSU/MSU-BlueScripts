#!/usr/bin/env bash
set -euo pipefail

ROOT_PASS='lsiu_asdf_SAF1'

rebuild() {
  local id="$1" image="$2"
  echo "==> Rebuilding Linode ${id} with image ${image}"
  linode-cli linodes rebuild "$id" --image "$image" --root_pass "$ROOT_PASS"
}

rebuild 88999067 linode/rocky10
rebuild 88999151 linode/centos-stream10
rebuild 89000152 linode/alpine3.19
rebuild 89000336 linode/fedora41
rebuild 89000422 linode/debian13
rebuild 89000538 linode/arch
rebuild 89000641 linode/opensuse15.6
rebuild 89001091 linode/slackware15.0
rebuild 89001282 linode/gentoo