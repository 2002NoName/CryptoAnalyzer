#!/usr/bin/env bash
set -euo pipefail

# Generates integration test images for CryptoAnalyzer using Linux tooling.
# Intended to be run inside WSL2.
#
# Output images are written to the provided output directory.
#
# Usage:
#   ./test_assets/wsl/generate_images.sh ./test_assets/generated
#
# Requirements (WSL2):
# - coreutils (dd)
# - util-linux (losetup)
# - parted
# - dosfstools (mkfs.fat)
# - e2fsprogs (mkfs.ext4)
# - sudo privileges (for loop mount) if you want to populate files

OUT_DIR="${1:-}"
if [[ -z "${OUT_DIR}" ]]; then
  echo "Usage: $0 <output_dir>" >&2
  exit 2
fi

mkdir -p "${OUT_DIR}"

IMG="${OUT_DIR}/multi_volume.img"
IMG_SIZE_MIB=64

echo "[1/3] Creating blank image: ${IMG} (${IMG_SIZE_MIB} MiB)"
dd if=/dev/zero of="${IMG}" bs=1M count="${IMG_SIZE_MIB}" status=none

echo "[2/3] Creating MBR partition table with 2 partitions"
parted -s "${IMG}" mklabel msdos
# p1: FAT32 32MiB
parted -s "${IMG}" mkpart primary fat32 1MiB 33MiB
# p2: RAW/unformatted 16MiB
parted -s "${IMG}" mkpart primary 33MiB 49MiB

# Attach loop device with partition scanning
LOOP=""
cleanup() {
  if [[ -n "${LOOP}" ]]; then
    sudo losetup -d "${LOOP}" || true
  fi
}
trap cleanup EXIT

LOOP=$(sudo losetup --find --show --partscan "${IMG}")

echo "[3/3] Formatting partition 1 as FAT32"
# Typically /dev/loopXp1
sudo mkfs.fat -F 32 "${LOOP}p1" > /dev/null

echo "Done: ${IMG}"
echo "Note: Partition 2 is left unformatted intentionally (UNKNOWN FS test)."
