#!/usr/bin/env bash
#
# setup-uz801-vm.sh
#
# Interactive KVM/QEMU + libvirt + virt-manager setup
# with optional dedicated USB-controller PCI passthrough via VFIO.
#
# Target: Debian / Debian-based systems
#
# WARNING:
# Passing a USB controller through VFIO removes that controller
# from the host. Every USB port belonging to that controller
# becomes unavailable to the host while the VM owns it.
#

set -Eeuo pipefail

SCRIPT_NAME="$(basename "$0")"

die() {
    echo
    echo "[!] ERROR: $*" >&2
    exit 1
}

info() {
    echo "[*] $*"
}

ok() {
    echo "[+] $*"
}

warn() {
    echo "[!] $*"
}

pause() {
    read -rp "Press ENTER to continue..." _
}

require_root() {
    [[ "${EUID}" -eq 0 ]] || die "Run this script with sudo/root."
}

confirm() {
    local answer
    read -rp "$1 [y/N]: " answer
    [[ "$answer" =~ ^[Yy]$ ]]
}

banner() {
    clear
    cat <<'EOF'

===============================================================
             UZ801 USB RESEARCH VM SETUP
===============================================================

This installer configures:

  - QEMU/KVM
  - libvirt
  - virt-manager
  - OVMF/UEFI
  - VFIO
  - optional PCI USB-controller passthrough

Intended architecture:

                    HOST
                      |
                      | VFIO
                      v
              +---------------+
              | USB Controller|
              +-------+-------+
                      |
                      | physical USB
                      v
                   UZ801
                      |
                      v
                     VM
                      |
              +-------+-------+
              | adb / fastboot|
              | Linux tooling |
              +---------------+

The host must NOT use the USB controller selected for VFIO.

===============================================================

EOF
}

detect_distro() {
    [[ -f /etc/os-release ]] || die "/etc/os-release not found."

    . /etc/os-release

    info "Detected OS: ${PRETTY_NAME:-unknown}"

    if [[ "${ID:-}" != "debian" && "${ID_LIKE:-}" != *debian* ]]; then
        warn "This script is designed primarily for Debian-based systems."
        confirm "Continue anyway?" || exit 0
    fi
}

install_packages() {
    info "Installing virtualization packages..."

    apt-get update

    apt-get install -y \
        qemu-system-x86 \
        qemu-utils \
        qemu-kvm \
        libvirt-daemon-system \
        libvirt-clients \
        virt-manager \
        ovmf \
        bridge-utils \
        cpu-checker \
        pciutils \
        usbutils \
        lshw \
        dnsmasq-base \
        swtpm \
        swtpm-tools \
        gir1.2-spiceclientgtk-3.0

    ok "Virtualization packages installed."
}

configure_user() {
    local target_user="${SUDO_USER:-}"

    if [[ -z "$target_user" || "$target_user" == "root" ]]; then
        warn "Could not determine the non-root login user."
        read -rp "Enter your Linux username: " target_user
    fi

    if ! id "$target_user" &>/dev/null; then
        die "User '$target_user' does not exist."
    fi

    info "Adding '$target_user' to virtualization groups..."

    usermod -aG libvirt "$target_user"
    usermod -aG kvm "$target_user"

    ok "User groups configured."
    echo
    echo "You will need to log out/in before group membership is refreshed."
}

check_kvm() {
    echo
    info "Checking KVM..."

    if [[ -e /dev/kvm ]]; then
        ok "/dev/kvm exists."
    else
        warn "/dev/kvm does not exist."

        if command -v kvm-ok &>/dev/null; then
            kvm-ok || true
        fi

        warn "KVM may be disabled in firmware."
    fi
}

detect_cpu_vendor() {
    if grep -qi 'GenuineIntel' /proc/cpuinfo; then
        CPU_VENDOR="intel"
    elif grep -qi 'AuthenticAMD' /proc/cpuinfo; then
        CPU_VENDOR="amd"
    else
        CPU_VENDOR="unknown"
    fi

    info "CPU vendor: ${CPU_VENDOR}"
}

check_iommu() {
    echo
    info "Checking IOMMU support..."

    local cmdline
    cmdline="$(cat /proc/cmdline)"

    if grep -qw 'intel_iommu=on' <<< "$cmdline" ||
       grep -qw 'amd_iommu=on' <<< "$cmdline" ||
       grep -qw 'iommu=on' <<< "$cmdline"; then
        ok "IOMMU kernel parameter appears to be active."
        return
    fi

    warn "No explicit IOMMU kernel parameter detected."

    case "$CPU_VENDOR" in
        intel)
            IOMMU_PARAM="intel_iommu=on iommu=pt"
            ;;
        amd)
            IOMMU_PARAM="amd_iommu=on iommu=pt"
            ;;
        *)
            warn "Unknown CPU vendor."
            IOMMU_PARAM=""
            ;;
    esac

    [[ -n "${IOMMU_PARAM:-}" ]] || return

    echo
    echo "Recommended kernel parameters:"
    echo
    echo "    $IOMMU_PARAM"
    echo

    if confirm "Add these parameters to GRUB?"; then
        configure_grub_iommu
    else
        warn "IOMMU configuration skipped."
    fi
}

configure_grub_iommu() {
    local grub_file="/etc/default/grub"

    [[ -f "$grub_file" ]] || die "$grub_file not found."

    cp -a "$grub_file" "${grub_file}.backup.$(date +%Y%m%d-%H%M%S)"

    if grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=' "$grub_file"; then
        sed -i \
            "s/^GRUB_CMDLINE_LINUX_DEFAULT=\"\(.*\)\"/GRUB_CMDLINE_LINUX_DEFAULT=\"\1 ${IOMMU_PARAM}\"/" \
            "$grub_file"
    else
        echo "GRUB_CMDLINE_LINUX_DEFAULT=\"${IOMMU_PARAM}\"" >> "$grub_file"
    fi

    update-grub

    ok "GRUB updated."
    warn "A reboot is required before IOMMU becomes active."
}

show_iommu_groups() {
    echo
    echo "==============================================================="
    echo " IOMMU GROUPS"
    echo "==============================================================="
    echo

    local groups
    groups="$(find /sys/kernel/iommu_groups/ -type l 2>/dev/null | sort -V)"

    if [[ -z "$groups" ]]; then
        warn "No IOMMU groups found."
        return 1
    fi

    while read -r path; do
        local group
        group="$(basename "$(dirname "$(dirname "$path")")")"

        local device
        device="$(basename "$path")"

        printf "Group %-4s  %s\n" \
            "${group}" \
            "$(lspci -nn -s "$device" 2>/dev/null || echo "$device")"
    done <<< "$groups"

    echo
}

list_usb_controllers() {
    echo
    echo "==============================================================="
    echo " USB CONTROLLERS"
    echo "==============================================================="
    echo

    mapfile -t CONTROLLERS < <(
        lspci -Dnnd ::0c03 2>/dev/null |
        awk '{print $1}'
    )

    if [[ "${#CONTROLLERS[@]}" -eq 0 ]]; then
        warn "No USB PCI controllers found."
        return 1
    fi

    local i=0

    for pci in "${CONTROLLERS[@]}"; do
        echo "[$i] $pci"
        lspci -nn -s "$pci"
        echo

        ((i+=1))
    done

    return 0
}

controller_iommu_group() {
    local pci="$1"

    local path="/sys/bus/pci/devices/0000:${pci}/iommu_group"

    if [[ -L "$path" ]]; then
        basename "$(readlink "$path")"
    else
        echo "NONE"
    fi
}

show_controller_group() {
    local pci="$1"
    local group

    group="$(controller_iommu_group "$pci")"

    echo
    echo "Selected controller:"
    lspci -nn -s "$pci"

    echo
    echo "IOMMU group: $group"

    [[ "$group" != "NONE" ]] || {
        warn "Controller has no visible IOMMU group."
        return
    }

    echo
    echo "Devices sharing this IOMMU group:"
    echo

    for dev in /sys/kernel/iommu_groups/"$group"/devices/*; do
        [[ -e "$dev" ]] || continue

        local id
        id="$(basename "$dev")"

        lspci -nn -s "$id" || true
    done

    echo
}

select_usb_controller() {
    list_usb_controllers || return

    echo
    read -rp "Select USB controller number: " choice

    [[ "$choice" =~ ^[0-9]+$ ]] ||
        die "Invalid controller selection."

    [[ "$choice" -lt "${#CONTROLLERS[@]}" ]] ||
        die "Controller selection out of range."

    SELECTED_PCI="${CONTROLLERS[$choice]}"

    show_controller_group "$SELECTED_PCI"

    echo
    warn "THIS CONTROLLER WILL DISAPPEAR FROM THE HOST."

    if ! confirm "Use ${SELECTED_PCI} for VM passthrough?"; then
        warn "Controller selection cancelled."
        SELECTED_PCI=""
        return
    fi
}

check_group_safety() {
    local pci="$1"
    local group

    group="$(controller_iommu_group "$pci")"

    [[ "$group" != "NONE" ]] || {
        warn "Cannot verify IOMMU isolation."
        return
    }

    mapfile -t devices < <(
        find "/sys/kernel/iommu_groups/${group}/devices" \
            -mindepth 1 \
            -maxdepth 1 \
            -type l |
        xargs -r -n1 basename
    )

    echo
    echo "IOMMU group ${group} contains:"
    echo

    local unsafe=0

    for dev in "${devices[@]}"; do
        lspci -nn -s "$dev"

        if [[ "$dev" != "$pci" ]]; then
            unsafe=1
        fi
    done

    echo

    if [[ "$unsafe" -eq 1 ]]; then
        warn "The USB controller shares its IOMMU group with other PCI devices."
        warn "This means isolation is NOT as clean as a single-device group."

        confirm "Continue anyway?" || die "Aborted."
    else
        ok "USB controller has an isolated IOMMU group."
    fi
}

configure_vfio_modules() {
    info "Configuring VFIO modules..."

    cat > /etc/modules-load.d/vfio.conf <<'EOF'
vfio
vfio_pci
vfio_iommu_type1
EOF

    modprobe vfio
    modprobe vfio_pci
    modprobe vfio_iommu_type1

    ok "VFIO modules configured."
}

configure_vfio_controller() {
    local pci="$1"

    local vendor_device
    vendor_device="$(lspci -n -s "$pci" | awk '{print $3}')"

    [[ "$vendor_device" =~ ^[0-9a-fA-F]{4}:[0-9a-fA-F]{4}$ ]] ||
        die "Could not determine PCI vendor/device ID."

    local vendor="${vendor_device%%:*}"
    local device="${vendor_device##*:}"

    echo
    echo "PCI device:"
    echo "  $pci"
    echo
    echo "Vendor: $vendor"
    echo "Device: $device"
    echo

    warn "The following configuration causes this PCI device"
    warn "to be claimed by vfio-pci instead of its normal driver."

    if ! confirm "Create persistent VFIO binding?"; then
        warn "VFIO binding skipped."
        return
    fi

    cat > /etc/modprobe.d/vfio-pci.conf <<EOF
# UZ801 research USB controller
options vfio-pci ids=${vendor}:${device}
EOF

    cat > /etc/modprobe.d/vfio.conf <<'EOF'
softdep xhci_pci pre: vfio-pci
softdep xhci_hcd pre: vfio-pci
EOF

    ok "VFIO PCI binding configuration written."

    update-initramfs -u

    ok "initramfs regenerated."

    echo
    warn "A reboot is required for persistent controller binding."
}

create_vm_directory() {
    VM_DIR="/var/lib/libvirt/images/uz801-research"

    mkdir -p "$VM_DIR"

    ok "VM directory: $VM_DIR"
}

create_vm_disk() {
    local disk="${VM_DIR}/uz801-research.qcow2"

    if [[ -f "$disk" ]]; then
        warn "VM disk already exists:"
        echo "  $disk"
        return
    fi

    echo
    read -rp "VM disk size [default: 32G]: " size
    size="${size:-32G}"

    qemu-img create -f qcow2 "$disk" "$size"

    ok "Created $disk"
}

create_libvirt_xml() {
    local pci="$1"

    local domain="${VM_DIR}/uz801-research.xml"

    local bus
    local slot
    local function

    bus="$(cut -d: -f1 <<< "$pci")"
    local rest="${pci#*:}"
    slot="$(cut -d. -f1 <<< "$rest")"
    function="$(cut -d. -f2 <<< "$rest")"

    cat > "$domain" <<EOF
<domain type='kvm'>
  <name>uz801-research</name>
  <memory unit='GiB'>4</memory>
  <currentMemory unit='GiB'>4</currentMemory>

  <vcpu placement='static'>4</vcpu>

  <os firmware='efi'>
    <type arch='x86_64'>hvm</type>
  </os>

  <features>
    <acpi/>
    <apic/>
  </features>

  <cpu mode='host-passthrough'/>

  <clock offset='utc'/>

  <devices>

    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='${VM_DIR}/uz801-research.qcow2'/>
      <target dev='vda' bus='virtio'/>
    </disk>

    <interface type='network'>
      <source network='default'/>
      <model type='virtio'/>
    </interface>

    <controller type='usb' model='qemu-xhci'/>

    <hostdev mode='subsystem' type='pci' managed='yes'>
      <source>
        <address
          domain='0x0000'
          bus='0x${bus}'
          slot='0x${slot}'
          function='0x${function}'/>
      </source>
    </hostdev>

    <graphics type='spice' autoport='yes'/>

    <video>
      <model type='virtio'/>
    </video>

    <channel type='spicevmc'>
      <target type='virtio' name='com.redhat.spice.0'/>
    </channel>

  </devices>
</domain>
EOF

    ok "libvirt XML generated:"
    echo "  $domain"
}

define_libvirt_vm() {
    local xml="${VM_DIR}/uz801-research.xml"

    if virsh dominfo uz801-research &>/dev/null; then
        warn "VM 'uz801-research' already exists."
        return
    fi

    virsh define "$xml"

    ok "VM registered with libvirt."
}

install_adb_tools() {
    echo
    if confirm "Install ADB/Fastboot tools on the HOST?"; then
        apt-get install -y adb fastboot
        ok "ADB/Fastboot installed."
    else
        info "Skipping host ADB/Fastboot."
    fi

    echo
    echo "NOTE:"
    echo "ADB should ultimately be installed INSIDE the research VM."
}

show_post_install() {
    cat <<'EOF'


===============================================================
 SETUP SUMMARY
===============================================================

The virtualization stack has been configured.

VM:

    uz801-research

Inspect:

    virsh list --all
    virsh dominfo uz801-research

Start:

    virsh start uz801-research

Open virt-manager:

    virt-manager

===============================================================
 IMPORTANT
===============================================================

If a PCI USB controller was bound to VFIO:

    The host loses access to that controller.

After reboot, verify:

    lspci -nnk

Look for:

    Kernel driver in use: vfio-pci

Then start the VM.

Inside the VM:

    lsusb
    adb devices
    adb shell

For USB diagnostics:

    lsusb -t
    dmesg -w

===============================================================

If the UZ801 does NOT appear inside the VM, DO NOT immediately
change random VFIO settings.

First inspect:

    virsh dumpxml uz801-research

and:

    lspci -nnk

===============================================================

EOF
}

main() {
    banner
    require_root
    detect_distro

    echo
    if ! confirm "Install/configure the virtualization environment?"; then
        exit 0
    fi

    install_packages
    configure_user
    check_kvm
    detect_cpu_vendor
    check_iommu

    echo
    warn "If you just enabled IOMMU in GRUB, reboot now."
    warn "After reboot, run this script again."

    if [[ ! -d /sys/kernel/iommu_groups ]]; then
        warn "IOMMU groups directory does not exist."
        exit 0
    fi

    if ! find /sys/kernel/iommu_groups/ -type l 2>/dev/null | grep -q .; then
        warn "No IOMMU groups currently detected."
        warn "A reboot may be required."
        exit 0
    fi

    show_iommu_groups || true

    select_usb_controller || exit 0

    [[ -n "${SELECTED_PCI:-}" ]] ||
        die "No USB controller selected."

    check_group_safety "$SELECTED_PCI"

    configure_vfio_modules

    echo
    if confirm "Configure persistent VFIO binding for this controller?"; then
        configure_vfio_controller "$SELECTED_PCI"

        echo
        warn "Because the controller binding is persistent, reboot is required."
        echo
    else
        warn "Skipping persistent VFIO binding."
        warn "VM creation will still be possible, but controller ownership"
        warn "may need to be handled manually."
    fi

    create_vm_directory
    create_vm_disk

    create_libvirt_xml "$SELECTED_PCI"
    define_libvirt_vm

    install_adb_tools

    show_post_install
}

main "$@"
