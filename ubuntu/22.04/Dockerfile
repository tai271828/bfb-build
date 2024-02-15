#  docker build -t bfb_runtime_ubuntu22.04 -f Dockerfile .
FROM scratch
Add jammy-server-cloudimg-arm64-root.tar.xz /
ADD qemu-aarch64-static /usr/bin/

ARG BASE_URL
ARG DOCA_VERSION
ARG BSP_VERSION
ARG DISTRO
ARG DISTRO_VERSION
WORKDIR /root/workspace
ADD install.sh .
ADD create_bfb .
ADD build_ubuntu_bfb .
ADD mlxbf-bootimages.deb .

ENV DEBIAN_FRONTEND=noninteractive
ENV FLASH_KERNEL_SKIP=yes
ENV RUN_FW_UPDATER=no

# Avoid running flash-kernel post install
RUN mkdir -p /run/systemd; echo docker > /run/systemd/container

RUN apt update
RUN apt upgrade -y
RUN apt remove --purge -y snapd plymouth
RUN apt autoremove -y
RUN apt install -y grub-efi-arm64-signed grub-efi-arm64-bin shim-signed watchdog binutils sbsigntool rasdaemon net-tools nfs-common iptables-persistent rsync tcpdump nvme-cli iputils-arping iputils-ping iputils-tracepath bridge-utils iperf3 bc lm-sensors ifenslave acpid network-manager kexec-tools i2c-tools dc lldpad unzip ipmitool sysstat mmc-utils libhugetlbfs-bin uuid ntp libgdbm-dev jq libev4

# Copy boot bits from rootfs to EFI partition
RUN mkdir -p /boot/efi/EFI/ubuntu/; \
	cp /usr/lib/grub/arm64-efi-signed/grubaa64.efi.signed \
	/boot/efi/EFI/ubuntu/grubaa64.efi; \
	cp /usr/lib/grub/arm64-efi-signed/grubnetaa64.efi.signed \
	/boot/efi/EFI/ubuntu/grubnetaa64.efi; \
	cp /usr/lib/shim/shimaa64.efi.signed \
	/boot/efi/EFI/ubuntu/shimaa64.efi; \
	cp /usr/lib/shim/mmaa64.efi \
	   /usr/lib/shim/BOOTAA64.CSV \
	/boot/efi/EFI/ubuntu/; \
	mkdir -p /boot/efi/EFI/BOOT; \
	cp /usr/lib/shim/shimaa64.efi.signed \
	/boot/efi/EFI/BOOT/BOOTAA64.EFI; \
	cp /usr/lib/shim/mmaa64.efi \
	   /usr/lib/shim/fbaa64.efi \
	/boot/efi/EFI/BOOT/

RUN sed -i -e "s/signed/@IMAGE_TYPE@@CUSTOM_VERSION@/" -e "s/prod/@IMAGE_TYPE@@CUSTOM_VERSION@/" /etc/mlnx-release

CMD ["bash", "-x", "/root/workspace/build_ubuntu_bfb"]
