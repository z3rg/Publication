#!/bin/bash

echo "running sequence of restore"
echo "==========================="
sudo mount /dev/sda1 /mnt && sudo mkdir -p /mnt/boot/efi && sudo mount /dev/sda2 /mnt/boot/efi && sudo tar -xvJpf /media/ubuntu/DATA/full-backup.tar.xz -C /mnt &&
sudo mkdir -p /mnt/dev /mnt/proc /mnt/sys /mnt/run /mnt/run/lock &&
sudo mount -o bind /dev /mnt/dev &&
sudo mount -o bind /proc /mnt/proc && 
sudo mount -o bind /sys /mnt/sys &&
sudo chroot /mnt /bin/bash &&
grub-install /dev/sda &&
update-grub

echo "writing file /etc/modprobe.d/blacklist-ipmi.conf"
cat > /etc/modprobe.d/blacklist-ipmi.conf << EOL
blacklist ipmi_si
blacklist ipmi_devintf
blacklist ipmi_msghandler
EOL &&
echo "check content of file that created" 
cat /etc/modprobe.d/blacklist-ipmi.conf

exit &&
sudo umount /mnt/boot/efi &&
sudo umount /mnt/{dev,proc,sys} &&
sudo umount /mnt