# Accessing the DPT-RP1 over USB in Linux

To use the DPT-RP1 through the USB cable, you need to perform two steps:

  1. Switch the USB mode for DPT-RP1 to Ethernet-over-USB.
  2. Determine the IPv6 link-local address for `digitalpaper.local` using mDNS.

## Switching the USB mode the Ethernet-over-USB.

When the DPT-RP1 is plugged into a USB port, it appears as a USB CDC ACM device (i.e. a serial port), usually at `/dev/ttyACM0`.

By sending a sequence of bytes to this serial port, the DPT-RP1 mode can be switched to Ethernet-over-USB.

The DPT-RP1 supports two protocols for Ethernet-over-USB : remote NDIS (RNDIS) for Windows machines, and USB CDC/ECM for Macs. Linux supports both these modes. 

You only need to enable one of these modes.

### Activating RNDIS mode

To activate RNDIS mode, send the following Python byte sequence to `/dev/ttyACM0` using [pyserial](https://pythonhosted.org/pyserial/) for example.

    b"\x01\x00\x00\x01\x00\x00\x00\x01\x00\x04"

Check the output of `dmesg` to verify this worked:
    
    rndis_host 2-1:1.0 usb0: register 'rndis_host' at usb-0000:00:14.0-1, RNDIS device, xx:xx:xx:xx:xx:xx
    
where `xx:xx:xx:xx:xx:xx` is the Ethernet address for the DPT-RP1.

### Activating CDC/ECM mode

To activate CDC/ECM mode, send the following alternative Python byte sequence:

    b"\x01\x00\x00\x01\x00\x00\x00\x01\x01\x04"

The `dmesg` command will show:

    cdc_ether 2-1:1.0 usb0: register 'cdc_ether' at usb-0000:00:14.0-1, CDC Ethernet Device, xx:xx:xx:xx:xx:xx

## De-activate DHCP on the new Ethernet device

If you're using DHCP to obtain addresses, you should disable it for the DPT-RP1, since the DPT-RP1 does not run a DHCP server. 

For example, if you're using Network Manager, change the IPv4 settings on the DPT-RP1 Ethernet device to 'Link-Local Only' instead of 'Automatic'. This will assign your end of the Ethernet link an IPv4 link-local address in the 169.254.0.0/16 range. 

## Determining the address for DPT-RP1

The DPT-RP1 uses an IPv6 link-local address when in Ethernet-over-USB. You can determine this address by using an mDNS resolver such as `avahi`.

    $ avahi-resolve -n digitalpaper.local
    digitalpaper.local	fe80::xxxx:xxxx:xxxx:xxxx

Although this returns the IPv6 link-local address, at least on my system, this address is incomplete. IPv6 link-local addresses need a scope identifier which identifies the network interface (i.e. link). On my system, the DPT-RP1 Ethernet device appears as `usb0` (from the output of `ifconfig`), and therefore the full address is:

    fe80::xxxx:xxxx:xxxx:xxxx%usb0

The full URI for the DPT-RP1 would be:

    https://[fe80::xxxx:xxxx:xxxx:xxxx%usb0]:8443/...

This syntax is accepted by urllib3 v1.22 and above.




