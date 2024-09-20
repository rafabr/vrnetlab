#!/usr/bin/env python3

import datetime
import logging
import os
import re
import signal
import sys
import time

import paramiko
import vrnetlab

STARTUP_CONFIG_FILE = "/config/startup-config.cfg"


def handle_SIGCHLD(signal, frame):
    os.waitpid(-1, os.WNOHANG)


def handle_SIGTERM(signal, frame):
    sys.exit(0)


signal.signal(signal.SIGINT, handle_SIGTERM)
signal.signal(signal.SIGTERM, handle_SIGTERM)
signal.signal(signal.SIGCHLD, handle_SIGCHLD)

TRACE_LEVEL_NUM = 9
logging.addLevelName(TRACE_LEVEL_NUM, "TRACE")


def trace(self, message, *args, **kws):
    # Yes, logger takes its '*args' as 'args'.
    if self.isEnabledFor(TRACE_LEVEL_NUM):
        self._log(TRACE_LEVEL_NUM, message, args, **kws)


logging.Logger.trace = trace


class NE40_vm(vrnetlab.VM):
    def __init__(self, username, password, hostname, conn_mode):
        disk_image = None
        for e in sorted(os.listdir("/")):
            if not disk_image and re.search(".qcow2$", e):
                disk_image = "/" + e

        super(NE40_vm, self).__init__(
            username,
            password,
            disk_image=disk_image,
            ram=2048,
            smp="2",
            driveif="virtio",
        )

        self.hostname = hostname
        self.conn_mode = conn_mode
        self.num_nics = 14
        self.nic_type = "virtio-net-pci"

    def bootstrap_spin(self):
        """This function should be called periodically to do work."""

        if self.spins > 300:
            # too many spins with no result ->  give up
            self.stop()
            self.start()
            return

        (ridx, match, res) = self.tn.expect([b"<HUAWEI>"], 1)

        if match and ridx == 0:  # got a match!
            # run main config!
            self.logger.info("Running bootstrap_config()")
            self.bootstrap_config()
            self.startup_config()
            time.sleep(1)
            # close telnet connection
            self.tn.close()
            # startup time?
            startup_time = datetime.datetime.now() - self.start_time
            self.logger.info("Startup complete in: %s" % startup_time)
            # mark as running
            self.running = True
            return

        time.sleep(5)

        # no match, if we saw some output from the router it's probably
        # booting, so let's give it some more time
        if res != b"":
            self.logger.trace("OUTPUT: %s" % res.decode())
            # reset spins if we saw some output
            self.spins = 0

        self.spins += 1

        return

    def bootstrap_config(self):
        """Do the actual bootstrap config"""
        self.wait_write(cmd="mmi-mode enable", wait=None)
        self.wait_write(cmd="system-view", wait=">")
        self.wait_write(cmd=f"sysname {self.hostname}", wait="]")

        self.wait_write(cmd="ip vpn-instance __MGMT_VPN__", wait="]")
        self.wait_write(cmd="ipv4-family", wait="]")
        self.wait_write(cmd="quit", wait="]")
        self.wait_write(cmd="quit", wait="]")
        self.wait_write(cmd="interface GigabitEthernet 0/0/0", wait="]")
        self.wait_write(cmd="ip binding vpn-instance __MGMT_VPN__", wait="]")
        self.wait_write(cmd="ip address 10.0.0.15 24", wait="]")
        self.wait_write(cmd="quit", wait="]")
        self.wait_write(
            cmd="ip route-static vpn-instance __MGMT_VPN__ 0.0.0.0 0 10.0.0.2", wait="]"
        )

        self.wait_write(cmd="undo user-security-policy enable", wait="]")

        self.wait_write(cmd="aaa", wait="]")
        self.wait_write(
            cmd=f"local-user {self.username} password irreversible-cipher {self.password}",
            wait="]",
        )
        self.wait_write(cmd=f"local-user {self.username} service-type ssh", wait="]")
        self.wait_write(
            cmd=f"local-user {self.username} user-group manage-ug", wait="]"
        )
        self.wait_write(cmd="quit", wait="]")

        # SSH
        self.wait_write(cmd="user-interface vty 0 4", wait="]")
        self.wait_write(cmd="authentication-mode aaa", wait="]")
        self.wait_write(cmd="protocol inbound ssh", wait="]")
        self.wait_write(cmd="quit", wait="]")
        self.wait_write(
            cmd=f"ssh user {self.username} authentication-type password ", wait="]"
        )
        self.wait_write(cmd=f"ssh user {self.username} service-type all ", wait="]")
        self.wait_write(cmd="stelnet server enable", wait="]")

        # NETCONF
        self.wait_write(cmd="snetconf server enable", wait="]")
        self.wait_write(cmd="netconf", wait="]")
        self.wait_write(cmd="protocol inbound ssh port 830", wait="]")
        self.wait_write(cmd="quit", wait="]")

        # Error: The system is busy in building configuration. Please wait for a moment...
        while True:
            self.wait_write(cmd="commit", wait=None)
            (idx, match, res) = self.tn.expect([rb"\[~"], 1)
            if match and idx == 0:
                break
            time.sleep(5)

        self.wait_write(cmd="return", wait=None)

    def startup_config(self):
        if not os.path.exists(STARTUP_CONFIG_FILE):
            self.logger.trace(f"Startup config file {STARTUP_CONFIG_FILE} not found")
            self.wait_write(cmd="undo mmi-mode enable", wait=None)
            return

        self.wait_write(cmd="system-view", wait=None)
        self.wait_write(
            cmd=f"ssh user {self.username} sftp-directory cfcard:", wait="]"
        )
        self.wait_write(cmd="sftp server enable", wait="]")
        self.wait_write(cmd="commit", wait="]")
        time.sleep(2)

        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(
            hostname="localhost", username=self.username, password=self.password
        )
        sftp_client = ssh_client.open_sftp()

        sftp_client.put(STARTUP_CONFIG_FILE, "containerlab.cfg")
        print(f"File '{STARTUP_CONFIG_FILE}' successfully transferred")

        sftp_client.close()
        ssh_client.close()

        self.wait_write(cmd=f"undo ssh user {self.username} sftp-directory", wait="]")
        self.wait_write(cmd="undo sftp server enable", wait="]")
        self.wait_write(cmd="commit", wait="]")

        self.wait_write(cmd="load configuration file containerlab.cfg merge", wait="]")
        self.wait_write(cmd="commit", wait="]")
        self.wait_write(cmd="return", wait="]")
        self.wait_write(cmd="undo mmi-mode enable", wait=">")

    def gen_mgmt(self):
        """Generate qemu args for the mgmt interface(s)"""
        res = []
        # mgmt interface is special - we use qemu user mode network
        res.append("-device")
        mac = (
            "c0:00:01:00:ca:fe"
            if getattr(self, "_static_mgmt_mac", False)
            else vrnetlab.gen_mac(0)
        )
        res.append(self.nic_type + f",netdev=p00,mac={mac}")
        res.append("-netdev")
        res.append(
            "user,id=p00,net=10.0.0.0/24,"
            "hostfwd=tcp:0.0.0.0:22-10.0.0.15:22,"  # ssh
            "hostfwd=udp:0.0.0.0:161-10.0.0.15:161,"  # snmp
            "hostfwd=tcp:0.0.0.0:830-10.0.0.15:830,"  # netconf
            "hostfwd=tcp:0.0.0.0:80-10.0.0.15:80,"  # http
            "hostfwd=tcp:0.0.0.0:443-10.0.0.15:443,"  # https
        )

        # Creates required dummy interface
        res.append(f"-device virtio-net-pci,netdev=dummy,mac={vrnetlab.gen_mac(0)}")
        res.append("-netdev tap,ifname=vrp-dummy,id=dummy,script=no,downscript=no")

        return res


class NE40(vrnetlab.VR):
    def __init__(self, hostname, username, password, conn_mode):
        super(NE40, self).__init__(username, password)
        self.vms = [NE40_vm(username, password, hostname, conn_mode)]


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="")
    parser.add_argument(
        "--trace", action="store_true", help="enable trace level logging"
    )
    parser.add_argument("--hostname", default="vr-ne40", help="Router hostname")
    parser.add_argument("--username", default="vrnetlab", help="Username")
    parser.add_argument("--password", default="VR-netlab9", help="Password")
    parser.add_argument(
        "--connection-mode",
        default="tc",
        help="Connection mode to use in the datapath",
    )

    args = parser.parse_args()

    LOG_FORMAT = "%(asctime)s: %(module)-10s %(levelname)-8s %(message)s"
    logging.basicConfig(format=LOG_FORMAT)
    logger = logging.getLogger()

    logger.setLevel(logging.DEBUG)

    if args.trace:
        logger.setLevel(1)

    vr = NE40(
        args.hostname, args.username, args.password, conn_mode=args.connection_mode
    )
    vr.start()
