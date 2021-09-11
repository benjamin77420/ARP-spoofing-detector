from scapy.all import Ether, ARP, srp, sniff, conf
from tkinter import *
import win32api
import win32con
import win32evtlog
import win32security
import win32evtlogutil
import subprocess


def disable_network_adapter():
    """
    closing the network adapter of the machine so it will prevent any leak of sensitive data
    """
    completed = subprocess.run(["powershell", "-Command", "Disable-NetAdapter -Name Wi-Fi -Confirm:$false"])



def write_ARP_spoofing_attempt(real_mac, fake_mac):
    """
    creating a log file that will note when the attack was made on the machine
    :param real_mac: the real mach of the owner to which the suspected packet belong too
    :param fake_mac: the fake mac address that was impersonating to be the router
    :return:
    """
    ph = win32api.GetCurrentProcess()
    th = win32security.OpenProcessToken(ph, win32con.TOKEN_READ)
    my_sid = win32security.GetTokenInformation(th, win32security.TokenUser)[0]

    applicationName = "ARP spoofer detector"
    eventID = 7000
    category = 4
    myType = win32evtlog.EVENTLOG_WARNING_TYPE
    descr = ["A warning", f"An attempt of a MITM attack was detected fake MAC{fake_mac}",
             f"the real MAC of the suspected ip is {real_mac}"]
    data = "ARP spoofer detector\0data".encode("ascii")

    win32evtlogutil.ReportEvent(applicationName, eventID, eventCategory=category,
                                eventType=myType, strings=descr, data=data, sid=my_sid)


def alert_popup(title, message):
    """Generate a pop-up window for special messages."""
    root = Tk()
    root.title(title)
    w = 400  # popup window width
    h = 200  # popup window height
    sw = root.winfo_screenwidth()
    sh = root.winfo_screenheight()
    x = (sw - w) / 2
    y = (sh - h) / 2
    root.geometry('%dx%d+%d+%d' % (w, h, x, y))
    m = message
    m += '\n'
    w = Label(root, text=m, width=120, height=10)
    w.pack()
    b = Button(root, text="OK", command=root.destroy, width=10)
    b.pack()
    mainloop()


def get_mac(ip):
    """
    Returns the MAC address of `ip`, if it is unable to find it
    for some reason, throws `IndexError`
    """
    p = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip)
    result = srp(p, timeout=3, verbose=False)[0]
    return result[0][1].hwsrc


def process(packet):
    # if the packet is an ARP packet
    if packet.haslayer(ARP):
        # if it is an ARP response (ARP reply)
        if packet[ARP].op == 2:
            try:
                # get the real MAC address of the sender
                real_mac = get_mac(packet[ARP].psrc)
                # get the MAC address from the packet sent to us
                response_mac = packet[ARP].hwsrc
                # if they're different, definitely there is an attack
                if real_mac != response_mac:
                    print(f"[!] You are under attack, REAL-MAC: {real_mac.upper()}, FAKE-MAC: {response_mac.upper()}")
                    disable_network_adapter()  # disabling the network adaptor that is under attack
                    alert_popup(title, message)  # call on the prompt for the user to see
                    write_ARP_spoofing_attempt(real_mac.upper(), response_mac.upper()) # register the attack in the windows event logs for the forensics team
            except IndexError:
                # unable to find the real mac
                # may be a fake IP or firewall is blocking packets
                pass


title = "arp poisoning attack detection"
message = "Hello, the ARP table was poisoned please contact support ASAP, the internet adaptor is disconnected of safety"
sniff(store=False, prn=process)
