import argparse

from scapy.sendrecv import AsyncSniffer

from flow_session import generate_session_class


def create_sniffer(input_interface, output_mode, output_file, url_model=None):

    NewFlowSession = generate_session_class(output_mode, output_file, url_model)

    return AsyncSniffer(
        iface=input_interface,
        filter="ip and (tcp or udp)",
        prn=None,
        session=NewFlowSession,
        store=False,
    )


def main():

    sniffer = create_sniffer(
        "Ethernet",
        "flow",
        "flow_modified",
        "",
    )
    sniffer.start()

    try:
        sniffer.join()
    except KeyboardInterrupt:
        sniffer.stop()
    finally:
        sniffer.join()


if __name__ == "__main__":
    main()
