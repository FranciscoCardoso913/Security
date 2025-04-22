FROM fe4d2a2cb5156ab9c60b9207246c78d2
ARG DEBIAN_FRONTEND=noninteractive
COPY 082b96ec819c95ae773daebde675ef80 /start.sh
COPY d18858afc6bb66ec3a19d872077acfd2 /seedemu_sniffer
COPY 17ac2d812a99a91e7f747e1defb72a29 /seedemu_worker
RUN chmod +x /start.sh
RUN chmod +x /seedemu_sniffer
RUN chmod +x /seedemu_worker
COPY e01e36443f9f72c6204189260d0bd276 /ifinfo.txt
COPY d3d51fdf7f4bad30dc5db560a01ce629 /interface_setup
COPY f4d556a844298d3911e6d250e4a2d93b /tmp/eth-genesis.json
COPY 1385b4a689e313fd232e072de55649d9 /tmp/keystore/UTC--2024-03-12T14-02-21.091656000Z--0x1be9288F9a7D2F809250f15c487E3a5A9Cf71f4F
COPY b2ee252f9eeba5cf3bf1697e04e7bebf /tmp/keystore/UTC--2024-03-12T14-02-22.076300000Z--0xA403f63AD02a557D5DDCBD5F5af9A7627C591034
COPY d2cdff8371aa6af79bb63954a87ac69f /tmp/eth-password
COPY 0bf749f51915d190035e14f6afa9a371 /tmp/eth-nodes
COPY 427fecb1e0b6c8dc8f669b5b71b8db71 /tmp/eth-bootstrapper
CMD ["/start.sh"]

