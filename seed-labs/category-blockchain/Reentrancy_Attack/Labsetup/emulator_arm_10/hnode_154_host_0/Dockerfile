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
COPY 32ba6b777cabbef37e1db08d9a5b4b14 /tmp/keystore/UTC--2024-03-12T14-02-28.979590000Z--0x72943017A1fa5f255fC0f06625Aec22319FCd5b3
COPY 6a55d5e5fd59cf788c9f39f8cdc3ef6f /tmp/keystore/UTC--2024-03-12T14-02-30.002120000Z--0xceEfd2C2bf4F9a3BEE8c7630282d968c32CF8552
COPY d2cdff8371aa6af79bb63954a87ac69f /tmp/eth-password
COPY 0bf749f51915d190035e14f6afa9a371 /tmp/eth-nodes
COPY 427fecb1e0b6c8dc8f669b5b71b8db71 /tmp/eth-bootstrapper
CMD ["/start.sh"]

