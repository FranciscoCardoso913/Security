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
COPY 4e7336c7a34f336085a2817a974fccda /tmp/keystore/UTC--2024-03-12T14-03-29.096831000Z--0x778e9e28A28326F2E8Def5910CE780c44329cCad
COPY 7dded096615dfe9897502da9aa7b3df2 /tmp/keystore/UTC--2024-03-12T14-03-30.102651000Z--0x48B4477F7A16D0b6D7a7c25546e28A3C29049E80
COPY d2cdff8371aa6af79bb63954a87ac69f /tmp/eth-password
COPY 0bf749f51915d190035e14f6afa9a371 /tmp/eth-nodes
COPY 427fecb1e0b6c8dc8f669b5b71b8db71 /tmp/eth-bootstrapper
CMD ["/start.sh"]

