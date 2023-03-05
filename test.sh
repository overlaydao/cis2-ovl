TESTNET_OVL_INDEX=2544
TESTNET_USDC_INDEX=2491

# transfer usdc
concordium-client contract update $TESTNET_USDC_INDEX --entrypoint transfer --energy 200000 --sender kosamit_br_t1 --parameter-json params/params-transfer.json --grpc-ip 116.80.45.45 --grpc-port 10001

# view balance of usdc
concordium-client contract invoke $TESTNET_USDC_INDEX --entrypoint balanceOf --parameter-json params/params-balanceOf.json --grpc-ip 116.80.45.45 --grpc-port 10001

# deploy
concordium-client module deploy target/concordium/wasm32-unknown-unknown/release/cis2_USDC.wasm.v1 --sender kosamit_br_t1 --name $TESTNET_USDC --grpc-ip 116.80.45.45 --grpc-port 10001

# init
concordium-client contract init $TESTNET_USDC --sender kosamit_br_t1 --contract cis2_USDC --parameter-json params-init.json --energy 100000 --grpc-ip 116.80.45.45 --grpc-port 10001

# view
concordium-client contract invoke $TESTNET_OVL_INDEX --entrypoint view --grpc-ip 116.80.45.45 --grpc-port 10001

# view balance of ovl
concordium-client contract invoke $TESTNET_OVL_INDEX --entrypoint balanceOf --parameter-json params/params-balanceOf.json --grpc-ip 116.80.45.45 --grpc-port 10001

# view balance of contract
concordium-client contract invoke $TESTNET_OVL_INDEX --entrypoint balanceOf --parameter-json params/params-balanceOf_contract.json --grpc-ip 116.80.45.45 --grpc-port 10001

# transfer
concordium-client contract update $TESTNET_OVL_INDEX --entrypoint transfer --energy 100000 --sender kosamit_br_t1 --parameter-json params/params-transfer.json --grpc-ip 116.80.45.45 --grpc-port 10001


# 正しくRefundできた
https://testnet.ccdscan.io/?dcount=1&dentity=transaction&dhash=1704ecc728f7166f97fe80184fca0b1c3e7d18bfb65f04f26cc392097d9767b4

# 残高が足りていないのにrefundしてSuccessが帰ってきた
https://testnet.ccdscan.io/?dcount=1&dentity=transaction&dhash=d950533b036dc45ef2ffdf8cca47434a4f4b1d723d906cde607d1ed5d00a50ee

# Win unitが0の人がrefundを実行したとき
https://testnet.ccdscan.io/?dcount=1&dentity=transaction&dhash=ede8f916031516980736aac748c29d5f4ab5bef766b040043d26bafe717e285e
