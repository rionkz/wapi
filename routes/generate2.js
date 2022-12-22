const express = require("express");
const router = express.Router();
const Mnemonic = require("bitcore-mnemonic");
const bip39 = require("bip39");
const ecc = require("tiny-secp256k1");
const { BIP32Factory } = require("bip32");
// You must wrap a tiny-secp256k1 compatible implementation
const bip32 = BIP32Factory(ecc);
const bitcore = require("bitcore-lib");
const bitcoin = require("bitcoinjs-lib");
const axios = require("axios");

const FEE_RATE = 1.1

//FUNCTIONS
function getWallet(privateKey) {
  let hdPublicKey = privateKey.hdPublicKey;
  let hdMaster = bip32.fromBase58(privateKey.xprivkey);
  let wallet = bitcoin.payments.p2pkh({
    pubkey: hdMaster.publicKey,
    network: bitcoin.networks.bitcoin,
  });
  return {
    private: privateKey,
    public: hdPublicKey,
    wallet: wallet.address,
  };
}

const createTxBitcoin = async (
  privateKey,
  sourceAddress,
  recieverAddress,
  amountToSend
) => {
  const satoshiToSend = parseInt(amountToSend * 1e8);
  let fee = 0;
  let inputCount = 0;
  let outputCount = 2;
  const utxos = await axios.get(
    `https://sochain.com/api/v2/get_tx_unspent/BTC/${sourceAddress}`
  );
  const transaction = new bitcore.Transaction();
  let totalAmountAvailable = 0;

  let inputs = [];
  utxos.data.data.txs.forEach(async (element) => {
    let utxo = {};
    utxo.satoshis = Math.floor(Number(element.value) * 100000000);
    utxo.script = element.script_hex;
    utxo.address = utxos.data.data.address;
    utxo.txId = element.txid;
    utxo.outputIndex = element.output_no;
    totalAmountAvailable += utxo.satoshis;
    inputCount += 1;
    inputs.push(utxo);
  });

  transactionSize = inputCount * 146 + outputCount * 34 + 10 - inputCount;
  // Check if we have enough funds to cover the transaction and the fees assuming we want to pay 20 satoshis per byte

  fee = parseInt(transactionSize * FEE_RATE);
  if (totalAmountAvailable - satoshiToSend - fee < 0) {
    throw new Error("Balance is too low for this transaction");
  }

  //Set transaction input
  transaction.from(inputs);

  // set the recieving address and the amount to send
  transaction.to(recieverAddress, satoshiToSend);

  // Set change address - Address to receive the left over funds after transfer
  transaction.change(sourceAddress);

  //manually set transaction fees: 20 satoshis per byte
  transaction.fee(fee);

  // Sign transaction with your private key
  transaction.sign(privateKey);

  // serialize Transactions
  return transaction.serialize();
};

/**
 * Endpoints to be implemented:
- generate seed phrase for the wallet
- generate wallet without passphrase
- generate wallet with passphrase
- recover wallet using seed phrase with or w/o passphrase
for 'generate' & 'recover' endpoints we should get wallet details:
Master private key, Master zprv, extended account private key, extended account zprv, extended account public key, extended account zpub
- generate bech32 addresses for a given derive path & private key
- send (broadcast) transaction with custom fee and multiple addresses for a given utxos
- build raw transaction without broadcasting to the network
 */

// generate seed phrase for the wallet
router.get("/seedPhrase", async (req, res) => {
  //EXAMPLE : http://localhost:3000/api/seedPhrase
  let code = new Mnemonic(Mnemonic.Words.ENGLISH);
  res.json({
    phrase: code.phrase,
  });
});

// generate wallet without passphrase
router.get("/genWalletWithoutPass", async (req, res) => {
  //EXAMPLE : http://localhost:3000/api/genWalletWithoutPass
  let code = new Mnemonic(Mnemonic.Words.ENGLISH);
  res.json(getWallet(code.toHDPrivateKey()));
});

// generate wallet with passphrase
router.get("/genWalletWithPass", async (req, res) => {
  //EXAMPLE : http://localhost:3000/api/genWalletWithPass?passphrase={PASSPHRASE}
  let code = new Mnemonic(Mnemonic.Words.ENGLISH);
  res.json(getWallet(code.toHDPrivateKey(req.query.passphrase)));
});

//recover wallet using seed phrase with or w/o passphrase
router.get("/recover", async (req, res) => {
  //EXAMPLE : http://localhost:3000/api/recover?seedPhrase=praise you muffin lion enable neck grocery crumble super myself license ghost&passPhrase=pass
  const seed = bip39.mnemonicToSeedSync(
    req.query.seedPhrase,
    req.query.passPhrase
  );
  const node = bip32.fromSeed(seed);
  const strng = node.toBase58();
  var private = new bitcore.HDPrivateKey(strng);
  res.json(getWallet(private));
});

//generate bech32 addresses for a given derive path & private key
router.get("/bech32", async (req, res) => {
  //EXAMPLE : http://localhost:3000/api/bech32?path=m/0'/0/0&xPrivateKey={privateKey}
  let hdMaster = bip32.fromBase58(req.query.xPrivateKey);
  let child = hdMaster.derivePath(req.query.path);
  const wallet = bitcoin.payments.p2wpkh({ pubkey: child.publicKey });
  res.json({
    wallet: wallet.address,
  });
});

// send (broadcast) transaction with custom fee and multiple addresses for a given utxos
router.get("/transactionBroadcast", async (req, res) => {
  //EXAMPLE: http:localhost:3000/api/transactionBroadcast?recieverAddress={}&amountToSend={}&privateKey={}&sourceAddress={}

  try {
    const rawtx = await createTxBitcoin(
      req.query.privateKey,
      req.query.sourceAddress,
      req.query.recieverAddress,
      req.query.amountToSend
    );
    const result = await axios({
      method: "POST",
      url: `https://sochain.com/api/v2/send_tx/BTC`,
      data: {
        tx_hex: rawtx,
      },
    });

    res.json({
      transaction: result.data.data,
    });
  } catch(err) {
    console.error(err)
    const errMessage = err.message ? err.message : 'unknown error'
    return res.status(500).json({ error: errMessage })
  }
});

// build raw transaction without broadcasting to the network
router.get("/rawTransaction", async (req, res) => {
  //EXAMPLE: http:localhost:3000/api/rawTransaction?recieverAddress={}&amountToSend={}&privateKey={}&sourceAddress={}
  try {
    const rawtx = await createTxBitcoin(
      req.query.privateKey,
      req.query.sourceAddress,
      req.query.recieverAddress,
      req.query.amountToSend
    );
    res.json({
      transaction: rawtx,
    });
  } catch(err) {
    console.error(err)
    const errMessage = err.message ? err.message : 'unknown error'
    return res.status(500).json({ error: errMessage });
  }
});

module.exports = router;
