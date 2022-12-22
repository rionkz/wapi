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
const bs58check = require('bs58check')

//FUNCTIONS
function changePrefix(prefix, extendedKey) {
    const payload = Buffer.concat([prefix, bs58check.decode(extendedKey).slice(4)])
    return bs58check.encode(payload)
  }
  
function check_test() {
    return 'a';
}

function getWallet(privateKey, seed = null, phrase = null, secret = null) {
  let hdPublicKey = privateKey.hdPublicKey;
  let hdMaster = bip32.fromBase58(privateKey.xprivkey);
  let wallet = bitcoin.payments.p2pkh({
    pubkey: hdMaster.publicKey,
    network: bitcoin.networks.bitcoin,
  });
  
  const walletdata = {
            'status' : 0,
        }
  
    if (seed != null && phrase != null && secret != null) {
        
        const root = bip32.fromSeed(seed)
        const coin = root.deriveHardened(84).deriveHardened(0)
        const account = coin.deriveHardened(0)
        const xpub = account.neutered()
        const zpub = changePrefix(Buffer.from('04b24746', 'hex'), xpub.toBase58())
        const zprv = changePrefix(Buffer.from('04b2430c', 'hex'), account.toBase58())
        const masterZprv = changePrefix(Buffer.from('04b2430c', 'hex'), root.toBase58())

            const walletdata = {
              'status' : 1,
              'masterPriv': root.toBase58(),
              'masterZprv': masterZprv,
              'xprv': account.toBase58(),
              'zprv': zprv,
              'xpub': xpub.toBase58(),
              'zpub': zpub
            }
    }
    else {
        const walletdata = {
            'status' : 0,
        }
    }
    
  return {
    phrase: phrase,
    secret: secret,
    private: privateKey,
    public: hdPublicKey,
    wallet: wallet.address,
    walletdata: walletdata,
  };
}

const createTxBitcoin = async (
  privateKey,
  sourceAddress,
  recieverAddress,
  amountToSend
) => {
  const satoshiToSend = amountToSend * 100000000;
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

  fee = transactionSize * 20;
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
  transaction.fee(fee * 20);

  // Sign transaction with your private key
  transaction.sign(privateKey);

  // serialize Transactions
  return transaction.serialize();
};

router.get("/decodetx", async (req, res) => {
    /*

    //var txid = tx.getId();
    bitcoin.script.classifyOutput = require('./node_modules/bitcoinjs-lib/src/classify').output;

    const rawtx = req.query.rawtx;
    
    var tx = bitcoin.Transaction.fromHex(rawtx);
    //var txid = tx.getId();
    var decodeFormat = function(tx){
        var result = {
            txid: tx.getId(),
            version: tx.version,
            locktime: tx.locktime,
        };
        return result;
    }

    var decodeInput = function(tx){
        var result = [];
        tx.ins.forEach(function(input, n){
            var vin = {
                txid: input.hash.reverse().toString('hex'),
                n : input.index,
                script: bitcoin.script.toASM(input.script),
                sequence: input.sequence,
            }
            result.push(vin);
        })
        return result
    }

    var decodeOutput = function(tx, network){

        var format = function(out, n, network){
            var vout = {
                satoshi: out.value,
                value: (1e-8 * out.value).toFixed(8),
                n: n,
                scriptPubKey: {
                    asm: bitcoin.script.toASM(out.script),
                    hex: out.script.toString('hex'),
                    type: bitcoin.script.classifyOutput(out.script),
                    addresses: [],
                },
            };
            switch(vout.scriptPubKey.type){
            case 'pubkeyhash':
            case 'scripthash':
                vout.scriptPubKey.addresses.push(bitcoin.address.fromOutputScript(out.script, network));
                break;
            }
            return vout
        }

        var result = [];
        tx.outs.forEach(function(out, n){
            result.push(format(out, n, network));
        })
        return result
    }


    
    var TxDecoder = module.exports = function(rawtx, network){
        this.tx = bitcoin.Transaction.fromHex(rawtx);
        this.network = network;
        this.format = decodeFormat(this.tx);
        this.inputs = decodeInput(this.tx);
        this.outputs = decodeOutput(this.tx, network);
    }

    TxDecoder.prototype.decode = function(){
        var result = {}
        var self = this;
        Object.keys(self.format).forEach(function(key){
            result[key] = self.format[key]
        })
        result.outputs = self.outputs
        return result;
    } 
    
    var inputs  = decodeInput(tx);
    var outputs = decodeOutput(tx, 'bitcoin');

    res.json({
        inputs: inputs, 
        outputs: outputs
    })
    */
});

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
  res.json({
	phrase: code.phrase,
	wallet: getWallet(code.toHDPrivateKey())
	});
});

// generate wallet with passphrase
router.get("/genWalletWithPass", async (req, res) => {
  //EXAMPLE : http://localhost:3000/api/genWalletWithPass?passphrase={PASSPHRASE}
  let code = new Mnemonic(Mnemonic.Words.ENGLISH);
  res.json({
	phrase: code.phrase,
	wallet: getWallet(code.toHDPrivateKey(req.query.passphrase))
       });
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
  const fingerprint = node.parentFingerprint;
  var private = new bitcore.HDPrivateKey(strng);
  //res.json(node);
  res.json(getWallet(private, seed, req.query.seedPhrase, req.query.passPhrase));
});

//generate bech32 addresses for a given derive path & private key
router.get("/bech32", async (req, res) => {
  //EXAMPLE : http://localhost:3000/api/bech32?path=m/0'/0/0&xPrivateKey={privateKey}
  let hdMaster = bip32.fromBase58(req.query.xPrivateKey);
  let child = hdMaster.derivePath(req.query.path);
  const wallet = bitcoin.payments.p2wpkh({ pubkey: child.publicKey });
  res.json({
    address: wallet.address,
    pubkey: child.publicKey.toString('hex')
  });
  
  /*
   * 
   * 
    const seed = bip39.mnemonicToSeedSync(this.mnemonic, this.passphrase)
    const root = bip32.BIP32Factory(ecc).fromSeed(seed)
    const path = 'm/84\'/0\'/0\'/0/' + index
    const external = root.derivePath(path)
    const { address } = bitcoin.payments.p2wpkh({ pubkey: external.publicKey })
    return {
      address: address,
      publicKey: external.publicKey
    }
   
   */
  
});

// send (broadcast) transaction with custom fee and multiple addresses for a given utxos
router.get("/transactionBroadcast", async (req, res) => {
  //EXAMPLE: http:localhost:3000/api/transactionBroadcast?recieverAddress={}&amountToSend={}&privateKey={}&sourceAddress={}

  const result = await axios({
    method: "POST",
    url: `https://sochain.com/api/v2/send_tx/BTC`,
    data: {
      tx_hex: createTxBitcoin(
        req.query.privateKey,
        req.query.sourceAddress,
        req.query.recieverAddress,
        req.query.amountToSend
      ),
    },
  });

  res.json({
    transaction: result.data.data,
  });
});

// build raw transaction without broadcasting to the network
router.get("/rawTransaction", async (req, res) => {
  //EXAMPLE: http:localhost:3000/api/rawTransaction?recieverAddress={}&amountToSend={}&privateKey={}&sourceAddress={}
  res.json({
    transaction: createTxBitcoin(
      req.query.privateKey,
      req.query.sourceAddress,
      req.query.recieverAddress,
      req.query.amountToSend
    ),
  });
});

module.exports = router;
