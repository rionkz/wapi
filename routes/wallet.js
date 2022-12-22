const crypto = require('crypto')
const bip39 = require('bip39')
const bip32 = require('bip32')
const bs58check = require('bs58check')
const ecc = require('tiny-secp256k1')
const bitcoin = require('bitcoinjs-lib')
const { Blockstream } = require('./network/network')

const DEFAULT_ENTROPY_LENGTH = 128

// Limit for P2WPKH outputs.
// See: https://bitcoin.stackexchange.com/questions/10986/what-is-meant-by-bitcoin-dust
const DUST_THRESHOLD = 294

const BITCOIN = {
  messagePrefix: '\x18Bitcoin Signed Message:\n',
  bech32: 'bc',
  bip32: {
    public: 0x04b24746,
    private: 0x04b2430c,
  },
  pubKeyHash: 0x00,
  scriptHash: 0x05,
  wif: 0x80,
}

class BitcoinWallet {
  constructor(mnemonic = null, passphrase = '', networkInterface = null) {
    if (!mnemonic) {
      mnemonic = BitcoinWallet.generateMnemonic()
    }
    this.mnemonic = mnemonic
    this.passphrase = passphrase
    if (!networkInterface) {
      const seed = bip39.mnemonicToSeedSync(this.mnemonic, this.passphrase)
      this.networkInterface = new Blockstream({ seed: seed })
    } else {
      this.networkInterface = networkInterface
    }
  }

  /**
   * Generates a new BIP-39 mnemonic
   * @param {Number} entropyLength - Length of the desired entropy
   */
  static generateMnemonic(entropyLength) {
    if (!entropyLength) entropyLength = DEFAULT_ENTROPY_LENGTH / 8
    const entropy = crypto.randomBytes(entropyLength)
    const mnemonic = bip39.entropyToMnemonic(entropy)
    return mnemonic
  }

  /**
   * Internal function used to change the prefix of a xprv or xpub, using the prefixes
   * defined in https://github.com/satoshilabs/slips/blob/master/slip-0132.md
   * 
   * @param {Buffer} prefix - The desired prefix
   * @param {String} extendedKey - Extended key, private or public
   */
  _changePrefix(prefix, extendedKey) {
    const payload = Buffer.concat([prefix, bs58check.decode(extendedKey).slice(4)])
    return bs58check.encode(payload)
  }

  /**
   * Method that returns a set of extended private and public keys
   * @returns master extended private key, xprv, zprv, xpub & zpub
   */
  getKeys() {
    const seed = bip39.mnemonicToSeedSync(this.mnemonic, this.passphrase)
    const root = bip32.BIP32Factory(ecc).fromSeed(seed)
    const coin = root.deriveHardened(84).deriveHardened(0)
    const account = coin.deriveHardened(0)
    const xpub = account.neutered()
    const zpub = this._changePrefix(Buffer.from('04b24746', 'hex'), xpub.toBase58())
    const zprv = this._changePrefix(Buffer.from('04b2430c', 'hex'), account.toBase58())
    const masterZprv = this._changePrefix(Buffer.from('04b2430c', 'hex'), root.toBase58())

    return {
      masterPriv: root.toBase58(),
      masterZprv: masterZprv,
      xprv: account.toBase58(),
      zprv: zprv,
      xpub: xpub.toBase58(),
      zpub: zpub
    }
  }

  deriveAddress(index) {
    const seed = bip39.mnemonicToSeedSync(this.mnemonic, this.passphrase)
    const root = bip32.BIP32Factory(ecc).fromSeed(seed)
    const path = 'm/84\'/0\'/0\'/0/' + index
    const external = root.derivePath(path)
    const { address } = bitcoin.payments.p2wpkh({ pubkey: external.publicKey })
    return {
      address: address,
      publicKey: external.publicKey
    }
  }

  /**
   * @typedef {Object} Utxo
   * @property {String} txid - Previous tx id
   * @property {Number} vout - Previous output index
   * @property {Number} value - Amount of satoshis
   */

  /**
   * @typedef {Object} ClassifiedUtxos
   * @param {Utxo[]} selected - Selected UTXOs
   * @param {Utxo[]} unselected - Unselected UTXOs
   */

  /**
   * Internal method used to select utxos
   * @param {Utxo[]} utxos - Array of unspent transaction outputs
   * @param {Number} toSpend - The total value to send
   * @returns {ClassifiedUtxos} Object with two arrays of selected and unselected UTXOs
   */
  _selectInputs(utxos, toSpend) {
    let valueSelected = 0
    const selected = []
    const unselected = []
    let index = 0
    while(valueSelected < toSpend) {
      selected.push(utxos[index])
      valueSelected += utxos[index].value
      index++
    }
    while(index < utxos.length) {
      unselected.push(utxos[index])
    }
    return {
      selected: selected,
      unselected: unselected
    }
  }

  /**
   * @typedef {Object} Output
   * @property {String} address - The destination address
   * @property {Number} value - The value, expressed in satoshis
   */

  /**
   * Method used to build a transaction
   * @param {Output[]} outputs - The desired outputs
   * @param {Number} feeRate - The desired fee rate
   */
  async buildTransaction(outputs, feeRate) {
    const keys = this.getKeys()
    const root = bip32.BIP32Factory(ecc).fromBase58(keys.masterPriv)

    const utxos = await this.networkInterface.getUtxos()
    const available = utxos.reduce((accum, utxo) => accum + utxo.value, 0)
    const toSpend = outputs.reduce((accum, output) => accum + output.value, 0)
    if (toSpend > available) {
      // Basic sanity check
      throw Error('Not enough balance to satisfy all outputs')
    }

    // Input selection
    const { selected, unselected } = this._selectInputs(utxos, toSpend)

    // Building a Partially Signed Bitcoin Tx
    const psbt = new bitcoin.Psbt()
    // Adding inputs
    for(let i = 0; i < selected.length; i++) {
      const bip32Derivation = {
        masterFingerprint: root.fingerprint,
        pubkey: selected[i].pubKey,
        path: selected[i].path
      }

      psbt.addInput({
        hash: selected[i].txid,
        index: selected[i].vout,
        bip32Derivation: [ bip32Derivation ],
        witnessUtxo: {
          script: selected[i].scriptPubKey,
          value: selected[i].value
        }
      })
    }
    // Adding outputs
    for(let i = 0; i < outputs.length; i++) {
      psbt.addOutput({
        address: outputs[i].address,
        value: outputs[i].value
      })
    }

    let { masterZprv } = this.getKeys()
    const hdSigner = bip32.BIP32Factory(ecc).fromBase58(masterZprv, BITCOIN)
    const tx = psbt
      .clone()
      .signAllInputsHD(hdSigner)
      .finalizeAllInputs()
      .extractTransaction()

    let vSize = tx.virtualSize()
    let feeAmount = Math.ceil(feeRate * vSize)

    // Calculating change value
    let changeValue = available - feeAmount - toSpend
    if (changeValue < 0) {
      throw new Error('Not enough balance to create a tx with the specified fee rate')
    }

    // Function used to calculate the cost of an P2WKH depending on the fee rate
    // A P2WKH output is 31 bytes, which translates to 4x for vsize
    const p2wkhOutputCost = feerate => Math.ceil(feerate * 31)

    const changeOutputCost = p2wkhOutputCost(feeRate)
    if (changeValue < (DUST_THRESHOLD + changeOutputCost)) {
      // No change output is required
      return psbt.signAllInputsHD(hdSigner)
    } else {
      // Recalculate feeAmount to account for an extra output (the change)
      feeAmount += p2wkhOutputCost(feeRate)
      changeValue = available - feeAmount - toSpend

      // Adds a change output
      const changeOutput = this.networkInterface.getChangeAddress()
      psbt.addOutput({
        address: changeOutput.address,
        value: changeValue
      })

      return psbt.signAllInputsHD(hdSigner)
    }
  }
}

module.exports = BitcoinWallet