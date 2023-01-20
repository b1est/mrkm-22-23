const openpgp = require('openpgp');
const BigInteger = require('jsbn').BigInteger;

(async () => {
    const { privateKey, publicKey } = await openpgp.generateKey({
        type: 'rsa',
        rsaBits: 2048,
        userIDs: [{ name: 'Jon Smith', email: 'jon@example.com' }],
        format: 'object'
    });
    const n = new BigInteger(publicKey.keyPacket.publicParams.n)
    const r = new BigInteger('3');
    const r_reverse = new BigInteger(`30204654284108576680657568952374990852606558731112132395256606
    308793587145191605243339716216143894494212040341295302281368715921097519675786088384843947968378
    673978106797262267417410637993606676403442748978204459352119182672756919748542928156303960182700
    885424574833631878626391051231948927627704251017657301428148148005033899220368969379018903150810
    886664055859261698194614243326662891105653473744737495820278974009959741776246394492434602696637
    475618818682103459778472489794082487701556246505942920400004523550793794327991956823636987430597
    09365929224019427443669721804096814315108438298417109049076470114712613732`);
    const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ binary: new Uint8Array(r.toByteArray()) }),
        encryptionKeys: publicKey,
        format: 'binary'
    });
    console.log('Encrypted r:', encrypted);
    const message = new BigInteger('255');
    console.log('Message:', message);
    const messageToSign = message.multiply(new BigInteger(encrypted)).mod(n);
    console.log('Message to SIGN:', new Uint8Array(messageToSign.toByteArray()))
    const signed = await openpgp.sign({
        message: await openpgp.createMessage({ binary: new Uint8Array(messageToSign.toByteArray()) }),
        signingKeys: privateKey,
        format: 'binary'
    });
    console.log('SIGNED message:', signed);
    const signedOriginal = new BigInteger(signed);
    const signedM = signedOriginal.multiply(r_reverse).mod(n);
    console.log(signedM)
    const verification = await openpgp.verify({
        message: await openpgp.readMessage({ binaryMessage: signed }),
        verificationKeys: publicKey,
        format: 'binary'
    });
    console.log('message.pow(d):', verification);
    const { verified, keyID } = verification.signatures[0];
    try {
        await verified; // throws on invalid signature
        console.log('Signed by key id ' + keyID.toHex());
    } catch (e) {
        throw new Error('Signature could not be verified: ' + e.message);
    }
})();