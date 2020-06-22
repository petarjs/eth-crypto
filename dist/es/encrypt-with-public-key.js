import { encrypt } from "eccrypto";
import { decompress } from "./public-key";

export default function encryptWithPublicKey(publicKey, message, opts) {
  // ensure its an uncompressed publicKey
  publicKey = decompress(publicKey);

  // re-add the compression-flag
  var pubString = "04" + publicKey;

  if (opts && opts.ephemPrivateKey && typeof opts.ephemPrivateKey === "string") {
    opts.ephemPrivateKey = Buffer.from(opts.ephemPrivateKey, "hex");
  }

  if (opts && opts.iv && typeof opts.iv === "string") {
    opts.iv = Buffer.from(opts.iv, "hex");
  }

  return encrypt(Buffer.from(pubString, "hex"), Buffer.from(message), opts).then(function (encryptedBuffers) {
    var encrypted = {
      iv: encryptedBuffers.iv.toString("hex"),
      ephemPublicKey: encryptedBuffers.ephemPublicKey.toString("hex"),
      ephemPrivateKey: encryptedBuffers.ephemPrivateKey.toString("hex"),
      ciphertext: encryptedBuffers.ciphertext.toString("hex"),
      mac: encryptedBuffers.mac.toString("hex")
    };
    return encrypted;
  });
}