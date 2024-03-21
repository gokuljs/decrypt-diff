import axios from "axios";
import { decode, atob } from "js-base64";

const ENDPOINT = "https://ciphersprint.pulley.com/";
const EMAIL = "jsgokul123@gmail.com";
import * as msgpack from "msgpack-lite"; // You may need to install this package: npm install msgpack-lite

function decryptPath(encryptedPath: string, key: string) {
  // Step 1: Hex decode the encrypted path
  const hexToBytes = (hex: string): Uint8Array => {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  };

  const xorDecrypt = (data: Uint8Array, key: string): Uint8Array => {
    const decrypted: Uint8Array = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
      const keyByte = key.charCodeAt(i % key.length);
      decrypted[i] = data[i] ^ keyByte;
    }
    return decrypted;
  };

  const bytesToHex = (bytes: Uint8Array): string => {
    return Array.from(bytes, (byte) => {
      return ("0" + (byte & 0xff).toString(16)).slice(-2);
    }).join("");
  };
  const { task, encrypt } = stringSplit(encryptedPath);
  // Step 1: Convert hex string to byte array
  const encryptedBytes: Uint8Array = hexToBytes(encrypt);

  // Step 2: Decrypt byte array
  const decryptedBytes: Uint8Array = xorDecrypt(encryptedBytes, key);

  // Step 3: Convert decrypted byte array back to hex string
  const decryptedHex: string = bytesToHex(decryptedBytes);

  return task + "_" + decryptedHex;
}

function stringSplit(path: string) {
  const task = path.split("_")[0].trim();
  const encrypt = path.split("_")[1].trim();
  return { task, encrypt };
}

function decodeBase64(encodedString: string) {
  const { task, encrypt } = stringSplit(encodedString);
  const decodedString = decode(encrypt);
  return task + "_" + decodedString;
}

function extractNumberFromString(inputStr: string) {
  // Use a regular expression to match the first number in the string
  const match = inputStr.match(/\d+/);
  // If a number is found, return it; otherwise, return null
  return match ? parseInt(match[0]) : 0;
}

function decryptSwappedPairs(str: string) {
  const { task, encrypt: encryptedStr } = stringSplit(str);
  let decryptedStr = "";
  // Swap back every pair of characters.
  for (let i = 0; i < encryptedStr.length; i += 2) {
    decryptedStr += encryptedStr.charAt(i + 1) + encryptedStr.charAt(i);
  }
  return task + "_" + decryptedStr;
}

function rotateArray(
  path: string,
  method: string,
  direction: "left" | "right" = "left"
) {
  // Ensure direction is valid
  if (direction !== "left" && direction !== "right") {
    throw new Error("Invalid rotation direction");
  }

  // Parse path and extract necessary information
  const { task, encrypt: str } = stringSplit(path);
  const positions = extractNumberFromString(method);
  const length = str.length;
  const actualPositions = positions % length;
  const rotatedStr =
    str.substring(length - actualPositions) +
    str.substring(0, length - actualPositions);
  return task + "_" + rotatedStr;
}

function decryptMessagePack(path: string, method: string) {
  const { task, encrypt } = stringSplit(path);
  const base64EncodedMsgPack = method.split(":")[1].trim();
  const originalPositionsBuffer = Buffer.from(base64EncodedMsgPack, "base64");
  const originalPositions: number[] = msgpack.decode(originalPositionsBuffer);
  const scrambledPositions: number[] = [];
  for (let i = 0; i < originalPositions.length; i++) {
    scrambledPositions[originalPositions[i]] = i;
  }
  const decryptedPathChars: string[] = [];
  for (let i = 0; i < encrypt.length; i++) {
    decryptedPathChars[i] = encrypt[scrambledPositions[i]];
  }
  const decryptedPath = decryptedPathChars.join("");
  console.log("Decrypted Path:", decryptedPath);

  return task + "_" + decryptedPath;
}

async function decodeSHA6(path: string) {
  const { task, encrypt } = stringSplit(path);

  return task + "_" + encrypt;
}

const encryptionMethod = async (
  method: string,
  path: string
): Promise<string> => {
  switch (true) {
    case method === "encoded as base64":
      return ENDPOINT + decodeBase64(path);
    case method.includes("swapped every pair of characters"):
      return ENDPOINT + decryptSwappedPairs(path);
    case method.includes("circularly rotated left"):
      return ENDPOINT + rotateArray(path, method);
    case method.includes(
      "hex decoded, encrypted with XOR, hex encoded again. key: secret"
    ):
      return ENDPOINT + decryptPath(path, "secret");
    case method.includes("scrambled! original positions as base64 encoded"):
      return ENDPOINT + decryptMessagePack(path, method);
    case method.includes("hashed with sha256,"):
      const decrypt = await decodeSHA6(path);
      return ENDPOINT + decrypt;
    default:
      return ENDPOINT + path;
  }
};

async function start(endpoint: string) {
  try {
    console.log({ endpoint });
    const { data: response } = await axios.get(endpoint);
    console.log(response);
    if (response && response.encrypted_path && response.encryption_method) {
      console.log(response.encryption_method);
      const endpoint = await encryptionMethod(
        response.encryption_method,
        response.encrypted_path
      );
      start(endpoint);
    }
  } catch (err) {
    console.log((err as any).message);
  }
}

start(`${ENDPOINT}+${EMAIL}`);
