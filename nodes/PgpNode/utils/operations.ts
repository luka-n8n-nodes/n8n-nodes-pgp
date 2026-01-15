import * as openpgp from 'openpgp';
import { Key, PrivateKey } from 'openpgp';
import { DataCompressor } from './DataCompressor';

function getCompressionAlgorithm(compressionAlgorithm: string) {
	switch (compressionAlgorithm) {
		case 'zlib':
			return openpgp.enums.compression.zlib;
		case 'zip':
			return openpgp.enums.compression.zip;
		case 'uncompressed':
			return openpgp.enums.compression.uncompressed;
		default:
			throw new Error('Unsupported algorithm');
	}
}

export async function encryptData(
	message: string | Uint8Array,
	publicKey: Key,
	inputFormat: string = 'text',
	outputFormat: 'armored' | 'binary' = 'armored',
	compressionAlgorithm: string = 'uncompressed',
	applyPrecompression: boolean = true,
	originalFileName: string = 'encrypted',
	applySignature: boolean = false,
	privateKey: Key | null = null,

) {
		if (applySignature && !privateKey) {
			throw new Error('If applying signature during encryption, private key is required.');
		}
		let newFileName = `${originalFileName}.pgp`;
		const precompressData = applyPrecompression && !(originalFileName.endsWith('.gz') || originalFileName.endsWith('.zip')) && compressionAlgorithm !== 'uncompressed';
		// If precompression = disabled, apply compression parameter during openpgp function call
		const compressInEncryption = !applyPrecompression;
		// If needed, compress data
    if (precompressData) {
			message = DataCompressor.compress(
					message as Uint8Array,
					compressionAlgorithm,
					originalFileName,
			);
			const compressionExt = compressionAlgorithm === 'zip' ? '.zip' : '.gz';
			newFileName = `${originalFileName}${compressionExt}.pgp`
		}

        let pgpMessage = (inputFormat === 'text')
            ? await openpgp.createMessage({text: message})
            : await openpgp.createMessage({binary: message});
        const encrypted = await openpgp.encrypt({
				message: pgpMessage,
				encryptionKeys: publicKey,
                // @ts-ignore - output format can be 'binary' or 'armored', which will evaluate to one of the valid options here.
				format: outputFormat,
                ...(compressInEncryption ? ({config: { preferredCompressionAlgorithm: getCompressionAlgorithm(compressionAlgorithm) }}) : ({})),
				...(applySignature ? ({signingKeys: privateKey}) : ({})),
		});
		return {
			data: (outputFormat === 'binary') ? (encrypted as Uint8Array) : (encrypted as string),
			filename: newFileName
		}
}

export async function decryptText(message: string, privateKey: PrivateKey): Promise<string | false> {
    try {
        const decrypted = await openpgp.decrypt({
            message: await openpgp.readMessage({ armoredMessage: message }),
            decryptionKeys: privateKey,
            format: 'utf8',
        });

        return decrypted.data as string;
    } catch (error) {
        // Store error for better debugging - will be caught and re-thrown with context
        const errorMessage = error instanceof Error ? error.message : String(error);
        const errorWithDetails = new Error(errorMessage);
        (errorWithDetails as any).originalError = error;
        throw errorWithDetails;
    }
}

export async function decryptBinary(message: string | Uint8Array, privateKey: PrivateKey): Promise<Uint8Array | false> {
    try {
        let decrypted;
        if (message instanceof Uint8Array) {
            const pgpMessage = await openpgp.readMessage({ binaryMessage: message });
            decrypted = await openpgp.decrypt({
                message: pgpMessage,
                decryptionKeys: privateKey,
                format: 'binary',
            });
        } else {
            const messageStr = message as string;
            if (messageStr.includes('-----BEGIN PGP')) {
                const pgpMessage = await openpgp.readMessage({ armoredMessage: messageStr });
                decrypted = await openpgp.decrypt({
                    message: pgpMessage,
                    decryptionKeys: privateKey,
                    format: 'binary',
                });
            } else {
                const binaryData = new TextEncoder().encode(messageStr);
                const pgpMessage = await openpgp.readMessage({ binaryMessage: binaryData });
                decrypted = await openpgp.decrypt({
                    message: pgpMessage,
                    decryptionKeys: privateKey,
                    format: 'binary',
                });
            }
        }

        return decrypted.data as Uint8Array;
    } catch (error) {
        // Store error for better debugging - will be caught and re-thrown with context
        const errorMessage = error instanceof Error ? error.message : String(error);
        const errorWithDetails = new Error(errorMessage);
        (errorWithDetails as any).originalError = error;
        throw errorWithDetails;
    }
}

export async function signText(message: string, privateKey: PrivateKey): Promise<string> {
    const signature = await openpgp.sign({
        message: await openpgp.createMessage({ text: message }),
        signingKeys: privateKey,
        detached: true,
        format: 'armored',
    });

    return signature as string;
}

export async function signBinary(binaryData: Uint8Array, privateKey: PrivateKey): Promise<string> {
    const signature = await openpgp.sign({
        message: await openpgp.createMessage({ binary: binaryData }),
        signingKeys: privateKey,
        detached: true,
        format: 'armored',
    });

    return signature as string;
}

export async function verifyText(message: string, armoredSignature: string, publicKey: Key): Promise<boolean> {
    const verification = await openpgp.verify({
        message: await openpgp.createMessage({ text: message }),
        signature: await openpgp.readSignature({ armoredSignature }),
        verificationKeys: publicKey,
    });
    const { verified } = verification.signatures[0];
    try {
        await verified;
        return true;
    } catch {
        return false;
    }
}

export async function verifyBinary(binaryData: Uint8Array, signature: string, publicKey: Key): Promise<boolean> {
    const verification = await openpgp.verify({
        message: await openpgp.createMessage({ binary: binaryData }),
        signature: await openpgp.readSignature({ armoredSignature: signature }),
        verificationKeys: publicKey,
    });

    const { verified } = verification.signatures[0];
    try {
        await verified;
        return true;
    } catch {
        return false;
    }
}

export async function decryptTextWithVerification(
    message: string,
    privateKey: PrivateKey,
    publicKey: Key,
): Promise<{ data: string; verified: boolean } | false> {
    try {
        const decrypted = await openpgp.decrypt({
            message: await openpgp.readMessage({ armoredMessage: message }),
            decryptionKeys: privateKey,
            verificationKeys: publicKey,
            format: 'utf8',
        });

        const { data, signatures } = decrypted;
        let verified = false;

        if (signatures && signatures.length > 0) {
            try {
                await signatures[0].verified;
                verified = true;
            } catch {
                verified = false;
            }
        }

        return { data: data as string, verified };
    } catch (error) {
        // Store error for better debugging - will be caught and re-thrown with context
        const errorMessage = error instanceof Error ? error.message : String(error);
        const errorWithDetails = new Error(errorMessage);
        (errorWithDetails as any).originalError = error;
        throw errorWithDetails;
    }
}

export async function decryptBinaryWithVerification(
    message: string | Uint8Array,
    privateKey: PrivateKey,
    publicKey: Key,
): Promise<{ data: Uint8Array; verified: boolean } | false> {
    try {
        let decrypted;
        if (message instanceof Uint8Array) {
            const pgpMessage = await openpgp.readMessage({ binaryMessage: message });
            decrypted = await openpgp.decrypt({
                message: pgpMessage,
                decryptionKeys: privateKey,
                verificationKeys: publicKey,
                format: 'binary',
            });
        } else {
            const messageStr = message as string;
            if (messageStr.includes('-----BEGIN PGP')) {
                const pgpMessage = await openpgp.readMessage({ armoredMessage: messageStr });
                decrypted = await openpgp.decrypt({
                    message: pgpMessage,
                    decryptionKeys: privateKey,
                    verificationKeys: publicKey,
                    format: 'binary',
                });
            } else {
                const binaryData = new TextEncoder().encode(messageStr);
                const pgpMessage = await openpgp.readMessage({ binaryMessage: binaryData });
                decrypted = await openpgp.decrypt({
                    message: pgpMessage,
                    decryptionKeys: privateKey,
                    verificationKeys: publicKey,
                    format: 'binary',
                });
            }
        }

        const { data, signatures } = decrypted;
        let verified = false;

        if (signatures && signatures.length > 0) {
            try {
                await signatures[0].verified;
                verified = true;
            } catch {
                verified = false;
            }
        }

        return { data: data as Uint8Array, verified };
    } catch (error) {
        // Store error for better debugging - will be caught and re-thrown with context
        const errorMessage = error instanceof Error ? error.message : String(error);
        const errorWithDetails = new Error(errorMessage);
        (errorWithDetails as any).originalError = error;
        throw errorWithDetails;
    }
}
